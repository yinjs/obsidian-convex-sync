import type { Bytes, Subkeys } from "../crypto";
import type { FileRow, RemotePort, VaultPort } from "./ports";
import type { Deps } from "./push";
import { SyncState, newFileId } from "./state";
import { computeContentTag, conflictName, decodeAttachment, decodeNote, decodePath, pathId } from "./codec";

/** Drain the entire feed (follows hasMore). */
export async function pull(d: Deps): Promise<void> {
  while (await pullOnce(d)) {
    /* keep paging */
  }
}

/** Apply one page; returns whether more pages remain. */
export async function pullOnce(d: Deps): Promise<boolean> {
  const { changes, nextCursor, hasMore } = await d.remote.listChanges(d.state.cursor);
  for (const row of changes) {
    await applyRemoteRow(row, d);
  }
  d.state.cursor = nextCursor;
  return hasMore;
}

async function fetchContent(row: FileRow, d: Deps): Promise<Bytes> {
  if (row.type === "attachment") {
    if (!row.storageId) throw new Error(`attachment ${row.fileId} has no storageId`);
    return decodeAttachment(await d.remote.getAttachment(row.storageId), d.keys);
  }
  const ids = row.contentChunks ?? [];
  return decodeNote(ids, await d.remote.getChunks(ids), d.keys);
}

/** Has the local file at this entry's path changed since we last synced it? */
async function localDiverged(entry: { path: string; contentTag: string }, d: Deps): Promise<boolean> {
  if (!(await d.vault.exists(entry.path))) return false;
  const tag = await computeContentTag(await d.vault.readBinary(entry.path), d.keys);
  return tag !== entry.contentTag;
}

async function applyRemoteRow(row: FileRow, d: Deps): Promise<void> {
  const local = d.state.getByFileId(row.fileId);
  if (local && local.syncedVersion >= row.version) return; // echo / our own write

  if (row.deleted) {
    await applyDelete(row, local, d);
    return;
  }

  const path = await decodePath(row.pathCipher, d.keys);
  const diverged = local ? await localDiverged(local, d) : false;

  if (local && diverged) {
    await applyConflict(row, local, path, d);
    return;
  }

  await applyClean(row, local, path, d);
}

async function applyDelete(
  row: FileRow,
  local: ReturnType<SyncState["getByFileId"]>,
  d: Deps,
): Promise<void> {
  if (!local) return;
  if ((await d.vault.exists(local.path)) && (await localDiverged(local, d))) {
    // Remote deleted but local was edited — preserve the local edit as a conflict
    // copy and push it as a new file, then accept the delete. No data loss.
    const content = await d.vault.readBinary(local.path);
    const mtime = await d.vault.mtime(local.path);
    const cpath = conflictName(local.path, d.clock.conflictStamp(d.clock.now()));
    await d.vault.writeBinary(cpath, content, mtime);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: cpath });
  }
  if (await d.vault.exists(local.path)) await d.vault.trash(local.path);
  d.state.removeEntry(row.fileId);
}

async function applyConflict(
  row: FileRow,
  local: NonNullable<ReturnType<SyncState["getByFileId"]>>,
  path: string,
  d: Deps,
): Promise<void> {
  const localContent = await d.vault.readBinary(local.path);
  const localMtime = await d.vault.mtime(local.path);
  const remoteContent = await fetchContent(row, d);
  const stamp = d.clock.conflictStamp(d.clock.now());

  // The canonical slot the winner takes. If a DIFFERENT local file already
  // occupies the remote's path (a remote rename onto a third file), don't fight
  // for it — resolve in place at local.path so the third file is never clobbered.
  const occupiedByThird = local.path !== path && (await d.vault.exists(path));
  const canonical = occupiedByThird ? local.path : path;

  if (localMtime > row.mtime) {
    // Local newer → local keeps the canonical slot; remote becomes a conflict copy.
    if (local.path !== canonical) await d.vault.rename(local.path, canonical);
    const cpath = conflictName(canonical, stamp);
    await d.vault.writeBinary(cpath, remoteContent, row.mtime);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: cpath });
    // Record we've seen row.version; keep local content (still dirty) and re-push it as canonical.
    d.state.upsertEntry({
      fileId: row.fileId, path: canonical, pathId: await pathId(canonical, d.keys), type: row.type,
      contentTag: await computeContentTag(localContent, d.keys), syncedVersion: row.version, mtime: localMtime,
    });
    d.state.enqueue({ op: "upsert", fileId: row.fileId, path: canonical });
  } else {
    // Remote newer (or tie) → remote takes the canonical slot; local becomes a conflict copy.
    // Known LOW divergence: when occupiedByThird forced canonical = local.path, this
    // device tracks the file at local.path while the server has it at `path`, and no
    // re-push is enqueued (unlike the local-newer branch). No content is lost, but the
    // file stays mis-pathed here. Enqueuing a re-push would risk ping-pong with the
    // third file, so we accept the cosmetic divergence.
    const cpath = conflictName(local.path, stamp);
    await d.vault.writeBinary(cpath, localContent, localMtime);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: cpath });
    if (local.path !== canonical && (await d.vault.exists(local.path))) await d.vault.trash(local.path);
    await d.vault.writeBinary(canonical, remoteContent, row.mtime);
    d.state.upsertEntry({
      fileId: row.fileId, path: canonical, pathId: await pathId(canonical, d.keys), type: row.type,
      contentTag: row.contentTag, syncedVersion: row.version, mtime: row.mtime,
    });
  }
}

async function applyClean(
  row: FileRow,
  local: ReturnType<SyncState["getByFileId"]>,
  path: string,
  d: Deps,
): Promise<void> {
  let target = path;

  // If the canonical path is already occupied on disk by a DIFFERENT file
  // (another tracked file, or a local-only file queued but not yet pushed, so
  // it has no SyncEntry), divert the incoming file to a conflict name rather
  // than clobbering that file. `local.path === path` means it is THIS file
  // being updated in place — not a collision.
  const occupiedByOther = (!local || local.path !== path) && (await d.vault.exists(path));
  if (occupiedByOther) {
    // Adopt the occupant in place ONLY when it is byte-identical to the incoming
    // remote content AND no other local identity claims this path — i.e. it is our
    // own write from a crashed pull that never persisted state. (push.ts adopts the
    // SAME fileId's server row, safe by construction; here the occupant may be a
    // DIFFERENT local file, so we must rule that out — otherwise we orphan that
    // file's queued identity and manufacture a duplicate.) A tracked entry at
    // `path` catches the drain-before-pull order (sync()); a queued upsert at
    // `path` catches the pull-before-drain order (reconcile()). Both are needed.
    // The guard fails safe: its only failure mode is an unnecessary divert (a
    // spurious conflict copy), never a clobber or loss — do not optimize it away.
    const occTag = await computeContentTag(await d.vault.readBinary(path), d.keys);
    const claimedByOther = d.state.getByPath(path) !== undefined || d.state.queuedUpsertPaths().has(path);
    if (occTag !== row.contentTag || claimedByOther) {
      target = conflictName(path, d.clock.conflictStamp(d.clock.now()));
    }
  }

  if (local && local.path !== target && (await d.vault.exists(local.path))) {
    // rename by fileId to the (possibly diverted) target
    await d.vault.rename(local.path, target);
  }

  // Write when: new file, content changed, OR the target is missing on disk
  // (e.g. the file was deleted locally with no event and must be rematerialized).
  if (!local || local.contentTag !== row.contentTag || !(await d.vault.exists(target))) {
    await d.vault.writeBinary(target, await fetchContent(row, d), row.mtime);
  }

  d.state.upsertEntry({
    fileId: row.fileId, path: target, pathId: await pathId(target, d.keys), type: row.type,
    contentTag: row.contentTag, syncedVersion: row.version, mtime: row.mtime,
  });
}
