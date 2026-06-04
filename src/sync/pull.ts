import type { Bytes, Subkeys } from "../crypto";
import type { FileRow, RemotePort, VaultPort } from "./ports";
import type { Deps } from "./push";
import { SyncState, newFileId } from "./state";
import { computeContentTag, conflictName, decodeAttachment, decodeNote, decodePath } from "./codec";

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

  if (localMtime > row.mtime) {
    // Local newer → local keeps the canonical path; remote becomes a conflict copy.
    if (local.path !== path) await d.vault.rename(local.path, path);
    const cpath = conflictName(path, stamp);
    await d.vault.writeBinary(cpath, remoteContent, row.mtime);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: cpath });
    // Record we've seen row.version; keep local content (still dirty) and re-push it as canonical.
    d.state.upsertEntry({
      fileId: row.fileId, path, pathId: row.pathId, type: row.type,
      contentTag: await computeContentTag(localContent, d.keys), syncedVersion: row.version, mtime: localMtime,
    });
    d.state.enqueue({ op: "upsert", fileId: row.fileId, path });
  } else {
    // Remote newer (or tie) → remote takes the canonical path; local becomes a conflict copy.
    const cpath = conflictName(local.path, stamp);
    await d.vault.writeBinary(cpath, localContent, localMtime);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: cpath });
    if (local.path !== path && (await d.vault.exists(local.path))) await d.vault.trash(local.path);
    await d.vault.writeBinary(path, remoteContent, row.mtime);
    d.state.upsertEntry({
      fileId: row.fileId, path, pathId: row.pathId, type: row.type,
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

  if (!local) {
    // create/create: a different local file already occupies this path → write remote under a conflict name.
    const occupant = d.state.getByPathId(row.pathId);
    if (occupant && occupant.fileId !== row.fileId && (await d.vault.exists(occupant.path))) {
      target = conflictName(path, d.clock.conflictStamp(d.clock.now()));
    }
  } else if (local.path !== path) {
    // rename by fileId
    if (await d.vault.exists(local.path)) await d.vault.rename(local.path, target);
  }

  if (!local || local.contentTag !== row.contentTag) {
    await d.vault.writeBinary(target, await fetchContent(row, d), row.mtime);
  }

  d.state.upsertEntry({
    fileId: row.fileId, path: target, pathId: row.pathId, type: row.type,
    contentTag: row.contentTag, syncedVersion: row.version, mtime: row.mtime,
  });
}
