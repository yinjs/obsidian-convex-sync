import type { Subkeys } from "../crypto";
import type { Clock, RemotePort, UpsertArgs, VaultPort } from "./ports";
import type { SyncState } from "./state";
import { encodeAttachment, encodeNote, encodePath, fileType, pathId } from "./codec";

export interface Deps {
  vault: VaultPort;
  remote: RemotePort;
  state: SyncState;
  keys: Subkeys;
  clock: Clock;
}

/** Replay every queued local change. Idempotent and safe to call repeatedly. */
export async function drainQueue(d: Deps): Promise<void> {
  for (const item of d.state.queueItems()) {
    if (item.op === "tombstone") {
      await pushTombstone(item.fileId, d);
    } else {
      await pushUpsert(item.fileId, item.path, d);
    }
  }
}

async function pushUpsert(fileId: string, path: string, d: Deps): Promise<void> {
  const entry = d.state.getByFileId(fileId);
  const baseVersion = entry?.syncedVersion ?? 0;
  const type = fileType(path);
  const content = await d.vault.readBinary(path);
  const mtime = await d.vault.mtime(path);
  const pId = await pathId(path, d.keys);
  const pCipher = await encodePath(path, d.keys);

  let args: UpsertArgs;
  if (type === "attachment") {
    const enc = await encodeAttachment(content, d.keys);
    const storageId = await d.remote.uploadAttachment(enc.cipher);
    args = { fileId, pathId: pId, pathCipher: pCipher, type, contentTag: enc.contentTag, size: content.length, mtime, baseVersion, storageId };
  } else {
    const enc = await encodeNote(content, d.keys);
    await d.remote.putChunks(enc.chunks);
    args = { fileId, pathId: pId, pathCipher: pCipher, type, contentTag: enc.contentTag, size: content.length, mtime, baseVersion, contentChunks: enc.contentChunks };
  }

  const res = await d.remote.upsertFile(args);
  if (res.status === "ok") {
    d.state.upsertEntry({ fileId, path, pathId: pId, type, contentTag: args.contentTag, syncedVersion: res.version, mtime });
    d.state.dequeue(fileId);
    return;
  }

  // Conflict. Idempotency: did our exact write already land (crash before persist)?
  const server = await d.remote.getFileById(fileId);
  if (server !== null && !server.deleted && server.contentTag === args.contentTag) {
    d.state.upsertEntry({ fileId, path, pathId: pId, type, contentTag: server.contentTag, syncedVersion: server.version, mtime: server.mtime });
  }
  // Otherwise leave sync-state stale: the next pull() detects the divergence and
  // produces the conflict copy (single conflict-resolution site).
  d.state.dequeue(fileId);
}

async function pushTombstone(fileId: string, d: Deps): Promise<void> {
  const entry = d.state.getByFileId(fileId);
  if (!entry) {
    d.state.dequeue(fileId);
    return;
  }
  const res = await d.remote.tombstoneFile(fileId, entry.syncedVersion);
  if (res.status === "ok" || res.status === "missing") {
    d.state.removeEntry(fileId);
  } else {
    // Conflict: remote moved past our base. If already deleted, adopt; otherwise
    // a remote edit beat our delete — drop the delete and let pull restore it
    // (no data loss; remote edit wins).
    const server = await d.remote.getFileById(fileId);
    if (server === null || server.deleted) d.state.removeEntry(fileId);
  }
  d.state.dequeue(fileId);
}
