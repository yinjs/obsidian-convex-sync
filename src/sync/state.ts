import { randomBytes, bytesToHex } from "../crypto";
import type { QueueItem, SyncEntry } from "./ports";

export function newFileId(): string {
  return bytesToHex(randomBytes(16));
}

interface Serialized {
  cursor: number;
  entries: SyncEntry[];
  queue: QueueItem[];
}

/**
 * In-memory sync state with three indexes (fileId / pathId / path), the feed
 * cursor, and the durable outbound queue. The pathId/path indexes are needed to
 * detect create/create collisions and renames during pull. The queue coalesces
 * to one item per fileId (latest op wins) so rapid edits replay once.
 */
export class SyncState {
  cursor = 0;
  private byFileId = new Map<string, SyncEntry>();
  private byPathId = new Map<string, SyncEntry>();
  private byPath = new Map<string, SyncEntry>();
  private queue = new Map<string, QueueItem>(); // keyed by fileId, insertion-ordered

  getByFileId(fileId: string): SyncEntry | undefined { return this.byFileId.get(fileId); }
  getByPathId(pathId: string): SyncEntry | undefined { return this.byPathId.get(pathId); }
  getByPath(path: string): SyncEntry | undefined { return this.byPath.get(path); }
  allEntries(): SyncEntry[] { return [...this.byFileId.values()]; }

  upsertEntry(entry: SyncEntry): void {
    const prior = this.byFileId.get(entry.fileId);
    if (prior) {
      this.byPathId.delete(prior.pathId);
      this.byPath.delete(prior.path);
    }
    this.byFileId.set(entry.fileId, entry);
    this.byPathId.set(entry.pathId, entry);
    this.byPath.set(entry.path, entry);
  }

  removeEntry(fileId: string): void {
    const prior = this.byFileId.get(fileId);
    if (!prior) return;
    this.byFileId.delete(fileId);
    this.byPathId.delete(prior.pathId);
    this.byPath.delete(prior.path);
  }

  enqueue(item: QueueItem): void {
    this.queue.set(item.fileId, item); // existing key: value updated, insertion order preserved
  }
  queueItems(): QueueItem[] { return [...this.queue.values()]; }
  dequeue(fileId: string): void { this.queue.delete(fileId); }

  /** Paths with a pending upsert in the queue. Lets pull/reconcile detect that a
   *  path is already claimed by a local identity that hasn't been pushed yet. */
  queuedUpsertPaths(): Set<string> {
    const paths = new Set<string>();
    for (const item of this.queue.values()) if (item.op === "upsert") paths.add(item.path);
    return paths;
  }

  serialize(): string {
    const data: Serialized = { cursor: this.cursor, entries: this.allEntries(), queue: this.queueItems() };
    return JSON.stringify(data);
  }

  static deserialize(json: string | null): SyncState {
    const s = new SyncState();
    if (json === null) return s;
    const data = JSON.parse(json) as Serialized;
    s.cursor = data.cursor ?? 0;
    for (const e of data.entries ?? []) s.upsertEntry(e);
    for (const q of data.queue ?? []) s.enqueue(q);
    return s;
  }
}
