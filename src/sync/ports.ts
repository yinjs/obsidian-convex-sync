import type { Bytes } from "../crypto";

export type FileType = "note" | "attachment" | "config";

/** A file as the engine sees it in the vault. Paths are vault-relative, POSIX. */
export interface VaultFile {
  path: string;
  type: FileType;
}

/** A remote file metadata row (the engine's view of a Convex `files` doc). */
export interface FileRow {
  fileId: string;
  pathId: string;
  pathCipher: string;
  type: FileType;
  contentTag: string;
  size: number;
  mtime: number;
  deleted: boolean;
  version: number;
  contentChunks?: string[];
  storageId?: string;
}

/** Arguments to upsertFile, minus the workspace/auth fields baked into RemotePort. */
export interface UpsertArgs {
  fileId: string;
  pathId: string;
  pathCipher: string;
  type: FileType;
  contentTag: string;
  size: number;
  mtime: number;
  baseVersion: number;
  contentChunks?: string[];
  storageId?: string;
}

export type UpsertResult =
  | { status: "ok"; version: number }
  | { status: "conflict"; serverVersion: number };

export type TombstoneResult =
  | { status: "ok"; version: number }
  | { status: "conflict"; serverVersion: number }
  | { status: "missing" };

/** Filesystem the engine reads and writes. Implemented over Obsidian's Vault in Plan 4. */
export interface VaultPort {
  list(): Promise<VaultFile[]>;
  exists(path: string): Promise<boolean>;
  mtime(path: string): Promise<number>;
  readBinary(path: string): Promise<Bytes>;
  writeBinary(path: string, data: Bytes, mtime: number): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  trash(path: string): Promise<void>;
}

/** Convex backend wrapper. Bakes in workspaceId + syncKey; the engine never sees auth. */
export interface RemotePort {
  putChunks(chunks: { chunkId: string; cipher: string }[]): Promise<void>;
  getChunks(chunkIds: string[]): Promise<{ chunkId: string; cipher: string }[]>;
  upsertFile(args: UpsertArgs): Promise<UpsertResult>;
  tombstoneFile(fileId: string, baseVersion: number): Promise<TombstoneResult>;
  listChanges(sinceVersion: number, limit?: number): Promise<{ changes: FileRow[]; nextCursor: number; hasMore: boolean }>;
  getFileByPath(pathId: string): Promise<FileRow | null>;
  getFileById(fileId: string): Promise<FileRow | null>;
  uploadAttachment(cipher: Bytes): Promise<string>; // returns storageId
  getAttachment(storageId: string): Promise<Bytes>;
}

/** Persist the engine's serialized state blob (plugin data dir in Plan 4). */
export interface StatePort {
  load(): Promise<string | null>;
  save(json: string): Promise<void>;
}

/** Time source. now() for stamps; conflictStamp formats a filename-safe timestamp. */
export interface Clock {
  now(): number;
  conflictStamp(ms: number): string; // e.g. "2026-06-04 14-22-09"
}

/** Persisted per-file sync state, keyed by stable fileId. */
export interface SyncEntry {
  fileId: string;
  path: string;
  pathId: string;
  type: FileType;
  contentTag: string;
  syncedVersion: number;
  mtime: number;
}

/** A pending local change to replay (durable outbound queue). */
export interface QueueItem {
  op: "upsert" | "tombstone";
  fileId: string;
  path: string;
}
