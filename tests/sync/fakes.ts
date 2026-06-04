import type { Bytes } from "../../src/crypto";
import { deriveSubkeys, type Subkeys } from "../../src/crypto";
import type {
  Clock, FileRow, RemotePort, StatePort, UpsertArgs, UpsertResult,
  TombstoneResult, VaultFile, VaultPort,
} from "../../src/sync/ports";
import { fileType } from "../../src/sync/codec";

export async function makeKeys(fill = 7): Promise<Subkeys> {
  return deriveSubkeys(new Uint8Array(32).fill(fill) as Bytes);
}

export const fakeClock: Clock = {
  now: () => 1_000_000,
  conflictStamp: () => "2026-06-04 12-00-00",
};

export class FakeVault implements VaultPort {
  files = new Map<string, { data: Bytes; mtime: number }>();
  async list(): Promise<VaultFile[]> {
    return [...this.files.keys()].map((path) => ({ path, type: fileType(path) }));
  }
  async exists(path: string) { return this.files.has(path); }
  async mtime(path: string) {
    const f = this.files.get(path);
    if (!f) throw new Error(`no file ${path}`);
    return f.mtime;
  }
  async readBinary(path: string): Promise<Bytes> {
    const f = this.files.get(path);
    if (!f) throw new Error(`no file ${path}`);
    return f.data;
  }
  async writeBinary(path: string, data: Bytes, mtime: number) {
    this.files.set(path, { data, mtime });
  }
  async rename(from: string, to: string) {
    const f = this.files.get(from);
    if (!f) throw new Error(`no file ${from}`);
    this.files.delete(from);
    this.files.set(to, f);
  }
  async trash(path: string) { this.files.delete(path); }
}

export class FakeRemote implements RemotePort {
  private counter = 0;
  private storageCounter = 0;
  files = new Map<string, FileRow>();
  chunks = new Map<string, string>();
  storage = new Map<string, Bytes>();

  async putChunks(cs: { chunkId: string; cipher: string }[]) {
    for (const c of cs) if (!this.chunks.has(c.chunkId)) this.chunks.set(c.chunkId, c.cipher);
  }
  async getChunks(ids: string[]) {
    const out: { chunkId: string; cipher: string }[] = [];
    for (const id of ids) {
      const cipher = this.chunks.get(id);
      if (cipher !== undefined) out.push({ chunkId: id, cipher });
    }
    return out;
  }
  async upsertFile(args: UpsertArgs): Promise<UpsertResult> {
    const existing = this.files.get(args.fileId);
    if (existing && existing.version !== args.baseVersion) {
      return { status: "conflict", serverVersion: existing.version };
    }
    const version = ++this.counter;
    this.files.set(args.fileId, {
      fileId: args.fileId, pathId: args.pathId, pathCipher: args.pathCipher,
      type: args.type, contentTag: args.contentTag, size: args.size, mtime: args.mtime,
      deleted: false, version, contentChunks: args.contentChunks, storageId: args.storageId,
    });
    return { status: "ok", version };
  }
  async tombstoneFile(fileId: string, baseVersion: number): Promise<TombstoneResult> {
    const existing = this.files.get(fileId);
    if (!existing) return { status: "missing" };
    if (existing.version !== baseVersion) return { status: "conflict", serverVersion: existing.version };
    const version = ++this.counter;
    this.files.set(fileId, { ...existing, deleted: true, version, contentTag: "", size: 0, contentChunks: undefined, storageId: undefined });
    return { status: "ok", version };
  }
  async listChanges(sinceVersion: number, limit = 50) {
    const all = [...this.files.values()].filter((f) => f.version > sinceVersion).sort((a, b) => a.version - b.version);
    const changes = all.slice(0, limit);
    const nextCursor = changes.length > 0 ? changes[changes.length - 1]!.version : sinceVersion;
    return { changes, nextCursor, hasMore: all.length > limit };
  }
  async getFileByPath(pathId: string) {
    return [...this.files.values()].find((f) => f.pathId === pathId && !f.deleted) ?? null;
  }
  async getFileById(fileId: string) {
    return this.files.get(fileId) ?? null;
  }
  async uploadAttachment(cipher: Bytes) {
    const id = `s${++this.storageCounter}`;
    this.storage.set(id, cipher);
    return id;
  }
  async getAttachment(storageId: string): Promise<Bytes> {
    const b = this.storage.get(storageId);
    if (!b) throw new Error(`no blob ${storageId}`);
    return b;
  }
}

export class FakeStatePort implements StatePort {
  blob: string | null = null;
  async load() { return this.blob; }
  async save(json: string) { this.blob = json; }
}
