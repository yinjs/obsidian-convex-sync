# Sync Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the platform-agnostic sync engine that ties crypto-core (Plan 1) and the Convex backend (Plan 2) into push/pull/conflict/offline sync, behind injected ports so it is fully unit-testable without Obsidian or a live Convex deployment.

**Architecture:** The engine is pure TypeScript in `src/sync/` behind four injected **ports** — `VaultPort` (filesystem), `RemotePort` (a thin wrapper over the Convex api that bakes in workspaceId+syncKey so the engine never touches auth), `StatePort` (persist a JSON blob), and `Clock` (timestamps only). The engine is **timer-free and subscription-free**: it exposes `notifyChange`/`notifyRename`/`notifyDelete` (record intent into a durable queue) and `sync()`/`reconcile()` (drain → pull → reconcile). Plan 4's plugin shell owns the debounce timer and the Convex reactive subscription that call `sync()`. Conflict resolution lives in exactly one place (the pull path); the push path defers genuine conflicts to it and only performs an idempotency adopt-if-already-landed check.

**Tech Stack:** TypeScript 6, vitest (node env), WebCrypto (via crypto-core), Convex backend api.

---

## Background for the implementer

The crypto-core module (`src/crypto/`, barrel `src/crypto/index.ts`) and the Convex backend (`convex/`) are already built and merged to `main`. You are building the glue. Read these existing surfaces — the plan's code calls them directly:

**crypto-core public exports (`src/crypto`):**
- `type Bytes = Uint8Array<ArrayBuffer>` — the engine's byte type everywhere a value flows into WebCrypto.
- `interface Subkeys { encKey; chunkMacKey; pathMacKey }` and `deriveSubkeys(dek: Bytes): Promise<Subkeys>` (Task 1 adds `contentMacKey`).
- `hmacId(macKey: CryptoKey, data: Bytes): Promise<string>` — 64-char hex.
- `chunk(data: Bytes): Bytes[]` — FastCDC content-defined chunks (one zero-length chunk for empty input).
- `aesGcmEncrypt(key, pt: Bytes): Promise<{nonce: Bytes; data: Bytes}>`, `aesGcmDecrypt(key, ct): Promise<Bytes>`, `serializeCiphertext(ct): string` (format `base64(nonce).base64(data)`), `deserializeCiphertext(s)`.
- `utf8ToBytes(s): Bytes`, `bytesToUtf8(b): string`, `bytesToHex(b): string`, `randomBytes(n): Bytes`.

**Convex backend functions** (engine reaches these only through `RemotePort`): `chunks.putChunks`/`getChunks`, `files.upsertFile` (returns `{status:"ok";version}` | `{status:"conflict";serverVersion}`), `files.tombstoneFile` (`ok`|`conflict`|`missing`), `files.listChanges` (`{changes, nextCursor, hasMore}`), `files.getFileByPath`, `attachments.generateUploadUrl`/`getAttachmentUrl`. Task 2 adds `files.getFileById`.

**Conventions:** TDD strictly (failing test → see it fail → implement → pass → commit). Tests live in `tests/sync/`. The engine NEVER imports Obsidian or Convex client packages — only the crypto barrel and its own ports. Run `npm test` (all) and `npm run typecheck` before each commit.

---

## File Structure

- `src/crypto/hkdf.ts` (modify) — add `contentMacKey` subkey.
- `convex/files.ts` (modify) — add `getFileById` query.
- `src/sync/ports.ts` — the four port interfaces + wire types (`FileRow`, `UpsertArgs`, `VaultFile`, `Clock`, `SyncEntry`, `QueueItem`).
- `src/sync/codec.ts` — pure crypto↔wire: `encodeNote`/`decodeNote`, `encodeAttachment`/`decodeAttachment`, `pathId`/`encodePath`/`decodePath`, `computeContentTag`, `fileType`, `conflictName`.
- `src/sync/state.ts` — `SyncState` (indexes by fileId/pathId/path, cursor, durable queue, serialize) + `newFileId`.
- `src/sync/push.ts` — `drainQueue` (idempotent; defers genuine conflicts to pull).
- `src/sync/pull.ts` — `pull`/`pullOnce`, `applyRemoteRow` (the single conflict-resolution site).
- `src/sync/reconcile.ts` — cold-start / reconnect three-way reconcile by tag.
- `src/sync/engine.ts` — `SyncEngine` orchestrator: `notifyChange`/`notifyRename`/`notifyDelete` + `sync()`/`reconcile()`.
- `src/sync/index.ts` — barrel.
- `tests/sync/fakes.ts` — in-memory `FakeVault`, `FakeRemote` (mini-backend mirroring real semantics), `FakeStatePort`, `fakeClock`, plus a `makeKeys()` helper.

---

## Task 1: crypto-core — add `contentMacKey`

A domain-separated HMAC key for content-change tags. Keyed (not a plain hash) so the server can't use the tag as an offline plaintext-guessing oracle — same rationale as chunkId/pathId. Additive: existing wrapped DEKs still derive identical enc/chunk/path keys (HKDF is info-separated), so no migration.

**Files:**
- Modify: `src/crypto/hkdf.ts`
- Test: `tests/crypto/hkdf.test.ts` (add cases)

- [ ] **Step 1: Add failing tests**

In `tests/crypto/hkdf.test.ts`, add inside the `describe("hkdf", ...)` block:
```typescript
  it("derives a contentMacKey usable for HMAC signing, sign-only", async () => {
    const { contentMacKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const sig = await crypto.subtle.sign("HMAC", contentMacKey, utf8ToBytes("x"));
    expect(new Uint8Array(sig).length).toBe(32);
    expect(contentMacKey.usages).toEqual(["sign"]);
  });

  it("contentMacKey is domain-separated from chunk and path mac keys", async () => {
    const { chunkMacKey, pathMacKey, contentMacKey } = await deriveSubkeys(new Uint8Array(32).fill(4));
    const sign = (k: CryptoKey) =>
      crypto.subtle.sign("HMAC", k, utf8ToBytes("same-input")).then((s) => new Uint8Array(s).join(","));
    const c = await sign(contentMacKey);
    expect(c).not.toBe(await sign(chunkMacKey));
    expect(c).not.toBe(await sign(pathMacKey));
  });
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/crypto/hkdf.test.ts`
Expected: FAIL — `contentMacKey` is `undefined`.

- [ ] **Step 3: Implement**

In `src/crypto/hkdf.ts`, add to the `Subkeys` interface after `pathMacKey`:
```typescript
  contentMacKey: CryptoKey; // HMAC-SHA256, sign only — contentTag (change detection)
```
In `deriveSubkeys`, after `const pathMacKey = await deriveMacKey("mac-path");`:
```typescript
  const contentMacKey = await deriveMacKey("mac-content");
```
And change the return to:
```typescript
  return { encKey, chunkMacKey, pathMacKey, contentMacKey };
```

- [ ] **Step 4: Run the whole crypto suite (confirm the widening breaks nothing)**

Run: `npx vitest run tests/crypto`
Expected: all crypto tests pass (the new 2 included).

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/crypto/hkdf.ts tests/crypto/hkdf.test.ts
git commit -m "feat(crypto): add domain-separated contentMacKey subkey"
```

---

## Task 2: backend — `getFileById` query

The push idempotency check needs the authoritative server row for a specific `fileId` (not by path — a rename changes the pathId). Add a read-only query.

**Files:**
- Modify: `convex/files.ts`
- Test: `convex/files.test.ts` (add cases)
- Modify: nothing in `_generated` (files module already registered).

- [ ] **Step 1: Add failing tests**

In `convex/files.test.ts`, add (the `seed`, `base`, `sha256Hex` helpers already exist in that file):
```typescript
test("getFileById returns the row for a known fileId, scoped to the workspace", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 }); // f1 -> v1
  const row = await t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "k", fileId: "f1" });
  expect(row?.fileId).toBe("f1");
  expect(row?.version).toBe(1);
});

test("getFileById returns null for an unknown fileId", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const row = await t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "k", fileId: "ghost" });
  expect(row).toBeNull();
});

test("getFileById rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await expect(
    t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "bad", fileId: "f1" }),
  ).rejects.toThrow("Unauthorized");
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run convex/files.test.ts`
Expected: FAIL — `api.files.getFileById` is undefined.

- [ ] **Step 3: Implement**

In `convex/files.ts`, append:
```typescript
/** Authenticated read of a single file row by its stable fileId (or null).
 *  Used by the client's push idempotency check after a conflict response. */
export const getFileById = query({
  args: { workspaceId: v.string(), syncKey: v.string(), fileId: v.string() },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return await ctx.db
      .query("files")
      .withIndex("by_workspace_file", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("fileId", args.fileId),
      )
      .unique();
  },
});
```
(`query`, `v`, `authenticate` are already imported in this file.)

- [ ] **Step 4: Run to verify pass + full suite**

Run: `npx vitest run convex/files.test.ts` → all pass.
Run: `npm test` → everything green.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add convex/files.ts convex/files.test.ts
git commit -m "feat(convex): getFileById query for push idempotency"
```

---

## Task 3: ports + test fakes

Define the port interfaces, wire types, and the in-memory fakes every later task tests against. The `FakeRemote` is a faithful mini-backend (version counter, conflict-on-stale-base, value-cursor feed) so the engine is exercised end-to-end without Convex.

**Files:**
- Create: `src/sync/ports.ts`
- Create: `tests/sync/fakes.ts`
- Test: `tests/sync/fakes.test.ts`

- [ ] **Step 1: Write the fakes self-test (failing)**

Create `tests/sync/fakes.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { FakeRemote, FakeVault } from "./fakes";

describe("fakes", () => {
  it("FakeRemote.upsertFile assigns versions and rejects stale base", async () => {
    const r = new FakeRemote();
    const a = await r.upsertFile({
      fileId: "f1", pathId: "p", pathCipher: "pc", type: "note",
      contentTag: "t1", size: 1, mtime: 1, baseVersion: 0, contentChunks: ["c"],
    });
    expect(a).toEqual({ status: "ok", version: 1 });
    const stale = await r.upsertFile({
      fileId: "f1", pathId: "p", pathCipher: "pc", type: "note",
      contentTag: "t2", size: 1, mtime: 2, baseVersion: 0, contentChunks: ["c"],
    });
    expect(stale).toEqual({ status: "conflict", serverVersion: 1 });
  });

  it("FakeRemote.listChanges streams by version cursor", async () => {
    const r = new FakeRemote();
    await r.upsertFile({ fileId: "f1", pathId: "p1", pathCipher: "x", type: "note", contentTag: "t", size: 1, mtime: 1, baseVersion: 0, contentChunks: [] });
    await r.upsertFile({ fileId: "f2", pathId: "p2", pathCipher: "x", type: "note", contentTag: "t", size: 1, mtime: 1, baseVersion: 0, contentChunks: [] });
    const page = await r.listChanges(0);
    expect(page.changes.map((c) => c.fileId)).toEqual(["f1", "f2"]);
    expect(page.nextCursor).toBe(2);
  });

  it("FakeVault round-trips bytes and mtime", async () => {
    const v = new FakeVault();
    await v.writeBinary("a.md", new Uint8Array([1, 2, 3]), 100);
    expect(await v.exists("a.md")).toBe(true);
    expect([...(await v.readBinary("a.md"))]).toEqual([1, 2, 3]);
    expect(await v.mtime("a.md")).toBe(100);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/fakes.test.ts`
Expected: FAIL — `./fakes` does not exist.

- [ ] **Step 3: Write the ports**

Create `src/sync/ports.ts`:
```typescript
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
```

- [ ] **Step 4: Write the fakes**

Create `tests/sync/fakes.ts`:
```typescript
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
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run tests/sync/fakes.test.ts`
Expected: 3 passed. (`fileType` is imported from codec — Task 4 creates it. Until then this import fails to resolve; create a temporary one-line `src/sync/codec.ts` exporting only `fileType` now, OR implement Task 4 before running. To keep TDD honest, add the minimal `fileType` export to `src/sync/codec.ts` here:)

```typescript
// src/sync/codec.ts (minimal for now; expanded in Task 4)
import type { FileType } from "./ports";
export function fileType(path: string): FileType {
  if (path.startsWith(".obsidian/")) return "config";
  if (path.endsWith(".md")) return "note";
  return "attachment";
}
```

- [ ] **Step 6: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/ports.ts src/sync/codec.ts tests/sync/fakes.ts tests/sync/fakes.test.ts
git commit -m "feat(sync): ports, wire types, and in-memory test fakes"
```

---

## Task 4: codec (pure crypto ↔ wire)

Pure functions converting vault bytes to/from the encrypted wire format. No ports, no state — trivially testable with real crypto.

**Files:**
- Modify: `src/sync/codec.ts` (expand the stub from Task 3)
- Test: `tests/sync/codec.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/codec.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { makeKeys } from "./fakes";
import {
  encodeNote, decodeNote, encodeAttachment, decodeAttachment,
  pathId, encodePath, decodePath, computeContentTag, fileType, conflictName,
} from "../../src/sync/codec";
import type { Bytes } from "../../src/crypto";
import { utf8ToBytes } from "../../src/crypto";

const bytes = (s: string) => utf8ToBytes(s);

describe("codec", () => {
  it("encodeNote then decodeNote round-trips", async () => {
    const keys = await makeKeys();
    const content = bytes("hello note body");
    const enc = await encodeNote(content, keys);
    const decoded = await decodeNote(enc.contentChunks, enc.chunks, keys);
    expect([...decoded]).toEqual([...content]);
  });

  it("encodeNote produces matching chunkIds and contentChunks order", async () => {
    const keys = await makeKeys();
    const enc = await encodeNote(bytes("abc"), keys);
    expect(enc.chunks.map((c) => c.chunkId)).toEqual(enc.contentChunks);
    expect(enc.contentTag).toMatch(/^[0-9a-f]{64}$/);
  });

  it("identical content yields identical chunkIds and tag (deterministic ids)", async () => {
    const keys = await makeKeys();
    const a = await encodeNote(bytes("same"), keys);
    const b = await encodeNote(bytes("same"), keys);
    expect(a.contentChunks).toEqual(b.contentChunks);
    expect(a.contentTag).toBe(b.contentTag);
  });

  it("encodeAttachment then decodeAttachment round-trips raw bytes (no base64 bloat)", async () => {
    const keys = await makeKeys();
    const blob = new Uint8Array([0, 1, 2, 255, 128]) as Bytes;
    const enc = await encodeAttachment(blob, keys);
    expect(enc.contentTag).toMatch(/^[0-9a-f]{64}$/);
    const decoded = await decodeAttachment(enc.cipher, keys);
    expect([...decoded]).toEqual([...blob]);
  });

  it("pathId is deterministic; encodePath/decodePath round-trips", async () => {
    const keys = await makeKeys();
    const id1 = await pathId("folder/note.md", keys);
    const id2 = await pathId("folder/note.md", keys);
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^[0-9a-f]{64}$/);
    const cipher = await encodePath("folder/note.md", keys);
    expect(await decodePath(cipher, keys)).toBe("folder/note.md");
  });

  it("computeContentTag changes when content changes", async () => {
    const keys = await makeKeys();
    expect(await computeContentTag(bytes("a"), keys)).not.toBe(await computeContentTag(bytes("b"), keys));
  });

  it("fileType classifies by path", () => {
    expect(fileType("a.md")).toBe("note");
    expect(fileType("img.png")).toBe("attachment");
    expect(fileType(".obsidian/app.json")).toBe("config");
  });

  it("conflictName inserts before the extension", () => {
    expect(conflictName("folder/note.md", "2026-06-04 12-00-00")).toBe("folder/note (conflict 2026-06-04 12-00-00).md");
    expect(conflictName("noext", "S")).toBe("noext (conflict S)");
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/codec.test.ts`
Expected: FAIL — most exports missing (only `fileType` exists from Task 3).

- [ ] **Step 3: Implement**

Replace `src/sync/codec.ts` with:
```typescript
import type { Bytes } from "../crypto";
import {
  chunk, hmacId, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext,
  utf8ToBytes, bytesToUtf8, type Subkeys,
} from "../crypto";
import type { FileType } from "./ports";

const NONCE_LEN = 12;

export interface EncodedNote {
  chunks: { chunkId: string; cipher: string }[]; // to putChunks
  contentChunks: string[]; // ordered chunk ids for the files row
  contentTag: string;
}

export interface EncodedAttachment {
  cipher: Bytes; // raw nonce(12) ++ data, for file storage
  contentTag: string;
}

/** HMAC(contentMacKey, SHA-256(content)) — keyed change-detection tag. */
export async function computeContentTag(content: Bytes, keys: Subkeys): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", content)) as Bytes;
  return hmacId(keys.contentMacKey, hash);
}

export async function encodeNote(content: Bytes, keys: Subkeys): Promise<EncodedNote> {
  const parts = chunk(content);
  const chunks: { chunkId: string; cipher: string }[] = [];
  const contentChunks: string[] = [];
  for (const part of parts) {
    const chunkId = await hmacId(keys.chunkMacKey, part);
    const ct = await aesGcmEncrypt(keys.encKey, part);
    chunks.push({ chunkId, cipher: serializeCiphertext(ct) });
    contentChunks.push(chunkId);
  }
  return { chunks, contentChunks, contentTag: await computeContentTag(content, keys) };
}

export async function decodeNote(
  contentChunks: string[],
  fetched: { chunkId: string; cipher: string }[],
  keys: Subkeys,
): Promise<Bytes> {
  const byId = new Map(fetched.map((c) => [c.chunkId, c.cipher]));
  const parts: Bytes[] = [];
  for (const id of contentChunks) {
    const cipher = byId.get(id);
    if (cipher === undefined) throw new Error(`missing chunk ${id}`);
    parts.push(await aesGcmDecrypt(keys.encKey, deserializeCiphertext(cipher)));
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total) as Bytes;
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function encodeAttachment(blob: Bytes, keys: Subkeys): Promise<EncodedAttachment> {
  const ct = await aesGcmEncrypt(keys.encKey, blob);
  const cipher = new Uint8Array(ct.nonce.length + ct.data.length) as Bytes;
  cipher.set(ct.nonce, 0);
  cipher.set(ct.data, ct.nonce.length);
  return { cipher, contentTag: await computeContentTag(blob, keys) };
}

export async function decodeAttachment(cipher: Bytes, keys: Subkeys): Promise<Bytes> {
  const nonce = cipher.slice(0, NONCE_LEN) as Bytes;
  const data = cipher.slice(NONCE_LEN) as Bytes;
  return aesGcmDecrypt(keys.encKey, { nonce, data });
}

export function pathId(path: string, keys: Subkeys): Promise<string> {
  return hmacId(keys.pathMacKey, utf8ToBytes(path));
}

export async function encodePath(path: string, keys: Subkeys): Promise<string> {
  return serializeCiphertext(await aesGcmEncrypt(keys.encKey, utf8ToBytes(path)));
}

export async function decodePath(pathCipher: string, keys: Subkeys): Promise<string> {
  return bytesToUtf8(await aesGcmDecrypt(keys.encKey, deserializeCiphertext(pathCipher)));
}

export function fileType(path: string): FileType {
  if (path.startsWith(".obsidian/")) return "config";
  if (path.endsWith(".md")) return "note";
  return "attachment";
}

/** Insert ` (conflict <stamp>)` before the file extension. */
export function conflictName(path: string, stamp: string): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  if (dot > slash && dot !== -1) {
    return `${path.slice(0, dot)} (conflict ${stamp})${path.slice(dot)}`;
  }
  return `${path} (conflict ${stamp})`;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/codec.test.ts`
Expected: 8 passed.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/codec.ts tests/sync/codec.test.ts
git commit -m "feat(sync): codec — encode/decode notes, attachments, paths, content tags"
```

---

## Task 5: SyncState (indexes, cursor, durable queue, persistence)

`SyncState` holds per-file entries indexed three ways (by fileId, pathId, path — the pathId/path indexes are required for create/create collision and rename detection), the feed cursor, and the durable outbound queue. It serializes to JSON for `StatePort`.

**Files:**
- Create: `src/sync/state.ts`
- Test: `tests/sync/state.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/state.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { SyncState, newFileId } from "../../src/sync/state";
import type { SyncEntry } from "../../src/sync/ports";

const entry = (over: Partial<SyncEntry> = {}): SyncEntry => ({
  fileId: "f1", path: "a.md", pathId: "pa", type: "note",
  contentTag: "t1", syncedVersion: 1, mtime: 100, ...over,
});

describe("SyncState", () => {
  it("indexes an entry by fileId, pathId, and path", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    expect(s.getByFileId("f1")?.path).toBe("a.md");
    expect(s.getByPathId("pa")?.fileId).toBe("f1");
    expect(s.getByPath("a.md")?.fileId).toBe("f1");
  });

  it("re-indexes when an entry's path changes (rename)", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    s.upsertEntry(entry({ path: "b.md", pathId: "pb" }));
    expect(s.getByPath("a.md")).toBeUndefined();
    expect(s.getByPathId("pa")).toBeUndefined();
    expect(s.getByPath("b.md")?.fileId).toBe("f1");
  });

  it("removeEntry clears all indexes", () => {
    const s = new SyncState();
    s.upsertEntry(entry());
    s.removeEntry("f1");
    expect(s.getByFileId("f1")).toBeUndefined();
    expect(s.getByPathId("pa")).toBeUndefined();
    expect(s.getByPath("a.md")).toBeUndefined();
  });

  it("enqueue coalesces repeated changes to one item per fileId, preserving order", () => {
    const s = new SyncState();
    s.enqueue({ op: "upsert", fileId: "f1", path: "a.md" });
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    s.enqueue({ op: "tombstone", fileId: "f1", path: "a.md" });
    expect(s.queueItems()).toEqual([
      { op: "tombstone", fileId: "f1", path: "a.md" },
      { op: "upsert", fileId: "f2", path: "b.md" },
    ]);
  });

  it("dequeue removes a single item", () => {
    const s = new SyncState();
    s.enqueue({ op: "upsert", fileId: "f1", path: "a.md" });
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    s.dequeue("f1");
    expect(s.queueItems().map((q) => q.fileId)).toEqual(["f2"]);
  });

  it("serialize then deserialize preserves entries, cursor, and queue", () => {
    const s = new SyncState();
    s.cursor = 7;
    s.upsertEntry(entry());
    s.enqueue({ op: "upsert", fileId: "f2", path: "b.md" });
    const restored = SyncState.deserialize(s.serialize());
    expect(restored.cursor).toBe(7);
    expect(restored.getByFileId("f1")?.contentTag).toBe("t1");
    expect(restored.getByPath("a.md")?.fileId).toBe("f1");
    expect(restored.queueItems()).toEqual([{ op: "upsert", fileId: "f2", path: "b.md" }]);
  });

  it("deserialize(null) yields an empty state at cursor 0", () => {
    const s = SyncState.deserialize(null);
    expect(s.cursor).toBe(0);
    expect(s.allEntries()).toEqual([]);
    expect(s.queueItems()).toEqual([]);
  });

  it("newFileId returns a 32-char hex id", () => {
    expect(newFileId()).toMatch(/^[0-9a-f]{32}$/);
    expect(newFileId()).not.toBe(newFileId());
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/state.test.ts`
Expected: FAIL — `./state` does not exist.

- [ ] **Step 3: Implement**

Create `src/sync/state.ts`:
```typescript
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
    this.queue.delete(item.fileId); // move-to-end + latest-op-wins
    this.queue.set(item.fileId, item);
  }
  queueItems(): QueueItem[] { return [...this.queue.values()]; }
  dequeue(fileId: string): void { this.queue.delete(fileId); }

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
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/state.test.ts`
Expected: 8 passed.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/state.ts tests/sync/state.test.ts
git commit -m "feat(sync): SyncState with fileId/pathId/path indexes, cursor, durable queue"
```

---

## Task 6: push (idempotent queue drain)

`drainQueue` replays each queued change. Upsert: encode → upload chunks/blob → `upsertFile(baseVersion)`. On `ok`, persist the server-returned version into sync-state (the push half of echo prevention). On `conflict`, do the idempotency check — fetch the server row by fileId; if its `contentTag` equals what we just pushed, our write already landed (e.g. crash before persist) → adopt it, no conflict copy. Otherwise leave sync-state stale and dequeue: the subsequent `pull()` is the single place that produces conflict copies.

**Files:**
- Create: `src/sync/push.ts`
- Test: `tests/sync/push.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/push.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { drainQueue } from "../../src/sync/push";
import { SyncState, newFileId } from "../../src/sync/state";
import { FakeVault, FakeRemote, fakeClock, makeKeys } from "./fakes";
import type { Deps } from "../../src/sync/push";
import { utf8ToBytes, type Bytes } from "../../src/crypto";

async function deps(): Promise<Deps & { vault: FakeVault; remote: FakeRemote; state: SyncState }> {
  return { vault: new FakeVault(), remote: new FakeRemote(), state: new SyncState(), keys: await makeKeys(), clock: fakeClock };
}
const b = (s: string) => utf8ToBytes(s) as Bytes;

describe("push.drainQueue", () => {
  it("pushes a new note: uploads chunks, upserts, records synced version", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("a.md", b("hello"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    const row = await d.remote.getFileById(fileId);
    expect(row?.type).toBe("note");
    expect(row?.contentChunks?.length).toBeGreaterThan(0);
    expect(d.state.getByFileId(fileId)?.syncedVersion).toBe(row?.version);
    expect(d.state.queueItems()).toEqual([]); // dequeued after success
    // chunks actually uploaded
    expect(await d.remote.getChunks(row!.contentChunks!)).toHaveLength(row!.contentChunks!.length);
  });

  it("pushes an attachment: uploads blob, sets storageId", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("img.png", new Uint8Array([9, 8, 7]) as Bytes, 100);
    d.state.enqueue({ op: "upsert", fileId, path: "img.png" });
    await drainQueue(d);
    const row = await d.remote.getFileById(fileId);
    expect(row?.type).toBe("attachment");
    expect(row?.storageId).toBeTruthy();
  });

  it("second edit pushes with the correct baseVersion and bumps version", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("a.md", b("v1"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    await d.vault.writeBinary("a.md", b("v2"), 200);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    expect((await d.remote.getFileById(fileId))?.version).toBe(2);
  });

  it("idempotent replay: if the write already landed, adopt it without a conflict copy", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("a.md", b("hello"), 100);
    // Simulate: write landed on server at v1, but sync-state never persisted (crash).
    const enc = await (await import("../../src/sync/codec")).encodeNote(b("hello"), d.keys);
    await d.remote.putChunks(enc.chunks);
    const pathIdHex = await (await import("../../src/sync/codec")).pathId("a.md", d.keys);
    await d.remote.upsertFile({
      fileId, pathId: pathIdHex, pathCipher: "x", type: "note",
      contentTag: enc.contentTag, size: 5, mtime: 100, baseVersion: 0, contentChunks: enc.contentChunks,
    });
    // Now replay the same queued item with stale base (0).
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    // Adopted: sync-state now points at the landed version; no extra conflict-copy file enqueued.
    expect(d.state.getByFileId(fileId)?.syncedVersion).toBe(1);
    expect(d.state.queueItems()).toEqual([]);
    expect([...d.vault.files.keys()]).toEqual(["a.md"]); // no conflict copy created
  });

  it("genuine conflict: leaves sync-state stale and dequeues (pull will resolve)", async () => {
    const d = await deps();
    const fileId = newFileId();
    // Server already has a DIFFERENT version of this fileId at v1.
    await d.remote.upsertFile({
      fileId, pathId: "p", pathCipher: "x", type: "note",
      contentTag: "server-tag", size: 1, mtime: 50, baseVersion: 0, contentChunks: [],
    });
    await d.vault.writeBinary("a.md", b("local edit"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    expect(d.state.getByFileId(fileId)).toBeUndefined(); // not advanced
    expect(d.state.queueItems()).toEqual([]); // dequeued; pull handles it
    expect((await d.remote.getFileById(fileId))?.contentTag).toBe("server-tag"); // server unchanged
  });

  it("tombstone pushes a delete and removes the entry", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("a.md", b("hi"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    await d.vault.trash("a.md");
    d.state.enqueue({ op: "tombstone", fileId, path: "a.md" });
    await drainQueue(d);
    expect((await d.remote.getFileById(fileId))?.deleted).toBe(true);
    expect(d.state.getByFileId(fileId)).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/push.test.ts`
Expected: FAIL — `./push` does not exist.

- [ ] **Step 3: Implement**

Create `src/sync/push.ts`:
```typescript
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
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/push.test.ts`
Expected: 7 passed.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/push.ts tests/sync/push.test.ts
git commit -m "feat(sync): idempotent push drain deferring conflicts to pull"
```

---

## Task 7: pull (apply remote changes; the single conflict-resolution site)

`pull` walks the feed via the value cursor and applies each row. It handles: echo suppression (skip our own already-synced versions), tombstones (trash + preserve a divergent local edit as a conflict copy), renames (by fileId), clean creates/updates, create/create path collisions, and both-sides-diverged conflicts (newer mtime keeps the canonical path; the loser becomes a conflict copy that gets pushed as a new file).

**Files:**
- Create: `src/sync/pull.ts`
- Test: `tests/sync/pull.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/pull.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { pull } from "../../src/sync/pull";
import { drainQueue } from "../../src/sync/push";
import { SyncState, newFileId } from "../../src/sync/state";
import { FakeVault, FakeRemote, fakeClock, makeKeys } from "./fakes";
import type { Deps } from "../../src/sync/push";
import { encodeNote, pathId, encodePath, computeContentTag } from "../../src/sync/codec";
import { utf8ToBytes, bytesToUtf8, type Bytes } from "../../src/crypto";

const b = (s: string) => utf8ToBytes(s) as Bytes;
async function deps(): Promise<Deps & { vault: FakeVault; remote: FakeRemote; state: SyncState }> {
  return { vault: new FakeVault(), remote: new FakeRemote(), state: new SyncState(), keys: await makeKeys(), clock: fakeClock };
}

// Push a note directly into a remote as if from "device B".
async function remotePutNote(d: Deps, fileId: string, path: string, body: string, mtime: number, baseVersion = 0) {
  const enc = await encodeNote(b(body), d.keys);
  await d.remote.putChunks(enc.chunks);
  return d.remote.upsertFile({
    fileId, pathId: await pathId(path, d.keys), pathCipher: await encodePath(path, d.keys),
    type: "note", contentTag: enc.contentTag, size: body.length, mtime, baseVersion, contentChunks: enc.contentChunks,
  });
}

describe("pull", () => {
  it("creates a new local file from a remote row", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "remote body", 100);
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("remote body");
    expect(d.state.getByFileId("f1")?.syncedVersion).toBe(1);
    expect(d.state.cursor).toBe(1);
  });

  it("suppresses echo: a row we already synced is not rewritten", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.vault.writeBinary("a.md", b("mine"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    const before = await d.vault.readBinary("a.md");
    await pull(d); // our own write comes back in the feed
    expect([...(await d.vault.readBinary("a.md"))]).toEqual([...before]);
    expect(d.state.cursor).toBe(1);
  });

  it("applies a tombstone by trashing the local file", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "body", 100);
    await pull(d);
    await d.remote.tombstoneFile("f1", 1);
    await pull(d);
    expect(await d.vault.exists("a.md")).toBe(false);
    expect(d.state.getByFileId("f1")).toBeUndefined();
  });

  it("applies a rename by fileId (move, not re-create)", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "body", 100);
    await pull(d);
    // device B renames: same fileId, new path, content unchanged
    const enc = await encodeNote(b("body"), d.keys);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("b.md", d.keys), pathCipher: await encodePath("b.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 4, mtime: 100, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(await d.vault.exists("a.md")).toBe(false);
    expect(bytesToUtf8(await d.vault.readBinary("b.md"))).toBe("body");
    expect(d.state.getByFileId("f1")?.path).toBe("b.md");
  });

  it("both-diverged conflict: remote newer wins the path, local saved as a conflict copy", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "base", 100);
    await pull(d); // local now a.md = "base", synced v1
    // local edits a.md (not yet pushed)
    await d.vault.writeBinary("a.md", b("local change"), 150);
    // remote also edits a.md, NEWER mtime, version 2
    const enc = await encodeNote(b("remote change"), d.keys);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("a.md", d.keys), pathCipher: await encodePath("a.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 13, mtime: 200, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("remote change"); // remote wins canonical
    const conflictPath = "a (conflict 2026-06-04 12-00-00).md";
    expect(bytesToUtf8(await d.vault.readBinary(conflictPath))).toBe("local change"); // local preserved
    expect(d.state.getByFileId("f1")?.syncedVersion).toBe(2);
    // the conflict copy is queued for push as a new file
    expect(d.state.queueItems().some((q) => q.path === conflictPath)).toBe(true);
  });

  it("both-diverged conflict: local newer keeps the path, remote saved as a conflict copy", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "base", 100);
    await pull(d);
    await d.vault.writeBinary("a.md", b("local newer"), 300); // local newer mtime
    const enc = await encodeNote(b("remote older"), d.keys);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("a.md", d.keys), pathCipher: await encodePath("a.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 12, mtime: 200, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("local newer"); // local keeps canonical
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("remote older");
    expect(d.state.queueItems().some((q) => q.fileId === "f1" && q.path === "a.md")).toBe(true); // local re-pushed
  });

  it("create/create same path different fileId: remote written under a conflict name", async () => {
    const d = await deps();
    // local already has its own file at a.md (fileId L), in sync
    const localId = newFileId();
    await d.vault.writeBinary("a.md", b("local one"), 100);
    d.state.enqueue({ op: "upsert", fileId: localId, path: "a.md" });
    await drainQueue(d);
    // remote (device B) created a DIFFERENT file at the same path
    await remotePutNote(d, "remoteId", "a.md", "remote one", 120);
    // reset cursor so the remote row is seen (drainQueue advanced server but not local cursor for remoteId)
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("local one"); // local keeps the path
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("remote one");
    expect(d.state.getByFileId("remoteId")?.path).toBe("a (conflict 2026-06-04 12-00-00).md");
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/pull.test.ts`
Expected: FAIL — `./pull` does not exist.

- [ ] **Step 3: Implement**

Create `src/sync/pull.ts`:
```typescript
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
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/pull.test.ts`
Expected: 7 passed.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/pull.ts tests/sync/pull.test.ts
git commit -m "feat(sync): pull apply with unified conflict resolution"
```

---

## Task 8: reconcile (cold start / reconnect)

Three-way reconcile by content tag, used on first run and on reconnect/foreground-resume: pull everything, then scan the vault and enqueue local-only or content-differing files for push, then enqueue tombstones for entries whose file vanished while we weren't watching, then drain.

**Files:**
- Create: `src/sync/reconcile.ts`
- Test: `tests/sync/reconcile.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/reconcile.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { reconcile } from "../../src/sync/reconcile";
import { SyncState } from "../../src/sync/state";
import { FakeVault, FakeRemote, fakeClock, makeKeys } from "./fakes";
import type { Deps } from "../../src/sync/push";
import { encodeNote, pathId, encodePath } from "../../src/sync/codec";
import { utf8ToBytes, bytesToUtf8, type Bytes } from "../../src/crypto";

const b = (s: string) => utf8ToBytes(s) as Bytes;
async function deps(): Promise<Deps & { vault: FakeVault; remote: FakeRemote; state: SyncState }> {
  return { vault: new FakeVault(), remote: new FakeRemote(), state: new SyncState(), keys: await makeKeys(), clock: fakeClock };
}

describe("reconcile (cold start)", () => {
  it("pushes local-only files and pulls remote-only files", async () => {
    const d = await deps();
    // local-only
    await d.vault.writeBinary("local.md", b("local body"), 100);
    // remote-only (from device B)
    const enc = await encodeNote(b("remote body"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "rf", pathId: await pathId("remote.md", d.keys), pathCipher: await encodePath("remote.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 11, mtime: 100, baseVersion: 0, contentChunks: enc.contentChunks,
    });
    await reconcile(d);
    // remote-only now local
    expect(bytesToUtf8(await d.vault.readBinary("remote.md"))).toBe("remote body");
    // local-only now on server
    const local = d.state.getByPath("local.md");
    expect(local).toBeTruthy();
    expect((await d.remote.getFileById(local!.fileId))?.type).toBe("note");
  });

  it("tombstones an entry whose local file disappeared while not watching", async () => {
    const d = await deps();
    await d.vault.writeBinary("gone.md", b("temp"), 100);
    await reconcile(d); // pushes gone.md
    const fileId = d.state.getByPath("gone.md")!.fileId;
    await d.vault.trash("gone.md"); // deleted offline, no event captured
    await reconcile(d);
    expect((await d.remote.getFileById(fileId))?.deleted).toBe(true);
  });

  it("is a no-op when local and remote already agree", async () => {
    const d = await deps();
    await d.vault.writeBinary("a.md", b("same"), 100);
    await reconcile(d);
    const versionAfterFirst = (await d.remote.getFileById(d.state.getByPath("a.md")!.fileId))!.version;
    await reconcile(d); // nothing changed
    const versionAfterSecond = (await d.remote.getFileById(d.state.getByPath("a.md")!.fileId))!.version;
    expect(versionAfterSecond).toBe(versionAfterFirst); // no spurious re-push
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/reconcile.test.ts`
Expected: FAIL — `./reconcile` does not exist.

- [ ] **Step 3: Implement**

Create `src/sync/reconcile.ts`:
```typescript
import type { Deps } from "./push";
import { drainQueue } from "./push";
import { pull } from "./pull";
import { newFileId } from "./state";
import { computeContentTag } from "./codec";

/**
 * Cold-start / reconnect reconcile. Order matters for no-loss: pull remote
 * first, then push local divergences, then tombstone vanished files, then drain.
 */
export async function reconcile(d: Deps): Promise<void> {
  await pull(d);

  // Local-only or content-differing files → enqueue push.
  const seen = new Set<string>();
  for (const f of await d.vault.list()) {
    seen.add(f.path);
    const entry = d.state.getByPath(f.path);
    const tag = await computeContentTag(await d.vault.readBinary(f.path), d.keys);
    if (!entry) {
      d.state.enqueue({ op: "upsert", fileId: newFileId(), path: f.path });
    } else if (entry.contentTag !== tag) {
      d.state.enqueue({ op: "upsert", fileId: entry.fileId, path: f.path });
    }
  }

  // Entries whose local file vanished while we weren't watching → tombstone.
  for (const entry of d.state.allEntries()) {
    if (!seen.has(entry.path)) {
      d.state.enqueue({ op: "tombstone", fileId: entry.fileId, path: entry.path });
    }
  }

  await drainQueue(d);
}
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/reconcile.test.ts`
Expected: 3 passed.

- [ ] **Step 5: Typecheck + commit**

Run: `npm run typecheck` → no errors.
```bash
git add src/sync/reconcile.ts tests/sync/reconcile.test.ts
git commit -m "feat(sync): cold-start/reconnect three-way reconcile"
```

---

## Task 9: SyncEngine orchestrator + barrel

The public surface Plan 4 drives. Timer-free and subscription-free: `notifyChange`/`notifyRename`/`notifyDelete` record durable intent; `sync()` drains → pulls → persists; `reconcile()` runs the cold-start path → persists. Construction loads persisted state via `StatePort`.

**Files:**
- Create: `src/sync/engine.ts`
- Create: `src/sync/index.ts`
- Test: `tests/sync/engine.test.ts`

- [ ] **Step 1: Write the tests**

Create `tests/sync/engine.test.ts`:
```typescript
import { describe, it, expect } from "vitest";
import { SyncEngine } from "../../src/sync/engine";
import { FakeVault, FakeRemote, FakeStatePort, fakeClock, makeKeys } from "./fakes";
import { utf8ToBytes, bytesToUtf8, type Bytes } from "../../src/crypto";

const b = (s: string) => utf8ToBytes(s) as Bytes;

async function makeEngine(over: { vault?: FakeVault; remote?: FakeRemote; statePort?: FakeStatePort } = {}) {
  const vault = over.vault ?? new FakeVault();
  const remote = over.remote ?? new FakeRemote();
  const statePort = over.statePort ?? new FakeStatePort();
  const engine = await SyncEngine.create({ vault, remote, statePort, clock: fakeClock }, await makeKeys());
  return { engine, vault, remote, statePort };
}

describe("SyncEngine", () => {
  it("notifyChange then sync pushes a new file", async () => {
    const { engine, vault, remote } = await makeEngine();
    await vault.writeBinary("a.md", b("hi"), 100);
    engine.notifyChange("a.md");
    await engine.sync();
    expect([...remote.files.values()][0]?.type).toBe("note");
  });

  it("notifyDelete then sync tombstones the file", async () => {
    const { engine, vault, remote } = await makeEngine();
    await vault.writeBinary("a.md", b("hi"), 100);
    engine.notifyChange("a.md");
    await engine.sync();
    await vault.trash("a.md");
    engine.notifyDelete("a.md");
    await engine.sync();
    expect([...remote.files.values()][0]?.deleted).toBe(true);
  });

  it("notifyRename moves the file server-side under the same fileId", async () => {
    const { engine, vault, remote } = await makeEngine();
    await vault.writeBinary("a.md", b("hi"), 100);
    engine.notifyChange("a.md");
    await engine.sync();
    const fileId = [...remote.files.keys()][0]!;
    await vault.rename("a.md", "b.md");
    engine.notifyRename("a.md", "b.md");
    await engine.sync();
    expect(remote.files.size).toBe(1); // not a new file
    expect(await (await import("../../src/sync/codec")).decodePath(remote.files.get(fileId)!.pathCipher, await makeKeys())).toBe("b.md");
  });

  it("persists state across instances (cursor + entries survive reload)", async () => {
    const statePort = new FakeStatePort();
    const remote = new FakeRemote();
    {
      const { engine, vault } = await makeEngine({ statePort, remote });
      await vault.writeBinary("a.md", b("hi"), 100);
      engine.notifyChange("a.md");
      await engine.sync();
    }
    // New engine instance, same statePort + remote: it resumes, no re-push.
    const { engine } = await makeEngine({ statePort, remote });
    const versionBefore = [...remote.files.values()][0]!.version;
    await engine.sync();
    expect([...remote.files.values()][0]!.version).toBe(versionBefore); // echo-suppressed, no bump
    expect(statePort.blob).toBeTruthy();
  });

  it("reconcile pulls remote-only files into a fresh engine", async () => {
    const remote = new FakeRemote();
    const { engine, vault } = await makeEngine({ remote });
    // seed remote directly
    const { encodeNote, pathId, encodePath } = await import("../../src/sync/codec");
    const keys = await makeKeys();
    const enc = await encodeNote(b("remote"), keys);
    await remote.putChunks(enc.chunks);
    await remote.upsertFile({
      fileId: "rf", pathId: await pathId("r.md", keys), pathCipher: await encodePath("r.md", keys),
      type: "note", contentTag: enc.contentTag, size: 6, mtime: 100, baseVersion: 0, contentChunks: enc.contentChunks,
    });
    await engine.reconcile();
    expect(bytesToUtf8(await vault.readBinary("r.md"))).toBe("remote");
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run tests/sync/engine.test.ts`
Expected: FAIL — `./engine` does not exist.

- [ ] **Step 3: Implement**

Create `src/sync/engine.ts`:
```typescript
import type { Subkeys } from "../crypto";
import type { Clock, RemotePort, StatePort, VaultPort } from "./ports";
import { SyncState, newFileId } from "./state";
import { drainQueue, type Deps } from "./push";
import { pull } from "./pull";
import { reconcile } from "./reconcile";

export interface EnginePorts {
  vault: VaultPort;
  remote: RemotePort;
  statePort: StatePort;
  clock: Clock;
}

/**
 * Orchestrates sync. Timer-free and subscription-free: the plugin shell (Plan 4)
 * owns the debounce timer and the Convex reactive trigger that call sync().
 */
export class SyncEngine {
  private constructor(
    private readonly ports: EnginePorts,
    private readonly deps: Deps,
  ) {}

  static async create(ports: EnginePorts, keys: Subkeys): Promise<SyncEngine> {
    const state = SyncState.deserialize(await ports.statePort.load());
    const deps: Deps = { vault: ports.vault, remote: ports.remote, state, keys, clock: ports.clock };
    return new SyncEngine(ports, deps);
  }

  /** Record a create/modify. Reuses the fileId already known for this path. */
  notifyChange(path: string): void {
    const fileId = this.deps.state.getByPath(path)?.fileId ?? newFileId();
    this.deps.state.enqueue({ op: "upsert", fileId, path });
  }

  /** Record a delete. No-op if the path is unknown. */
  notifyDelete(path: string): void {
    const entry = this.deps.state.getByPath(path);
    if (!entry) return;
    this.deps.state.enqueue({ op: "tombstone", fileId: entry.fileId, path });
  }

  /** Record a rename: same fileId, new path (one metadata update server-side). */
  notifyRename(from: string, to: string): void {
    const fileId = this.deps.state.getByPath(from)?.fileId ?? newFileId();
    this.deps.state.enqueue({ op: "upsert", fileId, path: to });
  }

  /** Drain the outbound queue, pull remote changes, persist. */
  async sync(): Promise<void> {
    await drainQueue(this.deps);
    await pull(this.deps);
    await this.persist();
  }

  /** Cold-start / reconnect reconcile, then persist. */
  async reconcile(): Promise<void> {
    await reconcile(this.deps);
    await this.persist();
  }

  private async persist(): Promise<void> {
    await this.ports.statePort.save(this.deps.state.serialize());
  }
}
```

Create `src/sync/index.ts`:
```typescript
export * from "./ports";
export * from "./codec";
export * from "./state";
export * from "./push";
export * from "./pull";
export * from "./reconcile";
export * from "./engine";
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run tests/sync/engine.test.ts`
Expected: 5 passed.

- [ ] **Step 5: Full suite + typecheck (final gate)**

Run: `npm test && npm run typecheck`
Expected: all crypto + convex + sync tests pass; tsc clean.

- [ ] **Step 6: Commit**

```bash
git add src/sync/engine.ts src/sync/index.ts tests/sync/engine.test.ts
git commit -m "feat(sync): SyncEngine orchestrator (notify + sync/reconcile) and barrel"
```

---

## Deferred (out of scope; for Plan 4 / later)

- **Debounce timer + Convex reactive subscription** — Plan 4's plugin shell owns these; they call `engine.sync()`. The engine stays a deterministic state machine.
- **Real port implementations** — `ObsidianVault` (Vault API), `ConvexRemote` (ConvexClient + upload fetch + workspaceId/syncKey), `DataDirState` (plugin data dir), real `Clock`. Plan 4.
- **`.obsidian` allowlist filtering** — which config files are eligible to sync (the engine already classifies `config` type; the *selection* policy is a Plan 4 setting feeding `VaultPort.list`).
- **Lazy attachment download** — Plan 4 opt-in; the codec/pull already isolate attachment fetch behind `fetchContent`.
- **Oversized/corrupt-file skip-and-notify** — Plan 4 surfaces user-facing notices; the engine's per-row apply is the natural place to wrap try/catch in Plan 4's adapter or a later hardening task.

## Notes for the implementer

- The engine imports only `../crypto` (the barrel) and its own modules — never Obsidian or Convex client packages.
- `Deps` (defined in `push.ts`) is the shared dependency bundle threaded through push/pull/reconcile. Import it from `./push` in those modules to keep one definition.
- All byte values flowing into WebCrypto are typed `Bytes` (`Uint8Array<ArrayBuffer>`). `FakeVault`/`FakeRemote` already produce `Bytes`; real adapters in Plan 4 wrap Obsidian's `ArrayBuffer` as `new Uint8Array(ab)`.
- Conflict copies are created in exactly one module (`pull.ts`). If you find yourself writing a conflict copy in `push.ts`, stop — push defers to pull by design.
- Run `npm run typecheck` before every commit; vitest uses esbuild and does NOT type-check.
