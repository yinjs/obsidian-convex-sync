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
    await pull(d);
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
    await pull(d);
    await d.vault.writeBinary("a.md", b("local change"), 150);
    const enc = await encodeNote(b("remote change"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("a.md", d.keys), pathCipher: await encodePath("a.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 13, mtime: 200, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("remote change");
    const conflictPath = "a (conflict 2026-06-04 12-00-00).md";
    expect(bytesToUtf8(await d.vault.readBinary(conflictPath))).toBe("local change");
    expect(d.state.getByFileId("f1")?.syncedVersion).toBe(2);
    expect(d.state.queueItems().some((q) => q.path === conflictPath)).toBe(true);
  });

  it("both-diverged conflict: local newer keeps the path, remote saved as a conflict copy", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "base", 100);
    await pull(d);
    await d.vault.writeBinary("a.md", b("local newer"), 300);
    const enc = await encodeNote(b("remote older"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("a.md", d.keys), pathCipher: await encodePath("a.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 12, mtime: 200, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("local newer");
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("remote older");
    expect(d.state.queueItems().some((q) => q.fileId === "f1" && q.path === "a.md")).toBe(true);
  });

  it("create/create same path different fileId: remote written under a conflict name", async () => {
    const d = await deps();
    const localId = newFileId();
    await d.vault.writeBinary("a.md", b("local one"), 100);
    d.state.enqueue({ op: "upsert", fileId: localId, path: "a.md" });
    await drainQueue(d);
    await remotePutNote(d, "remoteId", "a.md", "remote one", 120);
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("local one");
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("remote one");
    expect(d.state.getByFileId("remoteId")?.path).toBe("a (conflict 2026-06-04 12-00-00).md");
  });

  it("rematerializes a locally-deleted, content-unchanged file when remote renames it (bug A)", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "body", 100);
    await pull(d); // a.md created, f1 synced v1
    await d.vault.trash("a.md"); // deleted locally, no event captured
    // remote renames f1 a.md -> b.md, content unchanged
    const enc = await encodeNote(b("body"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("b.md", d.keys), pathCipher: await encodePath("b.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 4, mtime: 100, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("b.md"))).toBe("body"); // materialized, not silently skipped
    expect(d.state.getByFileId("f1")?.path).toBe("b.md");
  });

  it("remote rename does not clobber a different local file occupying the destination (bug B)", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "f1 body", 100);
    await pull(d); // a.md = "f1 body", f1 synced v1
    // local creates a DIFFERENT file at b.md (queued, not yet pushed → no SyncEntry)
    await d.vault.writeBinary("b.md", b("local f2 body"), 150);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: "b.md" });
    // remote renames f1 a.md -> b.md
    const enc = await encodeNote(b("f1 body"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("b.md", d.keys), pathCipher: await encodePath("b.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 7, mtime: 100, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    expect(bytesToUtf8(await d.vault.readBinary("b.md"))).toBe("local f2 body"); // local file preserved
    expect(bytesToUtf8(await d.vault.readBinary("b (conflict 2026-06-04 12-00-00).md"))).toBe("f1 body"); // f1 diverted
    expect(d.state.getByFileId("f1")?.path).toBe("b (conflict 2026-06-04 12-00-00).md");
    expect(await d.vault.exists("a.md")).toBe(false); // f1 moved away from its old path
  });

  it("conflict resolution does not clobber a third local file at the remote's destination (bug C1)", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "f1 base", 100);
    await pull(d); // a.md = "f1 base", f1 synced v1
    // local edits a.md (now diverged from synced state)
    await d.vault.writeBinary("a.md", b("f1 local edit"), 150);
    // a DIFFERENT local file sits at b.md (queued, not yet pushed → no SyncEntry)
    await d.vault.writeBinary("b.md", b("f2 third file"), 160);
    d.state.enqueue({ op: "upsert", fileId: newFileId(), path: "b.md" });
    // remote renames f1 a.md -> b.md with a NEWER mtime (remote wins)
    const enc = await encodeNote(b("f1 remote rename"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "f1", pathId: await pathId("b.md", d.keys), pathCipher: await encodePath("b.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 16, mtime: 200, baseVersion: 1, contentChunks: enc.contentChunks,
    });
    await pull(d);
    // third file at b.md is untouched
    expect(bytesToUtf8(await d.vault.readBinary("b.md"))).toBe("f2 third file");
    // remote winner placed at local's slot a.md; local edit preserved as a conflict copy
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("f1 remote rename");
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("f1 local edit");
    expect(d.state.getByFileId("f1")?.path).toBe("a.md");
  });

  it("does not create a spurious conflict copy when a crashed pull already wrote the content (bug I1)", async () => {
    const d = await deps();
    await remotePutNote(d, "f1", "a.md", "remote body", 100);
    // simulate a crashed pull: the file was written to disk with the EXACT remote
    // content, but sync-state (entry + cursor) was never persisted. Replay below.
    await d.vault.writeBinary("a.md", b("remote body"), 100);
    await pull(d); // no entry, cursor still 0 → row replays
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("remote body");
    expect(await d.vault.exists("a (conflict 2026-06-04 12-00-00).md")).toBe(false); // no spurious copy
    expect(d.state.getByFileId("f1")?.path).toBe("a.md");
    expect(d.state.getByFileId("f1")?.syncedVersion).toBe(1);
  });

  it("I1 guard: diverts a byte-identical remote file when a QUEUED local file claims the path (pull-before-drain)", async () => {
    const d = await deps();
    // local-only a.md queued under fLocal (no SyncEntry yet) — the reconcile() order
    // where pull runs before drainQueue. The adopt heuristic must NOT steal a.md from
    // fLocal just because content happens to match.
    const fLocal = newFileId();
    await d.vault.writeBinary("a.md", b("same body"), 100);
    d.state.enqueue({ op: "upsert", fileId: fLocal, path: "a.md" });
    await remotePutNote(d, "f1", "a.md", "same body", 120); // byte-identical remote file
    await pull(d);
    // f1 diverted to a conflict copy; a.md still belongs to the local file (no zombie).
    expect(d.state.getByFileId("f1")?.path).toBe("a (conflict 2026-06-04 12-00-00).md");
    expect(bytesToUtf8(await d.vault.readBinary("a (conflict 2026-06-04 12-00-00).md"))).toBe("same body");
    expect(bytesToUtf8(await d.vault.readBinary("a.md"))).toBe("same body");
    expect(d.state.queuedUpsertPaths().has("a.md")).toBe(true); // fLocal still owns its queued push
  });

  it("I1 guard: diverts a byte-identical remote file when a TRACKED local file claims the path (drain-before-pull)", async () => {
    const d = await deps();
    // local a.md pushed first (sync() order: drainQueue before pull) → fLocal has an entry.
    const fLocal = newFileId();
    await d.vault.writeBinary("a.md", b("same body"), 100);
    d.state.enqueue({ op: "upsert", fileId: fLocal, path: "a.md" });
    await drainQueue(d); // fLocal now tracked at a.md
    await remotePutNote(d, "f1", "a.md", "same body", 120); // byte-identical remote file
    await pull(d);
    // local keeps the path (entry intact, no zombie); f1 diverted to a conflict copy.
    expect(d.state.getByPath("a.md")?.fileId).toBe(fLocal);
    expect(d.state.getByFileId("f1")?.path).toBe("a (conflict 2026-06-04 12-00-00).md");
  });
});
