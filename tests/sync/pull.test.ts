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
});
