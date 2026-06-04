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
