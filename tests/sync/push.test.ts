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
    expect(d.state.queueItems()).toEqual([]);
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
    const enc = await (await import("../../src/sync/codec")).encodeNote(b("hello"), d.keys);
    await d.remote.putChunks(enc.chunks);
    const pathIdHex = await (await import("../../src/sync/codec")).pathId("a.md", d.keys);
    await d.remote.upsertFile({
      fileId, pathId: pathIdHex, pathCipher: "x", type: "note",
      contentTag: enc.contentTag, size: 5, mtime: 100, baseVersion: 0, contentChunks: enc.contentChunks,
    });
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    expect(d.state.getByFileId(fileId)?.syncedVersion).toBe(1);
    expect(d.state.queueItems()).toEqual([]);
    expect([...d.vault.files.keys()]).toEqual(["a.md"]);
  });

  it("genuine conflict: leaves sync-state stale and dequeues (pull will resolve)", async () => {
    const d = await deps();
    const fileId = newFileId();
    await d.remote.upsertFile({
      fileId, pathId: "p", pathCipher: "x", type: "note",
      contentTag: "server-tag", size: 1, mtime: 50, baseVersion: 0, contentChunks: [],
    });
    await d.vault.writeBinary("a.md", b("local edit"), 100);
    d.state.enqueue({ op: "upsert", fileId, path: "a.md" });
    await drainQueue(d);
    expect(d.state.getByFileId(fileId)).toBeUndefined();
    expect(d.state.queueItems()).toEqual([]);
    expect((await d.remote.getFileById(fileId))?.contentTag).toBe("server-tag");
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
