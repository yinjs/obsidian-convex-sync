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
    await d.vault.writeBinary("local.md", b("local body"), 100);
    const enc = await encodeNote(b("remote body"), d.keys);
    await d.remote.putChunks(enc.chunks);
    await d.remote.upsertFile({
      fileId: "rf", pathId: await pathId("remote.md", d.keys), pathCipher: await encodePath("remote.md", d.keys),
      type: "note", contentTag: enc.contentTag, size: 11, mtime: 100, baseVersion: 0, contentChunks: enc.contentChunks,
    });
    await reconcile(d);
    expect(bytesToUtf8(await d.vault.readBinary("remote.md"))).toBe("remote body");
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
    await reconcile(d);
    const versionAfterSecond = (await d.remote.getFileById(d.state.getByPath("a.md")!.fileId))!.version;
    expect(versionAfterSecond).toBe(versionAfterFirst);
  });
});
