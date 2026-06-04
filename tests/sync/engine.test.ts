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
    expect(remote.files.size).toBe(1);
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
    const { engine } = await makeEngine({ statePort, remote });
    const versionBefore = [...remote.files.values()][0]!.version;
    await engine.sync();
    expect([...remote.files.values()][0]!.version).toBe(versionBefore);
    expect(statePort.blob).toBeTruthy();
  });

  it("reconcile pulls remote-only files into a fresh engine", async () => {
    const remote = new FakeRemote();
    const { engine, vault } = await makeEngine({ remote });
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
