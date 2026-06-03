import { describe, it, expect } from "vitest";
import { bootstrap, unlock, unlockWithRecovery, rewrapForNewPassphrase } from "../../src/crypto/envelope";
import { hmacId } from "../../src/crypto/hmacId";
import { utf8ToBytes } from "../../src/crypto/bytes";

const sameChunkId = async (a: { chunkMacKey: CryptoKey }, b: { chunkMacKey: CryptoKey }) => {
  const ia = await hmacId(a.chunkMacKey, utf8ToBytes("chunk"));
  const ib = await hmacId(b.chunkMacKey, utf8ToBytes("chunk"));
  return ia === ib;
};

describe("envelope", () => {
  it("bootstrap then unlock with the same passphrase yields the same working keys", async () => {
    const boot = await bootstrap("hunter2");
    const keys = await unlock("hunter2", boot.wrapped);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
  });

  it("wrong passphrase fails to unlock (GCM tag)", async () => {
    const boot = await bootstrap("hunter2");
    await expect(unlock("wrong", boot.wrapped)).rejects.toThrow();
  });

  it("recovery code recovers the same DEK", async () => {
    const boot = await bootstrap("hunter2");
    const keys = await unlockWithRecovery(boot.recovery.code, boot.recovery.recoveryWrap);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
  });

  it("wrong recovery code fails (GCM tag)", async () => {
    const boot = await bootstrap("hunter2");
    const wrongCode = "0".repeat(boot.recovery.code.length);
    await expect(unlockWithRecovery(wrongCode, boot.recovery.recoveryWrap)).rejects.toThrow();
  });

  it("recovery still works after a passphrase rotation", async () => {
    const boot = await bootstrap("old-pass");
    await rewrapForNewPassphrase("new-pass", boot.wrapped, "old-pass");
    // recoveryWrap is independent of the passphrase wrap, so it is unaffected.
    const keys = await unlockWithRecovery(boot.recovery.code, boot.recovery.recoveryWrap);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
  });

  it("full envelope flow works under the PBKDF2 fallback KDF", async () => {
    const boot = await bootstrap("hunter2", { algo: "pbkdf2", iterations: 10_000 });
    const keys = await unlock("hunter2", boot.wrapped);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
    await expect(unlock("wrong", boot.wrapped)).rejects.toThrow();
  });

  it("passphrase rotation: new passphrase unlocks, old does not, keys unchanged", async () => {
    const boot = await bootstrap("old-pass");
    const rewrapped = await rewrapForNewPassphrase("new-pass", boot.wrapped, "old-pass");
    const keys = await unlock("new-pass", rewrapped);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
    await expect(unlock("old-pass", rewrapped)).rejects.toThrow();
  });

  it("bootstrap emits a sync key and its verifier hash", async () => {
    const boot = await bootstrap("hunter2");
    expect(boot.syncKey).toMatch(/^[0-9a-f]{64}$/);
    expect(boot.syncKeyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(boot.syncKeyHash).not.toBe(boot.syncKey);
  });
});
