import { describe, it, expect } from "vitest";
import { bootstrap, unlock, unlockWithRecovery, rewrapForNewPassphrase } from "../../src/crypto/envelope";
import { hmacId } from "../../src/crypto/hmacId";
import { utf8ToBytes } from "../../src/crypto/bytes";

const sameChunkId = async (a: { macKey: CryptoKey }, b: { macKey: CryptoKey }) => {
  const ia = await hmacId(a.macKey, utf8ToBytes("chunk"));
  const ib = await hmacId(b.macKey, utf8ToBytes("chunk"));
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
