import { describe, it, expect } from "vitest";
import { deriveSubkeys } from "../../src/crypto/hkdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8 } from "../../src/crypto/bytes";

describe("hkdf", () => {
  it("derives an encKey usable for AES-GCM", async () => {
    const dek = new Uint8Array(32).fill(7);
    const { encKey } = await deriveSubkeys(dek);
    const ct = await aesGcmEncrypt(encKey, utf8ToBytes("hi"));
    expect(bytesToUtf8(await aesGcmDecrypt(encKey, ct))).toBe("hi");
  });

  it("derives mac keys usable for HMAC signing", async () => {
    const dek = new Uint8Array(32).fill(7);
    const { chunkMacKey } = await deriveSubkeys(dek);
    const sig = await crypto.subtle.sign("HMAC", chunkMacKey, utf8ToBytes("x"));
    expect(new Uint8Array(sig).length).toBe(32);
  });

  it("is deterministic for the same DEK and divergent for different DEKs", async () => {
    const a = await deriveSubkeys(new Uint8Array(32).fill(1));
    const b = await deriveSubkeys(new Uint8Array(32).fill(1));
    const c = await deriveSubkeys(new Uint8Array(32).fill(2));
    const sign = (k: CryptoKey) =>
      crypto.subtle.sign("HMAC", k, utf8ToBytes("m")).then((s) => new Uint8Array(s).join(","));
    expect(await sign(a.chunkMacKey)).toBe(await sign(b.chunkMacKey));
    expect(await sign(a.chunkMacKey)).not.toBe(await sign(c.chunkMacKey));
  });

  it("enforces key usages: enc for AES, sign-only for the mac keys", async () => {
    const { encKey, chunkMacKey, pathMacKey } = await deriveSubkeys(new Uint8Array(32).fill(5));
    expect([...encKey.usages].sort()).toEqual(["decrypt", "encrypt"]);
    expect(chunkMacKey.usages).toEqual(["sign"]);
    expect(pathMacKey.usages).toEqual(["sign"]);
  });

  it("chunk and path mac keys are domain-separated: same input -> different id", async () => {
    const { chunkMacKey, pathMacKey } = await deriveSubkeys(new Uint8Array(32).fill(9));
    const sign = (k: CryptoKey) =>
      crypto.subtle.sign("HMAC", k, utf8ToBytes("collision")).then((s) => new Uint8Array(s).join(","));
    expect(await sign(chunkMacKey)).not.toBe(await sign(pathMacKey));
  });

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
});
