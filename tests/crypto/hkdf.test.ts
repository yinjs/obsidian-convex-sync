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

  it("derives a macKey usable for HMAC signing", async () => {
    const dek = new Uint8Array(32).fill(7);
    const { macKey } = await deriveSubkeys(dek);
    const sig = await crypto.subtle.sign("HMAC", macKey, utf8ToBytes("x"));
    expect(new Uint8Array(sig).length).toBe(32);
  });

  it("is deterministic for the same DEK and divergent for different DEKs", async () => {
    const a = await deriveSubkeys(new Uint8Array(32).fill(1));
    const b = await deriveSubkeys(new Uint8Array(32).fill(1));
    const c = await deriveSubkeys(new Uint8Array(32).fill(2));
    const sign = (k: CryptoKey) =>
      crypto.subtle.sign("HMAC", k, utf8ToBytes("m")).then((s) => new Uint8Array(s).join(","));
    expect(await sign(a.macKey)).toBe(await sign(b.macKey));
    expect(await sign(a.macKey)).not.toBe(await sign(c.macKey));
  });
});
