import { describe, it, expect } from "vitest";
import { importAesKey, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8, randomBytes } from "../../src/crypto/bytes";

describe("aesgcm", () => {
  it("encrypt then decrypt round-trips", async () => {
    const key = await importAesKey(randomBytes(32));
    const pt = utf8ToBytes("secret note body");
    const ct = await aesGcmEncrypt(key, pt);
    expect(bytesToUtf8(await aesGcmDecrypt(key, ct))).toBe("secret note body");
  });

  it("uses a fresh nonce each time (no reuse)", async () => {
    const key = await importAesKey(randomBytes(32));
    const pt = utf8ToBytes("same plaintext");
    const a = await aesGcmEncrypt(key, pt);
    const b = await aesGcmEncrypt(key, pt);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.data).not.toEqual(b.data);
  });

  it("tampered ciphertext fails to decrypt", async () => {
    const key = await importAesKey(randomBytes(32));
    const ct = await aesGcmEncrypt(key, utf8ToBytes("x"));
    ct.data[0]! ^= 0xff;
    await expect(aesGcmDecrypt(key, ct)).rejects.toThrow();
  });

  it("serialize then deserialize round-trips", async () => {
    const key = await importAesKey(randomBytes(32));
    const ct = await aesGcmEncrypt(key, utf8ToBytes("store me"));
    const restored = deserializeCiphertext(serializeCiphertext(ct));
    expect(bytesToUtf8(await aesGcmDecrypt(key, restored))).toBe("store me");
  });
});
