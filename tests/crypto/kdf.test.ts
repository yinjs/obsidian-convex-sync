import { describe, it, expect } from "vitest";
import { deriveKek, defaultKdfParams, type KdfParams } from "../../src/crypto/kdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8 } from "../../src/crypto/bytes";

const salt = new Uint8Array(16).fill(9);
const pbkdf2: KdfParams = { algo: "pbkdf2", iterations: 600000 };
const argon2: KdfParams = { algo: "argon2id", iterations: 3, memoryKiB: 65536, parallelism: 1 };

describe("kdf", () => {
  it("pbkdf2: derives a wrapping key that round-trips AES-GCM", async () => {
    const kek = await deriveKek("correct horse", salt, pbkdf2);
    const ct = await aesGcmEncrypt(kek, utf8ToBytes("dek-bytes"));
    expect(bytesToUtf8(await aesGcmDecrypt(kek, ct))).toBe("dek-bytes");
  });

  it("pbkdf2: same passphrase+salt -> same key; different passphrase -> different", async () => {
    const k1 = await deriveKek("pw", salt, pbkdf2);
    const ct = await aesGcmEncrypt(k1, utf8ToBytes("m"));
    const k1b = await deriveKek("pw", salt, pbkdf2);
    await expect(aesGcmDecrypt(k1b, ct)).resolves.toBeDefined();
    const k2 = await deriveKek("other", salt, pbkdf2);
    await expect(aesGcmDecrypt(k2, ct)).rejects.toThrow();
  });

  it("argon2id: derives a usable wrapping key (webview-feasibility spike)", async () => {
    const kek = await deriveKek("correct horse", salt, argon2);
    const ct = await aesGcmEncrypt(kek, utf8ToBytes("dek-bytes"));
    expect(bytesToUtf8(await aesGcmDecrypt(kek, ct))).toBe("dek-bytes");
  });

  it("defaultKdfParams is argon2id", () => {
    expect(defaultKdfParams().algo).toBe("argon2id");
  });
});
