import { describe, it, expect } from "vitest";
import { deriveSubkeys } from "../../src/crypto/hkdf";
import { hmacId } from "../../src/crypto/hmacId";
import { utf8ToBytes } from "../../src/crypto/bytes";

describe("hmacId", () => {
  it("is deterministic: same input -> same id", async () => {
    const { chunkMacKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const a = await hmacId(chunkMacKey, utf8ToBytes("chunk body"));
    const b = await hmacId(chunkMacKey, utf8ToBytes("chunk body"));
    expect(a).toBe(b);
  });

  it("different input -> different id", async () => {
    const { chunkMacKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const a = await hmacId(chunkMacKey, utf8ToBytes("a"));
    const b = await hmacId(chunkMacKey, utf8ToBytes("b"));
    expect(a).not.toBe(b);
  });

  it("returns a 64-char lowercase hex string", async () => {
    const { chunkMacKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const id = await hmacId(chunkMacKey, utf8ToBytes("x"));
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });
});
