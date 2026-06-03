import { describe, it, expect } from "vitest";
import { utf8ToBytes, bytesToUtf8, bytesToBase64, base64ToBytes, bytesToHex } from "../../src/crypto/bytes";

describe("bytes", () => {
  it("round-trips utf8", () => {
    const s = "héllo 世界";
    expect(bytesToUtf8(utf8ToBytes(s))).toBe(s);
  });

  it("round-trips base64", () => {
    const b = new Uint8Array([0, 1, 2, 250, 255]);
    expect(base64ToBytes(bytesToBase64(b))).toEqual(b);
  });

  it("hex is lowercase and fixed width", () => {
    expect(bytesToHex(new Uint8Array([0, 15, 255]))).toBe("000fff");
  });
});
