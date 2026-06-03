import { describe, it, expect } from "vitest";
import { chunk, CHUNK_MIN, CHUNK_MAX } from "../../src/crypto/chunker";
import { randomBytes } from "../../src/crypto/bytes";

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

describe("chunker", () => {
  it("reassembles to the original bytes", () => {
    const data = randomBytes(200_000);
    expect(concat(chunk(data))).toEqual(data);
  });

  it("small input is a single chunk", () => {
    const data = randomBytes(100);
    expect(chunk(data).length).toBe(1);
  });

  it("empty input is a single zero-length chunk", () => {
    const chunks = chunk(new Uint8Array(0));
    expect(chunks.length).toBe(1);
    expect(chunks[0]!.length).toBe(0);
  });

  it("respects min/max bounds (except the final chunk may be short)", () => {
    const data = randomBytes(300_000);
    const chunks = chunk(data);
    chunks.slice(0, -1).forEach((c) => {
      expect(c.length).toBeGreaterThanOrEqual(CHUNK_MIN);
      expect(c.length).toBeLessThanOrEqual(CHUNK_MAX);
    });
  });

  it("is deterministic", () => {
    const data = randomBytes(150_000);
    const a = chunk(data).map((c) => c.length);
    const b = chunk(data).map((c) => c.length);
    expect(a).toEqual(b);
  });

  it("an edit near the front leaves most later chunks unchanged (locality)", () => {
    const base = randomBytes(300_000);
    const edited = new Uint8Array(base);
    edited.set(randomBytes(10), 50); // mutate 10 bytes near the front
    const join = (cs: Uint8Array[]) => cs.map((c) => Array.from(c).join(","));
    const a = join(chunk(base));
    const b = join(chunk(edited));
    const shared = a.filter((c) => b.includes(c)).length;
    // Most chunks past the edit point should be byte-identical.
    expect(shared).toBeGreaterThan(a.length / 2);
  });
});
