import type { Bytes } from "./bytes";

// FastCDC-style content-defined chunking with a gear hash.
// Bounds chosen so each plaintext chunk's ciphertext stays well under Convex's 1 MiB doc cap.
export const CHUNK_MIN = 16 * 1024; // 16 KiB
export const CHUNK_AVG = 64 * 1024; // 64 KiB target
export const CHUNK_MAX = 256 * 1024; // 256 KiB

// Mask with ~log2(CHUNK_AVG) one-bits → boundary roughly every CHUNK_AVG bytes.
const MASK = 0xffff; // 16 one-bits ≈ 64 KiB average

// Deterministic 256-entry gear table (fixed seed, no randomness).
const GEAR = buildGear();
function buildGear(): Uint32Array {
  const g = new Uint32Array(256);
  let x = 0x9e3779b1 >>> 0; // fixed seed
  for (let i = 0; i < 256; i++) {
    // xorshift32 — deterministic
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    g[i] = x >>> 0;
  }
  return g;
}

function nextBoundary(data: Bytes, start: number): number {
  const end = Math.min(start + CHUNK_MAX, data.length);
  let hash = 0;
  let i = start;
  const minEnd = Math.min(start + CHUNK_MIN, data.length);
  // Skip the minimum region (no boundary allowed before CHUNK_MIN).
  for (; i < minEnd; i++) {
    hash = ((hash << 1) + GEAR[data[i]!]!) >>> 0;
  }
  for (; i < end; i++) {
    hash = ((hash << 1) + GEAR[data[i]!]!) >>> 0;
    if ((hash & MASK) === 0) return i + 1; // boundary
  }
  return end; // hit CHUNK_MAX or end of data
}

export function chunk(data: Bytes): Bytes[] {
  // Empty input yields exactly one zero-length chunk: an empty file still has a
  // chunk so it round-trips and is representable, rather than collapsing to "no
  // content". Callers can rely on `chunk(x).length >= 1` for any input.
  if (data.length === 0) return [new Uint8Array(0)];
  const out: Bytes[] = [];
  let pos = 0;
  while (pos < data.length) {
    const next = nextBoundary(data, pos);
    out.push(data.subarray(pos, next));
    pos = next;
  }
  return out;
}
