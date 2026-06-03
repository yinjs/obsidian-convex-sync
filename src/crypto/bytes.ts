// WebCrypto's BufferSource requires an ArrayBuffer-backed view (not SharedArrayBuffer).
// Bytes that flow into crypto.subtle.* are typed as `Bytes` so the backing buffer is honest.
export type Bytes = Uint8Array<ArrayBuffer>;

export function utf8ToBytes(s: string): Bytes {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesToBase64(b: Uint8Array): string {
  let bin = "";
  for (const byte of b) bin += String.fromCharCode(byte);
  return btoa(bin);
}

export function base64ToBytes(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// crypto.getRandomValues is limited to 65536 bytes per call (Web Crypto spec).
// Loop over 64 KiB-sized slices to support arbitrary lengths.
export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  const MAX = 65536;
  for (let off = 0; off < n; off += MAX) {
    crypto.getRandomValues(out.subarray(off, Math.min(off + MAX, n)));
  }
  return out;
}
