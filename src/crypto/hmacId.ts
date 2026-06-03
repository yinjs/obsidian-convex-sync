import { bytesToHex } from "./bytes";

/**
 * Deterministic opaque id for dedup (chunkId) and lookup (pathId).
 * The server never holds macKey, so it cannot test guessed plaintext.
 */
export async function hmacId(macKey: CryptoKey, data: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", macKey, data);
  return bytesToHex(new Uint8Array(sig));
}
