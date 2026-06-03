import { bytesToHex, type Bytes } from "./bytes";

/**
 * Deterministic opaque id for dedup (chunkId) and lookup (pathId).
 * Pass the domain-specific HMAC key from `deriveSubkeys` (chunkMacKey for chunk
 * bodies, pathMacKey for paths). The server never holds these keys, so it cannot
 * test guessed plaintext.
 */
export async function hmacId(macKey: CryptoKey, data: Bytes): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", macKey, data);
  return bytesToHex(new Uint8Array(sig));
}
