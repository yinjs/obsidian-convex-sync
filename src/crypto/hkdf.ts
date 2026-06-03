import { utf8ToBytes, type Bytes } from "./bytes";

export interface Subkeys {
  encKey: CryptoKey; // AES-GCM
  // Domain-separated HMAC keys: deriving a distinct key per id namespace means a
  // chunk and a path can never produce the same id, and the two id streams leak
  // nothing about each other to the server.
  chunkMacKey: CryptoKey; // HMAC-SHA256, sign only — chunkId
  pathMacKey: CryptoKey; // HMAC-SHA256, sign only — pathId
}

// Fixed, non-secret salt for HKDF — the DEK is the secret input.
const HKDF_SALT = utf8ToBytes("obsidian-convex-sync/hkdf/v1");

export async function deriveSubkeys(dek: Bytes): Promise<Subkeys> {
  const base = await crypto.subtle.importKey("raw", dek, "HKDF", false, ["deriveKey"]);

  const encKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes("enc") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const deriveMacKey = (info: string) =>
    crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes(info) },
      base,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );

  const chunkMacKey = await deriveMacKey("mac-chunk");
  const pathMacKey = await deriveMacKey("mac-path");

  return { encKey, chunkMacKey, pathMacKey };
}
