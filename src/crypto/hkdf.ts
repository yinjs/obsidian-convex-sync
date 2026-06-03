import { utf8ToBytes } from "./bytes";

export interface Subkeys {
  encKey: CryptoKey; // AES-GCM
  macKey: CryptoKey; // HMAC-SHA256, sign only
}

// Fixed, non-secret salt for HKDF — the DEK is the secret input.
const HKDF_SALT = utf8ToBytes("obsidian-convex-sync/hkdf/v1");

export async function deriveSubkeys(dek: Uint8Array): Promise<Subkeys> {
  const base = await crypto.subtle.importKey("raw", dek, "HKDF", false, ["deriveKey"]);

  const encKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes("enc") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const macKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes("mac") },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );

  return { encKey, macKey };
}
