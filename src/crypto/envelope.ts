import { randomBytes, bytesToBase64, base64ToBytes, bytesToHex, utf8ToBytes, type Bytes } from "./bytes";
import { importAesKey, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext } from "./aesgcm";
import { deriveKek, defaultKdfParams, type KdfParams } from "./kdf";
import { deriveSubkeys, type Subkeys } from "./hkdf";

/** Stored on the server in the `workspaces` row (all non-secret-at-rest). */
export interface WrappedDek {
  kdfSalt: string; // base64
  kdfParams: KdfParams;
  dekWrap: string; // serialized Ciphertext of the DEK under the KEK
}

export interface BootstrapResult {
  wrapped: WrappedDek;
  recovery: { code: string; recoveryWrap: string };
  keys: Subkeys;
  syncKey: string; // give to the user; paste on each device
  syncKeyHash: string; // store on server as the verifier
}

const RECOVERY_SALT = utf8ToBytes("obsidian-convex-sync/recovery/v1");

async function wrapDek(passphrase: string, dek: Bytes, params: KdfParams, salt: Bytes): Promise<WrappedDek> {
  const kek = await deriveKek(passphrase, salt, params);
  const dekWrap = serializeCiphertext(await aesGcmEncrypt(kek, dek));
  return { kdfSalt: bytesToBase64(salt), kdfParams: params, dekWrap };
}

async function unwrapDek(passphrase: string, wrapped: WrappedDek): Promise<Bytes> {
  const kek = await deriveKek(passphrase, base64ToBytes(wrapped.kdfSalt), wrapped.kdfParams);
  return aesGcmDecrypt(kek, deserializeCiphertext(wrapped.dekWrap)); // throws on wrong passphrase
}

async function sha256Hex(data: Bytes): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

// `params` lets a device pick its KDF (e.g. PBKDF2 where Argon2id's WASM is
// unavailable); it is stored per-wrap, so devices can differ without conflict.
export async function bootstrap(
  passphrase: string,
  params: KdfParams = defaultKdfParams(),
): Promise<BootstrapResult> {
  const dek = randomBytes(32);
  const salt = randomBytes(16);
  const wrapped = await wrapDek(passphrase, dek, params, salt);

  // Recovery: wrap the same DEK under a key derived from a random recovery code.
  const code = bytesToHex(randomBytes(16)); // 32-char recovery code, shown once
  const recoveryKek = await importAesKey(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...RECOVERY_SALT, ...utf8ToBytes(code)]))),
  );
  const recoveryWrap = serializeCiphertext(await aesGcmEncrypt(recoveryKek, dek));

  // The verifier hashes the hex-encoded sync-key string (not the raw 32 bytes);
  // each device re-hashes the same string it was given to match.
  const syncKey = bytesToHex(randomBytes(32));
  const syncKeyHash = await sha256Hex(utf8ToBytes(syncKey));

  return {
    wrapped,
    recovery: { code, recoveryWrap },
    keys: await deriveSubkeys(dek),
    syncKey,
    syncKeyHash,
  };
}

export async function unlock(passphrase: string, wrapped: WrappedDek): Promise<Subkeys> {
  return deriveSubkeys(await unwrapDek(passphrase, wrapped));
}

export async function unlockWithRecovery(code: string, recoveryWrap: string): Promise<Subkeys> {
  const recoveryKek = await importAesKey(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...RECOVERY_SALT, ...utf8ToBytes(code)]))),
  );
  const dek = await aesGcmDecrypt(recoveryKek, deserializeCiphertext(recoveryWrap));
  return deriveSubkeys(dek);
}

export async function rewrapForNewPassphrase(
  newPassphrase: string,
  wrapped: WrappedDek,
  oldPassphrase: string,
): Promise<WrappedDek> {
  const dek = await unwrapDek(oldPassphrase, wrapped); // verifies old passphrase
  // Inherit the existing wrap's KDF: rotation must not silently switch algorithm
  // (e.g. PBKDF2 -> Argon2id), which could lock out a device that can only run
  // the original KDF. Only the salt is refreshed.
  const salt = randomBytes(16);
  return wrapDek(newPassphrase, dek, wrapped.kdfParams, salt);
}
