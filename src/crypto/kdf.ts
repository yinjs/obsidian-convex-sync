import { argon2id } from "hash-wasm";
import { importAesKey } from "./aesgcm";
import { utf8ToBytes } from "./bytes";

export type KdfParams =
  | { algo: "pbkdf2"; iterations: number }
  | { algo: "argon2id"; iterations: number; memoryKiB: number; parallelism: number };

export function defaultKdfParams(): KdfParams {
  // Argon2id is the target; tune cost during the spike on real mobile hardware.
  return { algo: "argon2id", iterations: 3, memoryKiB: 65536, parallelism: 1 };
}

export async function deriveKek(
  passphrase: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<CryptoKey> {
  const raw = await deriveRawKek(passphrase, salt, params);
  return importAesKey(raw);
}

async function deriveRawKek(passphrase: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  if (params.algo === "argon2id") {
    const hash = await argon2id({
      password: utf8ToBytes(passphrase),
      salt,
      iterations: params.iterations,
      memorySize: params.memoryKiB,
      parallelism: params.parallelism,
      hashLength: 32,
      outputType: "binary",
    });
    return hash as Uint8Array;
  }
  // pbkdf2 fallback (native WebCrypto)
  const base = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: "SHA-256" },
    base,
    256,
  );
  return new Uint8Array(bits);
}
