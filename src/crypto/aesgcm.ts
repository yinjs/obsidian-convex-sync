import { randomBytes, bytesToBase64, base64ToBytes, type Bytes } from "./bytes";

export interface Ciphertext {
  nonce: Bytes; // 12 bytes
  data: Bytes; // ciphertext + 16-byte GCM tag
}

const NONCE_LEN = 12;

export async function importAesKey(raw: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function aesGcmEncrypt(key: CryptoKey, plaintext: Bytes): Promise<Ciphertext> {
  const nonce = randomBytes(NONCE_LEN);
  const buf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return { nonce, data: new Uint8Array(buf) };
}

export async function aesGcmDecrypt(key: CryptoKey, ct: Ciphertext): Promise<Bytes> {
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ct.nonce }, key, ct.data);
  return new Uint8Array(buf);
}

// Storage format: base64(nonce) + "." + base64(data)
export function serializeCiphertext(ct: Ciphertext): string {
  return `${bytesToBase64(ct.nonce)}.${bytesToBase64(ct.data)}`;
}

export function deserializeCiphertext(s: string): Ciphertext {
  const dot = s.indexOf(".");
  if (dot < 0) throw new Error("malformed ciphertext");
  return {
    nonce: base64ToBytes(s.slice(0, dot)),
    data: base64ToBytes(s.slice(dot + 1)),
  };
}
