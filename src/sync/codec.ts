import type { Bytes } from "../crypto";
import {
  chunk, hmacId, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext,
  utf8ToBytes, bytesToUtf8, type Subkeys,
} from "../crypto";
import type { FileType } from "./ports";

const NONCE_LEN = 12;

export interface EncodedNote {
  chunks: { chunkId: string; cipher: string }[]; // to putChunks
  contentChunks: string[]; // ordered chunk ids for the files row
  contentTag: string;
}

export interface EncodedAttachment {
  cipher: Bytes; // raw nonce(12) ++ data, for file storage
  contentTag: string;
}

/** HMAC(contentMacKey, SHA-256(content)) — keyed change-detection tag. */
export async function computeContentTag(content: Bytes, keys: Subkeys): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", content)) as Bytes;
  return hmacId(keys.contentMacKey, hash);
}

export async function encodeNote(content: Bytes, keys: Subkeys): Promise<EncodedNote> {
  const parts = chunk(content);
  const chunks: { chunkId: string; cipher: string }[] = [];
  const contentChunks: string[] = [];
  for (const part of parts) {
    const chunkId = await hmacId(keys.chunkMacKey, part);
    const ct = await aesGcmEncrypt(keys.encKey, part);
    chunks.push({ chunkId, cipher: serializeCiphertext(ct) });
    contentChunks.push(chunkId);
  }
  return { chunks, contentChunks, contentTag: await computeContentTag(content, keys) };
}

export async function decodeNote(
  contentChunks: string[],
  fetched: { chunkId: string; cipher: string }[],
  keys: Subkeys,
): Promise<Bytes> {
  const byId = new Map(fetched.map((c) => [c.chunkId, c.cipher]));
  const parts: Bytes[] = [];
  for (const id of contentChunks) {
    const cipher = byId.get(id);
    if (cipher === undefined) throw new Error(`missing chunk ${id}`);
    parts.push(await aesGcmDecrypt(keys.encKey, deserializeCiphertext(cipher)));
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total) as Bytes;
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function encodeAttachment(blob: Bytes, keys: Subkeys): Promise<EncodedAttachment> {
  const ct = await aesGcmEncrypt(keys.encKey, blob);
  const cipher = new Uint8Array(ct.nonce.length + ct.data.length) as Bytes;
  cipher.set(ct.nonce, 0);
  cipher.set(ct.data, ct.nonce.length);
  return { cipher, contentTag: await computeContentTag(blob, keys) };
}

export async function decodeAttachment(cipher: Bytes, keys: Subkeys): Promise<Bytes> {
  const nonce = cipher.slice(0, NONCE_LEN) as Bytes;
  const data = cipher.slice(NONCE_LEN) as Bytes;
  return aesGcmDecrypt(keys.encKey, { nonce, data });
}

export function pathId(path: string, keys: Subkeys): Promise<string> {
  return hmacId(keys.pathMacKey, utf8ToBytes(path));
}

export async function encodePath(path: string, keys: Subkeys): Promise<string> {
  return serializeCiphertext(await aesGcmEncrypt(keys.encKey, utf8ToBytes(path)));
}

export async function decodePath(pathCipher: string, keys: Subkeys): Promise<string> {
  return bytesToUtf8(await aesGcmDecrypt(keys.encKey, deserializeCiphertext(pathCipher)));
}

export function fileType(path: string): FileType {
  if (path.startsWith(".obsidian/")) return "config";
  if (path.endsWith(".md")) return "note";
  return "attachment";
}

/** Insert ` (conflict <stamp>)` before the file extension. */
export function conflictName(path: string, stamp: string): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  if (dot > slash && dot !== -1) {
    return `${path.slice(0, dot)} (conflict ${stamp})${path.slice(dot)}`;
  }
  return `${path} (conflict ${stamp})`;
}
