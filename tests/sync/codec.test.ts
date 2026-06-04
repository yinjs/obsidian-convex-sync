import { describe, it, expect } from "vitest";
import { makeKeys } from "./fakes";
import {
  encodeNote, decodeNote, encodeAttachment, decodeAttachment,
  pathId, encodePath, decodePath, computeContentTag, fileType, conflictName,
} from "../../src/sync/codec";
import type { Bytes } from "../../src/crypto";
import { utf8ToBytes } from "../../src/crypto";

const bytes = (s: string) => utf8ToBytes(s);

describe("codec", () => {
  it("encodeNote then decodeNote round-trips", async () => {
    const keys = await makeKeys();
    const content = bytes("hello note body");
    const enc = await encodeNote(content, keys);
    const decoded = await decodeNote(enc.contentChunks, enc.chunks, keys);
    expect([...decoded]).toEqual([...content]);
  });

  it("encodeNote produces matching chunkIds and contentChunks order", async () => {
    const keys = await makeKeys();
    const enc = await encodeNote(bytes("abc"), keys);
    expect(enc.chunks.map((c) => c.chunkId)).toEqual(enc.contentChunks);
    expect(enc.contentTag).toMatch(/^[0-9a-f]{64}$/);
  });

  it("identical content yields identical chunkIds and tag (deterministic ids)", async () => {
    const keys = await makeKeys();
    const a = await encodeNote(bytes("same"), keys);
    const b = await encodeNote(bytes("same"), keys);
    expect(a.contentChunks).toEqual(b.contentChunks);
    expect(a.contentTag).toBe(b.contentTag);
  });

  it("encodeAttachment then decodeAttachment round-trips raw bytes (no base64 bloat)", async () => {
    const keys = await makeKeys();
    const blob = new Uint8Array([0, 1, 2, 255, 128]) as Bytes;
    const enc = await encodeAttachment(blob, keys);
    expect(enc.contentTag).toMatch(/^[0-9a-f]{64}$/);
    const decoded = await decodeAttachment(enc.cipher, keys);
    expect([...decoded]).toEqual([...blob]);
  });

  it("pathId is deterministic; encodePath/decodePath round-trips", async () => {
    const keys = await makeKeys();
    const id1 = await pathId("folder/note.md", keys);
    const id2 = await pathId("folder/note.md", keys);
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^[0-9a-f]{64}$/);
    const cipher = await encodePath("folder/note.md", keys);
    expect(await decodePath(cipher, keys)).toBe("folder/note.md");
  });

  it("computeContentTag changes when content changes", async () => {
    const keys = await makeKeys();
    expect(await computeContentTag(bytes("a"), keys)).not.toBe(await computeContentTag(bytes("b"), keys));
  });

  it("fileType classifies by path", () => {
    expect(fileType("a.md")).toBe("note");
    expect(fileType("img.png")).toBe("attachment");
    expect(fileType(".obsidian/app.json")).toBe("config");
  });

  it("conflictName inserts before the extension", () => {
    expect(conflictName("folder/note.md", "2026-06-04 12-00-00")).toBe("folder/note (conflict 2026-06-04 12-00-00).md");
    expect(conflictName("noext", "S")).toBe("noext (conflict S)");
  });
});
