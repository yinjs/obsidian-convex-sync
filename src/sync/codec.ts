// src/sync/codec.ts (minimal for now; expanded in Task 4)
import type { FileType } from "./ports";
export function fileType(path: string): FileType {
  if (path.startsWith(".obsidian/")) return "config";
  if (path.endsWith(".md")) return "note";
  return "attachment";
}
