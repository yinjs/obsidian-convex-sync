import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/** Bumped when the table shapes change; stored on each workspace so an old
 *  plugin refuses to sync against a newer schema than it understands. */
export const SCHEMA_VERSION = 1;

/** KDF parameters as the client persists them. Validated here so a malformed
 *  write is rejected, without the backend importing any crypto code. */
export const kdfParamsValidator = v.union(
  v.object({
    algo: v.literal("argon2id"),
    iterations: v.number(),
    memoryKiB: v.number(),
    parallelism: v.number(),
  }),
  v.object({
    algo: v.literal("pbkdf2"),
    iterations: v.number(),
  }),
);

export default defineSchema({
  // One row per workspace, created at bootstrap. Holds the public KDF inputs
  // and the wrapped DEK so a second device can join with the passphrase.
  workspaces: defineTable({
    workspaceId: v.string(),
    syncKeyHash: v.string(),
    kdfSalt: v.string(),
    kdfParams: kdfParamsValidator,
    dekWrap: v.string(),
    recoveryWrap: v.optional(v.string()),
    schemaVersion: v.number(),
  }).index("by_workspace", ["workspaceId"]),

  // File metadata. Keyed by stable fileId; path is a mutable attribute.
  files: defineTable({
    workspaceId: v.string(),
    fileId: v.string(),
    pathId: v.string(),
    pathCipher: v.string(),
    type: v.union(v.literal("note"), v.literal("attachment"), v.literal("config")),
    contentTag: v.string(),
    size: v.number(),
    mtime: v.number(),
    deleted: v.boolean(),
    version: v.number(),
    baseVersion: v.number(),
    contentChunks: v.optional(v.array(v.string())),
    storageId: v.optional(v.id("_storage")),
  })
    .index("by_workspace_version", ["workspaceId", "version"])
    .index("by_workspace_path", ["workspaceId", "pathId"])
    .index("by_workspace_file", ["workspaceId", "fileId"]),

  // Deduplicated encrypted content chunks, addressed by opaque chunkId.
  chunks: defineTable({
    workspaceId: v.string(),
    chunkId: v.string(),
    cipher: v.string(),
  }).index("by_workspace_chunk", ["workspaceId", "chunkId"]),

  // Monotonic per-workspace version source. Bumped inside each write mutation.
  counters: defineTable({
    workspaceId: v.string(),
    version: v.number(),
  }).index("by_workspace", ["workspaceId"]),
});
