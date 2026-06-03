import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";
import { nextVersion } from "./lib/version";

/**
 * Create or update a file. Conflict check + version bump + write happen in one
 * mutation, so Convex's serializable transactions make stale-write rejection
 * correct: if the stored version for this fileId differs from the caller's
 * baseVersion, nothing is written and the caller makes a local conflict copy.
 */
export const upsertFile = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    fileId: v.string(),
    pathId: v.string(),
    pathCipher: v.string(),
    type: v.union(v.literal("note"), v.literal("attachment"), v.literal("config")),
    contentTag: v.string(),
    size: v.number(),
    mtime: v.number(),
    baseVersion: v.number(),
    contentChunks: v.optional(v.array(v.string())),
    storageId: v.optional(v.id("_storage")),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const existing = await ctx.db
      .query("files")
      .withIndex("by_workspace_file", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("fileId", args.fileId),
      )
      .unique();
    if (existing !== null && existing.version !== args.baseVersion) {
      return { status: "conflict" as const, serverVersion: existing.version };
    }
    const version = await nextVersion(ctx.db, args.workspaceId);
    const row = {
      workspaceId: args.workspaceId,
      fileId: args.fileId,
      pathId: args.pathId,
      pathCipher: args.pathCipher,
      type: args.type,
      contentTag: args.contentTag,
      size: args.size,
      mtime: args.mtime,
      deleted: false,
      version,
      baseVersion: args.baseVersion,
      contentChunks: args.contentChunks,
      storageId: args.storageId,
    };
    if (existing === null) {
      await ctx.db.insert("files", row);
    } else {
      await ctx.db.replace(existing._id, row);
    }
    return { status: "ok" as const, version };
  },
});

/**
 * Mark a file deleted (tombstone). Same conflict-check + version-bump path as
 * upsert. The row is retained as a tombstone so other devices see the delete
 * in the feed; content references are cleared (orphaned chunks/blobs are GC'd
 * later — deferred).
 */
export const tombstoneFile = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    fileId: v.string(),
    baseVersion: v.number(),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const existing = await ctx.db
      .query("files")
      .withIndex("by_workspace_file", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("fileId", args.fileId),
      )
      .unique();
    if (existing === null) {
      return { status: "missing" as const };
    }
    if (existing.version !== args.baseVersion) {
      return { status: "conflict" as const, serverVersion: existing.version };
    }
    const version = await nextVersion(ctx.db, args.workspaceId);
    await ctx.db.patch(existing._id, {
      deleted: true,
      version,
      baseVersion: args.baseVersion,
      contentTag: "",
      size: 0,
      contentChunks: undefined,
      storageId: undefined,
    });
    return { status: "ok" as const, version };
  },
});

/**
 * Reactive change feed via a value cursor: all rows with version > sinceVersion,
 * ascending, capped at `limit`. Returns the rows, the next cursor (max version
 * seen, or sinceVersion if empty), and whether a full page was returned.
 * Restart- and reconnect-safe because the cursor is a real version number.
 */
export const listChanges = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    sinceVersion: v.number(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const limit = args.limit ?? 50;
    const changes = await ctx.db
      .query("files")
      .withIndex("by_workspace_version", (q) =>
        q.eq("workspaceId", args.workspaceId).gt("version", args.sinceVersion),
      )
      .order("asc")
      .take(limit);
    const nextCursor =
      changes.length > 0 ? changes[changes.length - 1]!.version : args.sinceVersion;
    return { changes, nextCursor, hasMore: changes.length === limit };
  },
});

/**
 * Resolve a path (via its HMAC pathId) to its live file row, or null. A path
 * may have a tombstone plus a later live file sharing the same pathId, so we
 * return the first non-deleted match rather than using `.unique()`.
 */
export const getFileByPath = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    pathId: v.string(),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const rows = await ctx.db
      .query("files")
      .withIndex("by_workspace_path", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("pathId", args.pathId),
      )
      .collect();
    return rows.find((r) => !r.deleted) ?? null;
  },
});
