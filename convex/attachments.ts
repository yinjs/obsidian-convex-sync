import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";

/**
 * Issue a one-time upload URL for an encrypted attachment blob. Must be a
 * mutation (Convex requirement). The client PUTs the ciphertext to this URL,
 * then records the returned storageId on a file via upsertFile.
 */
export const generateUploadUrl = mutation({
  args: { workspaceId: v.string(), syncKey: v.string() },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return await ctx.storage.generateUploadUrl();
  },
});

/**
 * Return a download URL for a stored encrypted blob, but only if the blob is
 * referenced by a (live or tombstoned) file in the authenticated workspace.
 * Returns null for an unknown blob or one that does not belong to this
 * workspace — no cross-workspace storage dereference.
 */
export const getAttachmentUrl = query({
  args: { workspaceId: v.string(), syncKey: v.string(), storageId: v.id("_storage") },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const owning = await ctx.db
      .query("files")
      .withIndex("by_workspace_storage", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("storageId", args.storageId),
      )
      .first();
    if (owning === null) {
      return null;
    }
    return await ctx.storage.getUrl(args.storageId);
  },
});
