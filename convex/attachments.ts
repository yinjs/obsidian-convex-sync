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

/** Return a download URL for a stored encrypted blob, or null if it is gone. */
export const getAttachmentUrl = query({
  args: { workspaceId: v.string(), syncKey: v.string(), storageId: v.id("_storage") },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return await ctx.storage.getUrl(args.storageId);
  },
});
