import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { SCHEMA_VERSION, kdfParamsValidator } from "./schema";
import { authenticate } from "./lib/auth";

/**
 * Create the one workspace row and its version counter. Refuses if the
 * workspace already exists — a second device must JOIN (getWorkspaceMeta),
 * never bootstrap, or it would clobber the existing wrapped DEK. This mutation
 * cannot pre-authenticate (no workspace exists yet), so the create-once guard
 * is the only protection; whoever holds the deployment can create it once.
 */
export const bootstrapWorkspace = mutation({
  args: {
    workspaceId: v.string(),
    syncKeyHash: v.string(),
    kdfSalt: v.string(),
    kdfParams: kdfParamsValidator,
    dekWrap: v.string(),
    recoveryWrap: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("workspaces")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .unique();
    if (existing !== null) {
      throw new Error(`Workspace ${args.workspaceId} already exists`);
    }
    await ctx.db.insert("workspaces", { ...args, schemaVersion: SCHEMA_VERSION });
    await ctx.db.insert("counters", { workspaceId: args.workspaceId, version: 0 });
    return { workspaceId: args.workspaceId };
  },
});

/**
 * Authenticated read of the workspace's unlock material, used by a joining
 * device to fetch the wrapped DEK + KDF inputs and unlock locally.
 */
export const getWorkspaceMeta = query({
  args: { workspaceId: v.string(), syncKey: v.string() },
  handler: async (ctx, args) => {
    const w = await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return {
      kdfSalt: w.kdfSalt,
      kdfParams: w.kdfParams,
      dekWrap: w.dekWrap,
      recoveryWrap: w.recoveryWrap ?? null,
      schemaVersion: w.schemaVersion,
    };
  },
});
