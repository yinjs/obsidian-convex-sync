import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";

/**
 * Insert encrypted chunks, skipping any chunkId already stored
 * (content-addressed dedup). The client batches calls to respect the 16 MiB
 * transaction cap. Returns how many rows were newly inserted.
 */
export const putChunks = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    chunks: v.array(v.object({ chunkId: v.string(), cipher: v.string() })),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    let inserted = 0;
    for (const chunk of args.chunks) {
      const existing = await ctx.db
        .query("chunks")
        .withIndex("by_workspace_chunk", (q) =>
          q.eq("workspaceId", args.workspaceId).eq("chunkId", chunk.chunkId),
        )
        .unique();
      if (existing === null) {
        await ctx.db.insert("chunks", {
          workspaceId: args.workspaceId,
          chunkId: chunk.chunkId,
          cipher: chunk.cipher,
        });
        inserted++;
      }
    }
    return { inserted };
  },
});

/**
 * Fetch ciphers for a list of chunk ids. Unknown ids are silently skipped;
 * the caller reassembles content in `contentChunks` order client-side.
 */
export const getChunks = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    chunkIds: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const out: { chunkId: string; cipher: string }[] = [];
    for (const chunkId of args.chunkIds) {
      const row = await ctx.db
        .query("chunks")
        .withIndex("by_workspace_chunk", (q) =>
          q.eq("workspaceId", args.workspaceId).eq("chunkId", chunkId),
        )
        .unique();
      if (row !== null) {
        out.push({ chunkId: row.chunkId, cipher: row.cipher });
      }
    }
    return out;
  },
});
