import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const put = mutation({
  args: { value: v.string() },
  handler: async (ctx, args) => {
    await ctx.db.insert("smoke", { value: args.value });
  },
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("smoke").collect();
  },
});
