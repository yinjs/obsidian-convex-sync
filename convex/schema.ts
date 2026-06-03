import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  smoke: defineTable({ value: v.string() }),
});
