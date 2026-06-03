// @vitest-environment edge-runtime
import { convexTest } from "convex-test";
import { test, expect } from "vitest";
import schema from "../schema";
import { nextVersion } from "./version";

const modules = import.meta.glob("../**/!(*.*.*)*.*s");

test("nextVersion increments from the counter and persists", async () => {
  const t = convexTest(schema, modules);
  await t.run((ctx) => ctx.db.insert("counters", { workspaceId: "ws1", version: 0 }));
  const v1 = await t.run((ctx) => nextVersion(ctx.db, "ws1"));
  const v2 = await t.run((ctx) => nextVersion(ctx.db, "ws1"));
  expect(v1).toBe(1);
  expect(v2).toBe(2);
});

test("nextVersion throws if the workspace has no counter", async () => {
  const t = convexTest(schema, modules);
  await expect(t.run((ctx) => nextVersion(ctx.db, "missing"))).rejects.toThrow();
});
