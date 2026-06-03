// @vitest-environment edge-runtime
import { convexTest } from "convex-test";
import { test, expect } from "vitest";
import schema from "../schema";
import { authenticate } from "./auth";

const modules = import.meta.glob("../**/!(*.*.*)*.*s");

const KEY = "correct-key";

async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function seedWorkspace(t: ReturnType<typeof convexTest>) {
  const hash = await t.run(() => sha256Hex(KEY));
  await t.run((ctx) =>
    ctx.db.insert("workspaces", {
      workspaceId: "ws1",
      syncKeyHash: hash,
      kdfSalt: "s",
      kdfParams: { algo: "pbkdf2", iterations: 600000 },
      dekWrap: "w",
      schemaVersion: 1,
    }),
  );
}

test("accepts the correct sync key and returns the workspace", async () => {
  const t = convexTest(schema, modules);
  await seedWorkspace(t);
  const ws = await t.run((ctx) => authenticate(ctx.db, "ws1", KEY));
  expect(ws.workspaceId).toBe("ws1");
});

test("rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  await seedWorkspace(t);
  await expect(t.run((ctx) => authenticate(ctx.db, "ws1", "wrong"))).rejects.toThrow("Unauthorized");
});

test("rejects an unknown workspace", async () => {
  const t = convexTest(schema, modules);
  await seedWorkspace(t);
  await expect(t.run((ctx) => authenticate(ctx.db, "nope", KEY))).rejects.toThrow("Unauthorized");
});
