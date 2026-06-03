// @vitest-environment edge-runtime
import { convexTest } from "convex-test";
import { test, expect } from "vitest";
import schema from "./schema";
import { api } from "./_generated/api";

const modules = import.meta.glob("./**/!(*.*.*)*.*s");

async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const ARGON: { algo: "argon2id"; iterations: number; memoryKiB: number; parallelism: number } = {
  algo: "argon2id",
  iterations: 3,
  memoryKiB: 65536,
  parallelism: 1,
};

async function bootstrapArgs(t: ReturnType<typeof convexTest>) {
  return {
    workspaceId: "ws1",
    syncKey: "the-sync-key",
    syncKeyHash: await t.run(() => sha256Hex("the-sync-key")),
    kdfSalt: "c2FsdA==",
    kdfParams: ARGON,
    dekWrap: "wrapped-dek",
    recoveryWrap: "wrapped-recovery",
  };
}

test("bootstrap creates the workspace and a zeroed counter", async () => {
  const t = convexTest(schema, modules);
  const args = await bootstrapArgs(t);
  const { syncKey, ...rest } = args;
  await t.mutation(api.workspaces.bootstrapWorkspace, rest);
  const counter = await t.run((ctx) =>
    ctx.db.query("counters").withIndex("by_workspace", (q) => q.eq("workspaceId", "ws1")).unique(),
  );
  expect(counter?.version).toBe(0);
});

test("bootstrap refuses to clobber an existing workspace", async () => {
  const t = convexTest(schema, modules);
  const args = await bootstrapArgs(t);
  const { syncKey, ...rest } = args;
  await t.mutation(api.workspaces.bootstrapWorkspace, rest);
  await expect(t.mutation(api.workspaces.bootstrapWorkspace, rest)).rejects.toThrow("already exists");
});

test("getWorkspaceMeta returns the wrapped DEK for an authenticated joiner", async () => {
  const t = convexTest(schema, modules);
  const args = await bootstrapArgs(t);
  const { syncKey, ...rest } = args;
  await t.mutation(api.workspaces.bootstrapWorkspace, rest);
  const meta = await t.query(api.workspaces.getWorkspaceMeta, { workspaceId: "ws1", syncKey });
  expect(meta.dekWrap).toBe("wrapped-dek");
  expect(meta.recoveryWrap).toBe("wrapped-recovery");
  expect(meta.kdfParams.algo).toBe("argon2id");
  expect(meta.schemaVersion).toBe(1);
});

test("getWorkspaceMeta rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  const args = await bootstrapArgs(t);
  const { syncKey, ...rest } = args;
  await t.mutation(api.workspaces.bootstrapWorkspace, rest);
  await expect(
    t.query(api.workspaces.getWorkspaceMeta, { workspaceId: "ws1", syncKey: "wrong" }),
  ).rejects.toThrow("Unauthorized");
});
