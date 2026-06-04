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

async function seed(t: ReturnType<typeof convexTest>) {
  const hash = await t.run(() => sha256Hex("k"));
  await t.run(async (ctx) => {
    await ctx.db.insert("workspaces", {
      workspaceId: "ws1",
      syncKeyHash: hash,
      kdfSalt: "s",
      kdfParams: { algo: "pbkdf2", iterations: 600000 },
      dekWrap: "w",
      schemaVersion: 1,
    });
    await ctx.db.insert("counters", { workspaceId: "ws1", version: 0 });
  });
}

const base = {
  workspaceId: "ws1",
  syncKey: "k",
  fileId: "f1",
  pathId: "p1",
  pathCipher: "pc1",
  type: "note" as const,
  contentTag: "t1",
  size: 10,
  mtime: 1000,
  contentChunks: ["c1"],
};

test("first upsert inserts at version 1", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const res = await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 });
  expect(res).toEqual({ status: "ok", version: 1 });
});

test("matching baseVersion updates and bumps the version", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 }); // -> v1
  const res = await t.mutation(api.files.upsertFile, {
    ...base,
    contentTag: "t2",
    contentChunks: ["c2"],
    baseVersion: 1,
  });
  expect(res).toEqual({ status: "ok", version: 2 });
});

test("stale baseVersion is rejected as a conflict without writing", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 }); // -> v1
  const res = await t.mutation(api.files.upsertFile, {
    ...base,
    contentTag: "stale",
    baseVersion: 0, // device thought it was still at v0
  });
  expect(res).toEqual({ status: "conflict", serverVersion: 1 });
  const row = await t.query(api.files.getFileByPath, { workspaceId: "ws1", syncKey: "k", pathId: "p1" });
  expect(row?.contentTag).toBe("t1"); // unchanged
});

test("tombstone marks deleted, bumps version, and clears content", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 }); // -> v1
  const res = await t.mutation(api.files.tombstoneFile, {
    workspaceId: "ws1",
    syncKey: "k",
    fileId: "f1",
    baseVersion: 1,
  });
  expect(res).toEqual({ status: "ok", version: 2 });
  const row = await t.query(api.files.getFileByPath, { workspaceId: "ws1", syncKey: "k", pathId: "p1" });
  expect(row).toBeNull(); // getFileByPath returns only live files
});

test("tombstone of an unknown file reports missing", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const res = await t.mutation(api.files.tombstoneFile, {
    workspaceId: "ws1",
    syncKey: "k",
    fileId: "ghost",
    baseVersion: 0,
  });
  expect(res).toEqual({ status: "missing" });
});

test("listChanges streams rows after a version cursor and reports the next cursor", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, fileId: "f1", pathId: "p1", baseVersion: 0 }); // v1
  await t.mutation(api.files.upsertFile, { ...base, fileId: "f2", pathId: "p2", baseVersion: 0 }); // v2
  const page = await t.query(api.files.listChanges, {
    workspaceId: "ws1",
    syncKey: "k",
    sinceVersion: 0,
    limit: 50,
  });
  expect(page.changes.map((c) => c.fileId)).toEqual(["f1", "f2"]);
  expect(page.nextCursor).toBe(2);
  expect(page.hasMore).toBe(false);
  const tail = await t.query(api.files.listChanges, {
    workspaceId: "ws1",
    syncKey: "k",
    sinceVersion: 2,
  });
  expect(tail.changes).toEqual([]);
  expect(tail.nextCursor).toBe(2);
});

test("listChanges respects the limit and signals more", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, fileId: "f1", pathId: "p1", baseVersion: 0 });
  await t.mutation(api.files.upsertFile, { ...base, fileId: "f2", pathId: "p2", baseVersion: 0 });
  const page = await t.query(api.files.listChanges, {
    workspaceId: "ws1",
    syncKey: "k",
    sinceVersion: 0,
    limit: 1,
  });
  expect(page.changes.map((c) => c.fileId)).toEqual(["f1"]);
  expect(page.nextCursor).toBe(1);
  expect(page.hasMore).toBe(true);
});

test("getFileById returns the row for a known fileId, scoped to the workspace", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.files.upsertFile, { ...base, baseVersion: 0 }); // f1 -> v1
  const row = await t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "k", fileId: "f1" });
  expect(row?.fileId).toBe("f1");
  expect(row?.version).toBe(1);
});

test("getFileById returns null for an unknown fileId", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const row = await t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "k", fileId: "ghost" });
  expect(row).toBeNull();
});

test("getFileById rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await expect(
    t.query(api.files.getFileById, { workspaceId: "ws1", syncKey: "bad", fileId: "f1" }),
  ).rejects.toThrow("Unauthorized");
});
