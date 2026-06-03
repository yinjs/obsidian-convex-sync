// @vitest-environment edge-runtime
import { convexTest } from "convex-test";
import { test, expect } from "vitest";
import schema from "./schema";

const modules = import.meta.glob("./**/!(*.*.*)*.*s");

test("workspaces row round-trips with an argon2id kdfParams", async () => {
  const t = convexTest(schema, modules);
  const id = await t.run((ctx) =>
    ctx.db.insert("workspaces", {
      workspaceId: "ws1",
      syncKeyHash: "deadbeef",
      kdfSalt: "c2FsdA==",
      kdfParams: { algo: "argon2id", iterations: 3, memoryKiB: 65536, parallelism: 1 },
      dekWrap: "wrap",
      schemaVersion: 1,
    }),
  );
  const row = await t.run((ctx) => ctx.db.get(id));
  expect(row?.workspaceId).toBe("ws1");
  expect(row?.kdfParams.algo).toBe("argon2id");
});

test("files row supports optional contentChunks and storageId", async () => {
  const t = convexTest(schema, modules);
  const id = await t.run((ctx) =>
    ctx.db.insert("files", {
      workspaceId: "ws1",
      fileId: "f1",
      pathId: "p1",
      pathCipher: "pc1",
      type: "note",
      contentTag: "t1",
      size: 12,
      mtime: 1000,
      deleted: false,
      version: 1,
      baseVersion: 0,
      contentChunks: ["c1", "c2"],
    }),
  );
  const row = await t.run((ctx) => ctx.db.get(id));
  expect(row?.contentChunks).toEqual(["c1", "c2"]);
  expect(row?.storageId).toBeUndefined();
});
