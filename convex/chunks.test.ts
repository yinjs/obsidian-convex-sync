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

test("putChunks inserts new chunks and dedupes repeats", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const first = await t.mutation(api.chunks.putChunks, {
    workspaceId: "ws1",
    syncKey: "k",
    chunks: [
      { chunkId: "a", cipher: "CA" },
      { chunkId: "b", cipher: "CB" },
    ],
  });
  expect(first.inserted).toBe(2);
  const second = await t.mutation(api.chunks.putChunks, {
    workspaceId: "ws1",
    syncKey: "k",
    chunks: [
      { chunkId: "a", cipher: "CA" },
      { chunkId: "c", cipher: "CC" },
    ],
  });
  expect(second.inserted).toBe(1); // only "c" is new
});

test("getChunks returns ciphers for known ids and skips unknown ids", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await t.mutation(api.chunks.putChunks, {
    workspaceId: "ws1",
    syncKey: "k",
    chunks: [{ chunkId: "a", cipher: "CA" }],
  });
  const got = await t.query(api.chunks.getChunks, {
    workspaceId: "ws1",
    syncKey: "k",
    chunkIds: ["a", "missing"],
  });
  expect(got).toEqual([{ chunkId: "a", cipher: "CA" }]);
});

test("putChunks rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await expect(
    t.mutation(api.chunks.putChunks, { workspaceId: "ws1", syncKey: "bad", chunks: [] }),
  ).rejects.toThrow("Unauthorized");
});
