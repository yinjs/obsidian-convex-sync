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

test("generateUploadUrl returns a string URL for an authenticated caller", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const url = await t.mutation(api.attachments.generateUploadUrl, {
    workspaceId: "ws1",
    syncKey: "k",
  });
  expect(typeof url).toBe("string");
  expect(url.length).toBeGreaterThan(0);
});

test("generateUploadUrl rejects a wrong sync key", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  await expect(
    t.mutation(api.attachments.generateUploadUrl, { workspaceId: "ws1", syncKey: "bad" }),
  ).rejects.toThrow("Unauthorized");
});

test("getAttachmentUrl returns a URL for a stored blob", async () => {
  const t = convexTest(schema, modules);
  await seed(t);
  const storageId = await t.run(async (ctx) =>
    ctx.storage.store(new Blob([new Uint8Array([1, 2, 3])])),
  );
  const url = await t.query(api.attachments.getAttachmentUrl, {
    workspaceId: "ws1",
    syncKey: "k",
    storageId,
  });
  expect(typeof url).toBe("string");
});
