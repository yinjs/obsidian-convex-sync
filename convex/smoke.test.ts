// @vitest-environment edge-runtime
import { convexTest } from "convex-test";
import { test, expect } from "vitest";
import schema from "./schema";
import { api } from "./_generated/api";

const modules = import.meta.glob("./**/!(*.*.*)*.*s");

test("smoke: mutation writes, query reads", async () => {
  const t = convexTest(schema, modules);
  await t.mutation(api.smoke.put, { value: "hello" });
  expect(await t.query(api.smoke.list)).toMatchObject([{ value: "hello" }]);
});

test("smoke: SHA-256 digest is available in the Convex runtime", async () => {
  const t = convexTest(schema, modules);
  const hex = await t.run(async () => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("x"));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  });
  // Confirms crypto.subtle.digest is available server-side and returns a real
  // 256-bit hash (auth depends on this). Shape assertion, not a memorized
  // constant, so a recall error can't masquerade as "crypto unavailable".
  expect(hex).toMatch(/^[0-9a-f]{64}$/);
});
