# Convex Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Convex backend (schema + queries + mutations) that stores one workspace's encrypted vault — opaque chunks, file metadata, attachments — authenticated by a sync key, with atomic versioned writes and a reactive change feed.

**Architecture:** A single Convex deployment per user holds four tables (`workspaces`, `files`, `chunks`, `counters`). The backend is **crypto-agnostic**: it stores opaque strings (ciphertext, HMAC ids, wrapped keys, KDF params) and never imports the crypto-core module. Every request carries `workspaceId` + raw `syncKey`; the server hashes the key with web-standard `crypto.subtle.digest` (available in the Convex runtime) and constant-time-compares it to the stored `syncKeyHash`. Writes that mutate a file run version-bump + conflict-check + write inside one mutation, so Convex's serializable transactions reject stale writes for free. The change feed is a reactive **value-cursor** query (`version > sinceVersion`), restart- and reconnect-safe.

**Tech Stack:** Convex (queries/mutations/file storage), `convex-test` (community mock backend) running under vitest's `edge-runtime` environment, TypeScript 6, vitest 1.6.

---

## Background for the implementer

You are building the server side of an end-to-end-encrypted Obsidian sync plugin. The client (crypto-core, already built in `src/crypto/`) does all encryption; the server only ever sees opaque blobs and ids. **Do not import anything from `src/`** in `convex/` — the backend must stay crypto-agnostic. The client generates all random values (fileId, nonces) so the Convex runtime stays deterministic.

Key data model facts (from `docs/superpowers/specs/2026-06-03-obsidian-convex-sync-design.md`):

- Files are keyed by a **stable random `fileId`**; the path is a *mutable attribute*. A rename is one metadata update.
- `pathId = HMAC(path)` is a deterministic lookup key; `pathCipher` is the encrypted path. The server learns neither the path nor whether two ids map to related paths.
- `version` is monotonic **per workspace** (from the `counters` table). It is the change-feed cursor and the conflict-detection key.
- `baseVersion` is the version a write was based on. If the server's current version for that file ≠ `baseVersion`, the write is a **conflict** (the client makes a conflict copy locally).
- Note content is stored as an ordered list of opaque `chunkId`s in `files.contentChunks`, with the ciphertext in the `chunks` table (deduped by `chunkId`). Attachments are a single encrypted blob in Convex file storage, referenced by `storageId`.

### Convex specifics you must know

- `crypto.subtle.digest("SHA-256", …)` **is** available in Convex queries and mutations (the runtime exposes web-standard crypto). `Math.random`/`crypto.getRandomValues` are seeded and `Date.now()` is frozen for determinism — that's why the client supplies all randomness.
- Validators come from `import { v } from "convex/values"`. `v.id("_storage")` is the type of a file-storage id.
- Indexes are declared with `.index("name", ["field1", "field2"])` and queried with `.withIndex("name", q => q.eq(...).gt(...))`.
- `.unique()` returns the single match or `null`, and **throws if more than one row matches** — only use it on truly unique index ranges.
- A reactive feed uses a **value cursor**, not `.paginate()`: `withIndex("by_workspace_version", q => q.eq("workspaceId", w).gt("version", sinceVersion)).order("asc").take(N)`, returning the rows plus `max(version)` as the next cursor. This survives reconnect/restart and stays reactive. (`.paginate()` with opaque cursors is reserved for cold-start bulk reads, which this plan does not implement.)
- `ctx.storage.generateUploadUrl()` must be called from a **mutation**; `ctx.storage.getUrl(id)` works in a query.
- Document cap is 1 MiB; a transaction may write ≤ 16 MiB / 32k docs. The chunker keeps chunks well under 1 MiB; the client batches `putChunks` to respect the txn cap.

### Codegen decision (resolved during Task 0)

`convex@1.40.0 codegen` requires a configured `CONVEX_DEPLOYMENT` even for `--dry-run`, so it cannot run offline. Rather than introduce a one-time interactive Convex login (and a live deployment dependency the mock tests don't need), `convex/_generated/` is **hand-maintained from Convex's standard templates** and committed. This keeps the whole test toolchain offline/CI-friendly (`convex-test` is a pure in-memory mock — it never talks to a deployment).

What this means per task:
- `convex/_generated/server.ts` — fixed boilerplate, never changes.
- `convex/_generated/dataModel.ts` — fixed boilerplate; it derives `DataModel` from `typeof schema`, so it **automatically** reflects schema changes. Do not edit it when the schema changes.
- `convex/_generated/api.ts` — the **only** per-module file. When you add a function module (e.g. `convex/files.ts`), add two lines: `import type * as files from "../files.js";` and a `"files": typeof files,` entry in the `ApiFromModules<{...}>` map. The runtime `api` is `anyApi as any`, so a missing entry only loses *type* checking on `api.files.*` (tests still run) — keep it in sync so types stay honest.

Wherever a later task says "regenerate types", that means **edit `convex/_generated/api.ts` by hand** as above — do NOT run `npx convex codegen` (it will error on the missing deployment).

### Testing approach

`convex-test` is a mock backend that runs your real function code in vitest. It is an **API-shape smoke test**, not proof of production-runtime behavior — the real evidence that `crypto.subtle` works server-side is Convex's Cloudflare-Workers-equivalent runtime docs. Treat green convex-test runs as "the wiring is correct," not "production is guaranteed."

Each convex test file:
- starts with the pragma `// @vitest-environment edge-runtime` (crypto-core tests stay on `node`),
- builds the module map with `const modules = import.meta.glob("./**/!(*.*.*)*.*s");` and passes it as the second arg to `convexTest(schema, modules)`,
- imports `schema` (default export) from `./schema` and `api` from `./_generated/api`.

---

## File Structure

- `convex/schema.ts` — table definitions, indexes, `SCHEMA_VERSION`, shared `kdfParamsValidator`.
- `convex/lib/auth.ts` — `authenticate(db, workspaceId, syncKey)`: load workspace, SHA-256 the key, constant-time compare, return the workspace doc or throw `"Unauthorized"`.
- `convex/lib/version.ts` — `nextVersion(db, workspaceId)`: internal helper that atomically reserves the next per-workspace version. **Not** a Convex function.
- `convex/workspaces.ts` — `bootstrapWorkspace` mutation (create-once guard) + `getWorkspaceMeta` query (authenticated; returns the wrapped DEK for a joining device).
- `convex/chunks.ts` — `putChunks` mutation (dedup insert) + `getChunks` query (fetch ciphers by id).
- `convex/files.ts` — `upsertFile` mutation (conflict check + version bump), `tombstoneFile` mutation, `listChanges` query (value-cursor feed), `getFileByPath` query.
- `convex/attachments.ts` — `generateUploadUrl` mutation + `getAttachmentUrl` query.

---

## Task 0: Verified Convex scaffold

Stand up Convex + convex-test and prove the toolchain runs *before* writing any real function. This is a verified scaffold: it ends with a green smoke test, not a placeholder.

**Files:**
- Modify: `package.json` (add deps + scripts)
- Modify: `vitest.config.ts`
- Modify: `tsconfig.json`
- Create: `convex/schema.ts` (minimal, replaced in Task 1)
- Create: `convex/smoke.ts`
- Create: `convex/smoke.test.ts`
- Generated: `convex/_generated/**` (via `npx convex codegen`)

- [ ] **Step 1: Install Convex + test deps**

Run:
```bash
npm install convex
npm install --save-dev convex-test @edge-runtime/vm
```
Expected: installs succeed; `convex`, `convex-test`, `@edge-runtime/vm` appear in `package.json`.

- [ ] **Step 2: Broaden vitest include and keep node default**

Replace `vitest.config.ts` with:
```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Default environment is node (crypto-core tests). Convex test files
    // opt into edge-runtime per-file via a `// @vitest-environment` pragma.
    environment: "node",
    include: ["tests/**/*.test.ts", "convex/**/*.test.ts"],
  },
});
```

- [ ] **Step 3: Add `convex` to the typecheck include**

In `tsconfig.json`, change the `include` line to:
```json
  "include": ["src", "tests", "convex"]
```

- [ ] **Step 4: Write a minimal schema**

Create `convex/schema.ts`:
```typescript
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  smoke: defineTable({ value: v.string() }),
});
```

- [ ] **Step 5: Write a trivial mutation + query**

Create `convex/smoke.ts`:
```typescript
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
```

- [ ] **Step 6: Create `convex/_generated/`**

`npx convex codegen` cannot run offline in this Convex version (it errors `No CONVEX_DEPLOYMENT set`). Per the "Codegen decision" section, hand-write the three standard generated files instead, committed to the repo:
- `convex/_generated/server.ts` — copy Convex's standard server template (re-exports `query`, `mutation`, `action`, `internalQuery`, etc. and the `Database*`/ctx types via `convex/server` generics).
- `convex/_generated/dataModel.ts` — standard template that defines `DataModel = DataModelFromSchemaDefinition<typeof schema>` plus `Doc`/`Id`/`TableNames`. Imports `schema from "../schema.js"`; reflects schema changes automatically.
- `convex/_generated/api.ts` — standard template with `import type * as smoke from "../smoke.js";` and `"smoke": typeof smoke,` in the `ApiFromModules<{...}>` map; `api`/`internal` are `anyApi as any`.

(The templates live in `node_modules/convex/dist/esm/cli/codegen_templates/` if you need an exact reference.) Add `"vite/client"` to `tsconfig.json`'s `types` array so `import.meta.glob` typechecks.

- [ ] **Step 7: Write the smoke test**

Create `convex/smoke.test.ts`:
```typescript
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
```

- [ ] **Step 8: Run the smoke test (must pass)**

Run: `npx vitest run convex/smoke.test.ts`
Expected: 2 passed. This proves convex-test + edge-runtime + glob loading + server-side `crypto.subtle` all work.

**Contingency if this fails on a `convex-test` import / ESM error** (not on an assertion): add an inline-deps hint to `vitest.config.ts` so Vitest transforms the package:
```typescript
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "convex/**/*.test.ts"],
    server: { deps: { inline: ["convex-test"] } },
  },
});
```
Re-run. Only add this if the bare config errors on importing `convex-test`.

- [ ] **Step 9: Confirm the full suite and typecheck still pass**

Run: `npm test && npm run typecheck`
Expected: all crypto-core tests + the 2 smoke tests pass; `tsc --noEmit` reports no errors.

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json vitest.config.ts tsconfig.json convex/
git commit -m "feat(convex): verified scaffold — convex-test on edge-runtime, server crypto.subtle confirmed"
```

---

## Task 1: Schema

Define the four real tables, their indexes, the schema version, and the shared KDF-params validator. This replaces the minimal smoke schema.

**Files:**
- Modify: `convex/schema.ts`
- Delete: `convex/smoke.ts`, `convex/smoke.test.ts`
- Test: `convex/schema.test.ts`

- [ ] **Step 1: Write the schema test**

Create `convex/schema.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/schema.test.ts`
Expected: FAIL — the `smoke` schema has no `workspaces`/`files` tables.

- [ ] **Step 3: Write the real schema**

Replace `convex/schema.ts`:
```typescript
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/** Bumped when the table shapes change; stored on each workspace so an old
 *  plugin refuses to sync against a newer schema than it understands. */
export const SCHEMA_VERSION = 1;

/** KDF parameters as the client persists them. Validated here so a malformed
 *  write is rejected, without the backend importing any crypto code. */
export const kdfParamsValidator = v.union(
  v.object({
    algo: v.literal("argon2id"),
    iterations: v.number(),
    memoryKiB: v.number(),
    parallelism: v.number(),
  }),
  v.object({
    algo: v.literal("pbkdf2"),
    iterations: v.number(),
  }),
);

export default defineSchema({
  // One row per workspace, created at bootstrap. Holds the public KDF inputs
  // and the wrapped DEK so a second device can join with the passphrase.
  workspaces: defineTable({
    workspaceId: v.string(),
    syncKeyHash: v.string(),
    kdfSalt: v.string(),
    kdfParams: kdfParamsValidator,
    dekWrap: v.string(),
    recoveryWrap: v.optional(v.string()),
    schemaVersion: v.number(),
  }).index("by_workspace", ["workspaceId"]),

  // File metadata. Keyed by stable fileId; path is a mutable attribute.
  files: defineTable({
    workspaceId: v.string(),
    fileId: v.string(),
    pathId: v.string(),
    pathCipher: v.string(),
    type: v.union(v.literal("note"), v.literal("attachment"), v.literal("config")),
    contentTag: v.string(),
    size: v.number(),
    mtime: v.number(),
    deleted: v.boolean(),
    version: v.number(),
    baseVersion: v.number(),
    contentChunks: v.optional(v.array(v.string())),
    storageId: v.optional(v.id("_storage")),
  })
    .index("by_workspace_version", ["workspaceId", "version"])
    .index("by_workspace_path", ["workspaceId", "pathId"])
    .index("by_workspace_file", ["workspaceId", "fileId"]),

  // Deduplicated encrypted content chunks, addressed by opaque chunkId.
  chunks: defineTable({
    workspaceId: v.string(),
    chunkId: v.string(),
    cipher: v.string(),
  }).index("by_workspace_chunk", ["workspaceId", "chunkId"]),

  // Monotonic per-workspace version source. Bumped inside each write mutation.
  counters: defineTable({
    workspaceId: v.string(),
    version: v.number(),
  }).index("by_workspace", ["workspaceId"]),
});
```

- [ ] **Step 4: Remove the smoke files and regenerate types**

Run:
```bash
git rm convex/smoke.ts convex/smoke.test.ts
```
Then hand-edit `convex/_generated/api.ts`: remove the `import type * as smoke ...` line and the `"smoke": typeof smoke,` map entry (leaving `ApiFromModules<{}>`). Do NOT touch `dataModel.ts` — it derives `DataModel` from `typeof schema` and reflects the new tables automatically.
Expected: smoke files gone; `api.ts` no longer references smoke.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run convex/schema.test.ts`
Expected: 2 passed.

- [ ] **Step 6: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add convex/ tsconfig.json
git commit -m "feat(convex): workspaces/files/chunks/counters schema with indexes"
```

---

## Task 2: Auth helper

`authenticate` loads the workspace, hashes the presented sync key, and constant-time-compares it to the stored verifier. Every query/mutation calls it first. Encryption is the real wall (a stolen sync key still can't decrypt anything); this is cheap defense-in-depth and scopes all access to one workspace.

**Files:**
- Create: `convex/lib/auth.ts`
- Test: `convex/lib/auth.test.ts`

- [ ] **Step 1: Write the auth test**

Create `convex/lib/auth.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/lib/auth.test.ts`
Expected: FAIL — `./auth` does not exist.

- [ ] **Step 3: Write the auth helper**

Create `convex/lib/auth.ts`:
```typescript
import { DatabaseReader } from "../_generated/server";
import { Doc } from "../_generated/dataModel";

/** Constant-time comparison of two equal-length hex strings. Returns false
 *  immediately on length mismatch (length is not secret here). */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Authenticate a request against a workspace's sync-key verifier and return
 * the workspace document. Throws "Unauthorized" for both an unknown workspace
 * and a bad key (no oracle distinguishing the two). Works with a query or a
 * mutation ctx — pass `ctx.db`. DatabaseWriter extends DatabaseReader.
 */
export async function authenticate(
  db: DatabaseReader,
  workspaceId: string,
  syncKey: string,
): Promise<Doc<"workspaces">> {
  const workspace = await db
    .query("workspaces")
    .withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId))
    .unique();
  if (workspace === null) {
    throw new Error("Unauthorized");
  }
  const presentedHash = await sha256Hex(syncKey);
  if (!timingSafeEqualHex(presentedHash, workspace.syncKeyHash)) {
    throw new Error("Unauthorized");
  }
  return workspace;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run convex/lib/auth.test.ts`
Expected: 3 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add convex/lib/auth.ts convex/lib/auth.test.ts
git commit -m "feat(convex): sync-key authentication with constant-time verifier compare"
```

---

## Task 3: Version helper

`nextVersion` atomically reserves the next per-workspace version inside a mutation. Convex serializes conflicting transactions, so two concurrent writers can never receive the same number — that property is what makes stale-write rejection in Task 5 correct.

**Files:**
- Create: `convex/lib/version.ts`
- Test: `convex/lib/version.test.ts`

- [ ] **Step 1: Write the version test**

Create `convex/lib/version.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/lib/version.test.ts`
Expected: FAIL — `./version` does not exist.

- [ ] **Step 3: Write the version helper**

Create `convex/lib/version.ts`:
```typescript
import { DatabaseWriter } from "../_generated/server";

/**
 * Reserve and return the next monotonic version for a workspace. MUST be
 * called inside a mutation. Relies on Convex's serializable transactions:
 * two concurrent callers cannot read the same counter value and both commit,
 * so versions are unique and gap-free per workspace.
 */
export async function nextVersion(db: DatabaseWriter, workspaceId: string): Promise<number> {
  const counter = await db
    .query("counters")
    .withIndex("by_workspace", (q) => q.eq("workspaceId", workspaceId))
    .unique();
  if (counter === null) {
    throw new Error(`No counter for workspace ${workspaceId}`);
  }
  const version = counter.version + 1;
  await db.patch(counter._id, { version });
  return version;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run convex/lib/version.test.ts`
Expected: 2 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add convex/lib/version.ts convex/lib/version.test.ts
git commit -m "feat(convex): per-workspace monotonic version helper"
```

---

## Task 4: Workspaces — bootstrap and meta

`bootstrapWorkspace` creates the single workspace row + its counter, refusing to clobber an existing workspace. `getWorkspaceMeta` is the authenticated path a *second* device uses to fetch the wrapped DEK so it can unlock locally (a joining device must NOT bootstrap).

**Files:**
- Create: `convex/workspaces.ts`
- Test: `convex/workspaces.test.ts`

- [ ] **Step 1: Write the workspaces test**

Create `convex/workspaces.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/workspaces.test.ts`
Expected: FAIL — `api.workspaces` is undefined.

- [ ] **Step 3: Write the workspaces functions**

Create `convex/workspaces.ts`:
```typescript
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { SCHEMA_VERSION, kdfParamsValidator } from "./schema";
import { authenticate } from "./lib/auth";

/**
 * Create the one workspace row and its version counter. Refuses if the
 * workspace already exists — a second device must JOIN (getWorkspaceMeta),
 * never bootstrap, or it would clobber the existing wrapped DEK. This mutation
 * cannot pre-authenticate (no workspace exists yet), so the create-once guard
 * is the only protection; whoever holds the deployment can create it once.
 */
export const bootstrapWorkspace = mutation({
  args: {
    workspaceId: v.string(),
    syncKeyHash: v.string(),
    kdfSalt: v.string(),
    kdfParams: kdfParamsValidator,
    dekWrap: v.string(),
    recoveryWrap: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("workspaces")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .unique();
    if (existing !== null) {
      throw new Error(`Workspace ${args.workspaceId} already exists`);
    }
    await ctx.db.insert("workspaces", { ...args, schemaVersion: SCHEMA_VERSION });
    await ctx.db.insert("counters", { workspaceId: args.workspaceId, version: 0 });
    return { workspaceId: args.workspaceId };
  },
});

/**
 * Authenticated read of the workspace's unlock material, used by a joining
 * device to fetch the wrapped DEK + KDF inputs and unlock locally.
 */
export const getWorkspaceMeta = query({
  args: { workspaceId: v.string(), syncKey: v.string() },
  handler: async (ctx, args) => {
    const w = await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return {
      kdfSalt: w.kdfSalt,
      kdfParams: w.kdfParams,
      dekWrap: w.dekWrap,
      recoveryWrap: w.recoveryWrap ?? null,
      schemaVersion: w.schemaVersion,
    };
  },
});
```

- [ ] **Step 4: Update generated api types and run the test**

Hand-edit `convex/_generated/api.ts`: add `import type * as workspaces from "../workspaces.js";` and a `"workspaces": typeof workspaces,` entry in the `ApiFromModules<{...}>` map. Then run:
```bash
npx vitest run convex/workspaces.test.ts
```
Expected: 4 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add convex/workspaces.ts convex/workspaces.test.ts convex/_generated
git commit -m "feat(convex): bootstrapWorkspace (create-once) + authenticated getWorkspaceMeta"
```

---

## Task 5: Chunks — dedup put and get

`putChunks` inserts only chunk ids not already present (content-addressed dedup). `getChunks` returns ciphers for a list of ids. Both authenticate first. The client batches `putChunks` to stay under the 16 MiB transaction cap.

**Files:**
- Create: `convex/chunks.ts`
- Test: `convex/chunks.test.ts`

- [ ] **Step 1: Write the chunks test**

Create `convex/chunks.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/chunks.test.ts`
Expected: FAIL — `api.chunks` is undefined.

- [ ] **Step 3: Write the chunks functions**

Create `convex/chunks.ts`:
```typescript
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";

/**
 * Insert encrypted chunks, skipping any chunkId already stored
 * (content-addressed dedup). The client batches calls to respect the 16 MiB
 * transaction cap. Returns how many rows were newly inserted.
 */
export const putChunks = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    chunks: v.array(v.object({ chunkId: v.string(), cipher: v.string() })),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    let inserted = 0;
    for (const chunk of args.chunks) {
      const existing = await ctx.db
        .query("chunks")
        .withIndex("by_workspace_chunk", (q) =>
          q.eq("workspaceId", args.workspaceId).eq("chunkId", chunk.chunkId),
        )
        .unique();
      if (existing === null) {
        await ctx.db.insert("chunks", {
          workspaceId: args.workspaceId,
          chunkId: chunk.chunkId,
          cipher: chunk.cipher,
        });
        inserted++;
      }
    }
    return { inserted };
  },
});

/**
 * Fetch ciphers for a list of chunk ids. Unknown ids are silently skipped;
 * the caller reassembles content in `contentChunks` order client-side.
 */
export const getChunks = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    chunkIds: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const out: { chunkId: string; cipher: string }[] = [];
    for (const chunkId of args.chunkIds) {
      const row = await ctx.db
        .query("chunks")
        .withIndex("by_workspace_chunk", (q) =>
          q.eq("workspaceId", args.workspaceId).eq("chunkId", chunkId),
        )
        .unique();
      if (row !== null) {
        out.push({ chunkId: row.chunkId, cipher: row.cipher });
      }
    }
    return out;
  },
});
```

- [ ] **Step 4: Update generated api types and run the test**

Hand-edit `convex/_generated/api.ts`: add `import type * as chunks from "../chunks.js";` and a `"chunks": typeof chunks,` entry in the `ApiFromModules<{...}>` map. Then run:
```bash
npx vitest run convex/chunks.test.ts
```
Expected: 3 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add convex/chunks.ts convex/chunks.test.ts convex/_generated
git commit -m "feat(convex): content-addressed chunk dedup put + get"
```

---

## Task 6: Files — atomic upsert, tombstone, feed, path lookup

The heart of the backend. `upsertFile` does conflict-check + version-bump + write in one mutation. `tombstoneFile` marks a delete the same way. `listChanges` is the reactive value-cursor feed. `getFileByPath` resolves a path to its live file row.

**Files:**
- Create: `convex/files.ts`
- Test: `convex/files.test.ts`

- [ ] **Step 1: Write the files test**

Create `convex/files.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/files.test.ts`
Expected: FAIL — `api.files` is undefined.

- [ ] **Step 3: Write the files functions**

Create `convex/files.ts`:
```typescript
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";
import { nextVersion } from "./lib/version";

/**
 * Create or update a file. Conflict check + version bump + write happen in one
 * mutation, so Convex's serializable transactions make stale-write rejection
 * correct: if the stored version for this fileId differs from the caller's
 * baseVersion, nothing is written and the caller makes a local conflict copy.
 */
export const upsertFile = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    fileId: v.string(),
    pathId: v.string(),
    pathCipher: v.string(),
    type: v.union(v.literal("note"), v.literal("attachment"), v.literal("config")),
    contentTag: v.string(),
    size: v.number(),
    mtime: v.number(),
    baseVersion: v.number(),
    contentChunks: v.optional(v.array(v.string())),
    storageId: v.optional(v.id("_storage")),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const existing = await ctx.db
      .query("files")
      .withIndex("by_workspace_file", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("fileId", args.fileId),
      )
      .unique();
    if (existing !== null && existing.version !== args.baseVersion) {
      return { status: "conflict" as const, serverVersion: existing.version };
    }
    const version = await nextVersion(ctx.db, args.workspaceId);
    const row = {
      workspaceId: args.workspaceId,
      fileId: args.fileId,
      pathId: args.pathId,
      pathCipher: args.pathCipher,
      type: args.type,
      contentTag: args.contentTag,
      size: args.size,
      mtime: args.mtime,
      deleted: false,
      version,
      baseVersion: args.baseVersion,
      contentChunks: args.contentChunks,
      storageId: args.storageId,
    };
    if (existing === null) {
      await ctx.db.insert("files", row);
    } else {
      await ctx.db.replace(existing._id, row);
    }
    return { status: "ok" as const, version };
  },
});

/**
 * Mark a file deleted (tombstone). Same conflict-check + version-bump path as
 * upsert. The row is retained as a tombstone so other devices see the delete
 * in the feed; content references are cleared (orphaned chunks/blobs are GC'd
 * later — deferred, see plan notes).
 */
export const tombstoneFile = mutation({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    fileId: v.string(),
    baseVersion: v.number(),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const existing = await ctx.db
      .query("files")
      .withIndex("by_workspace_file", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("fileId", args.fileId),
      )
      .unique();
    if (existing === null) {
      return { status: "missing" as const };
    }
    if (existing.version !== args.baseVersion) {
      return { status: "conflict" as const, serverVersion: existing.version };
    }
    const version = await nextVersion(ctx.db, args.workspaceId);
    await ctx.db.patch(existing._id, {
      deleted: true,
      version,
      baseVersion: args.baseVersion,
      contentTag: "",
      size: 0,
      contentChunks: undefined,
      storageId: undefined,
    });
    return { status: "ok" as const, version };
  },
});

/**
 * Reactive change feed via a value cursor: all rows with version > sinceVersion,
 * ascending, capped at `limit`. Returns the rows, the next cursor (max version
 * seen, or sinceVersion if empty), and whether a full page was returned.
 * Restart- and reconnect-safe because the cursor is a real version number.
 */
export const listChanges = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    sinceVersion: v.number(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const limit = args.limit ?? 50;
    const changes = await ctx.db
      .query("files")
      .withIndex("by_workspace_version", (q) =>
        q.eq("workspaceId", args.workspaceId).gt("version", args.sinceVersion),
      )
      .order("asc")
      .take(limit);
    const nextCursor =
      changes.length > 0 ? changes[changes.length - 1]!.version : args.sinceVersion;
    return { changes, nextCursor, hasMore: changes.length === limit };
  },
});

/**
 * Resolve a path (via its HMAC pathId) to its live file row, or null. A path
 * may have a tombstone plus a later live file sharing the same pathId, so we
 * return the first non-deleted match rather than using `.unique()`.
 */
export const getFileByPath = query({
  args: {
    workspaceId: v.string(),
    syncKey: v.string(),
    pathId: v.string(),
  },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    const rows = await ctx.db
      .query("files")
      .withIndex("by_workspace_path", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("pathId", args.pathId),
      )
      .collect();
    return rows.find((r) => !r.deleted) ?? null;
  },
});
```

- [ ] **Step 4: Update generated api types and run the test**

Hand-edit `convex/_generated/api.ts`: add `import type * as files from "../files.js";` and a `"files": typeof files,` entry in the `ApiFromModules<{...}>` map. Then run:
```bash
npx vitest run convex/files.test.ts
```
Expected: 8 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add convex/files.ts convex/files.test.ts convex/_generated
git commit -m "feat(convex): atomic upsert/tombstone with conflict check + value-cursor feed"
```

---

## Task 7: Attachments — upload URL and serve URL

`generateUploadUrl` (a mutation, as Convex requires) hands the client a one-time URL to PUT an encrypted blob; the client then records the returned `storageId` on a file via `upsertFile`. `getAttachmentUrl` returns a download URL for a stored blob.

**Files:**
- Create: `convex/attachments.ts`
- Test: `convex/attachments.test.ts`

- [ ] **Step 1: Write the attachments test**

Create `convex/attachments.test.ts`:
```typescript
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run convex/attachments.test.ts`
Expected: FAIL — `api.attachments` is undefined.

- [ ] **Step 3: Write the attachments functions**

Create `convex/attachments.ts`:
```typescript
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { authenticate } from "./lib/auth";

/**
 * Issue a one-time upload URL for an encrypted attachment blob. Must be a
 * mutation (Convex requirement). The client PUTs the ciphertext to this URL,
 * then records the returned storageId on a file via upsertFile.
 */
export const generateUploadUrl = mutation({
  args: { workspaceId: v.string(), syncKey: v.string() },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return await ctx.storage.generateUploadUrl();
  },
});

/** Return a download URL for a stored encrypted blob, or null if it is gone. */
export const getAttachmentUrl = query({
  args: { workspaceId: v.string(), syncKey: v.string(), storageId: v.id("_storage") },
  handler: async (ctx, args) => {
    await authenticate(ctx.db, args.workspaceId, args.syncKey);
    return await ctx.storage.getUrl(args.storageId);
  },
});
```

- [ ] **Step 4: Update generated api types and run the test**

Hand-edit `convex/_generated/api.ts`: add `import type * as attachments from "../attachments.js";` and a `"attachments": typeof attachments,` entry in the `ApiFromModules<{...}>` map. Then run:
```bash
npx vitest run convex/attachments.test.ts
```
Expected: 3 passed.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Run the whole suite + typecheck (final gate)**

Run: `npm test && npm run typecheck`
Expected: every crypto-core + convex test passes; `tsc --noEmit` clean.

- [ ] **Step 7: Commit**

```bash
git add convex/attachments.ts convex/attachments.test.ts convex/_generated
git commit -m "feat(convex): attachment upload + serve URLs"
```

---

## Deferred (out of scope, documented on purpose)

- **Orphan-chunk / orphan-blob GC.** Tombstones and attachment replacements leave unreferenced chunks and blobs. With the 1 GB free file tier and small personal vaults, the storage cost is negligible; a sweep (mark-and-delete over `contentChunks` references) is deferred to a later production plan rather than complicating every write path now.
- **Cold-start bulk read.** `listChanges` from `sinceVersion = 0` already replays the whole vault in pages; a dedicated `.paginate()` bulk endpoint is only worth adding if a cold start over many thousands of files proves slow.
- **Per-request rate limiting / abuse controls.** Single-user personal deployment; not needed now.

## Notes for the implementer

- Never import from `src/` inside `convex/`. The backend is crypto-agnostic.
- The client supplies all randomness (fileId, nonces); never call `crypto.getRandomValues`/`Math.random` in a function to generate stored values.
- Do NOT run `npx convex codegen` (it errors without a deployment). When you add a function module, hand-edit `convex/_generated/api.ts` per the "Codegen decision" section: add the `import type * as <mod>` line and the `"<mod>": typeof <mod>,` map entry. `dataModel.ts`/`server.ts` need no edits.
- `authenticate` takes `ctx.db` (a `DatabaseReader`/`DatabaseWriter`), not the whole `ctx`.
- convex-test is API-shape evidence, not a production-runtime guarantee. The load-bearing claim "server-side `crypto.subtle` works" is additionally proven by Task 0 Step 7's digest assertion and by Convex's CF-Workers-equivalent runtime docs.
