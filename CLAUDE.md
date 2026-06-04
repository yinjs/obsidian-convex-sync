# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An Obsidian plugin that syncs a single user's vault (notes + attachments)
across their devices in near-real-time, using a Convex backend as the reactive
transport. **End-to-end encrypted and zero-knowledge**: the server stores only
ciphertext and opaque HMAC ids — never paths, titles, or content. Built in
phases; see the Roadmap table in `README.md` for current status (crypto +
backend done on `main`; sync engine in progress; plugin shell not started).

## Commands

```bash
npm test                 # vitest run — all unit tests (tests/ + convex/)
npm run test:watch       # vitest watch
npm run typecheck        # tsc --noEmit
npx vitest run tests/crypto/kdf.test.ts        # single file
npx vitest run -t "wraps the DEK"               # single test by name
```

No build/lint step yet. No dev server (the plugin shell does not exist).

## Hard rules

- **Convex codegen is hand-maintained.** Never run `npx convex codegen` or
  `npx convex dev`. When adding a Convex function module, hand-edit
  `convex/_generated/api.ts` (add the `import type * as <mod>` line and the
  `fullApi` entry). The generated files are committed on purpose.
- The sync engine (`src/sync/`) must **never import Obsidian or the Convex
  client** — only the crypto barrel (`src/crypto`) and its own `ports.ts`. This
  is what keeps it unit-testable without a device or a live deployment. Don't
  break it.

## Architecture

Three layers, each platform-agnostic except the not-yet-built plugin shell:

### `src/crypto/` — crypto core (WebCrypto + hash-wasm, no platform deps)

Barrel-exported via `src/crypto/index.ts`. Envelope encryption:

- A random 256-bit **DEK** is generated once at bootstrap. The passphrase +
  `kdfSalt` derive a **KEK** (Argon2id preferred, PBKDF2-HMAC-SHA256 ≥600k as a
  fallback — see `kdf.ts`) that wraps the DEK with AES-GCM.
- From the DEK, HKDF (`hkdf.ts`) derives `encKey` (content + paths) and
  domain-separated HMAC keys (`chunkMacKey`, `pathMacKey`, `contentMacKey`) used
  to compute deterministic dedup ids (`hmacId.ts`).
- A wrong passphrase fails the GCM auth tag — no canary, no corruption.
- Notes are content-defined chunked (`chunker.ts`, FastCDC-style) on the
  **plaintext**, so a one-char edit re-uploads ~one chunk.

### `convex/` — the user's own Convex backend (schema + functions)

- Tables (`schema.ts`): `workspaces` (one row, holds KDF params + wrapped DEK
  so a 2nd device can join), `files` (metadata keyed by stable `fileId`, with a
  monotonic per-workspace `version`), `chunks` (deduped ciphertext by
  `chunkId`), `counters` (the version source).
- **Every function authenticates via `lib/auth.ts` `authenticate(ctx.db,
  workspaceId, syncKey)`** and scopes all reads/writes to that workspace.
  Unknown workspace and bad key throw the same `"Unauthorized"`.
- **Every write mutation bumps the version via `lib/version.ts`
  `nextVersion()`** inside the transaction. Convex's serializable transactions
  make versions unique and gap-free — this monotonic `version` is the spine of
  the pull change-feed. Don't write a `files` row without it.
- `SCHEMA_VERSION` in `schema.ts` gates old plugins against newer schemas; bump
  it when table shapes change.

### `src/sync/` — sync engine (in progress, behind ports)

Pure TypeScript behind four injected **ports** defined in `ports.ts`:
`VaultPort` (filesystem), `RemotePort` (Convex wrapper that bakes in
`workspaceId` + `syncKey` so the engine never sees auth), `StatePort`
(persists the serialized state blob), `Clock`. The engine maps `fileId →
SyncEntry` to break echo loops and drive conflict detection.

Sync model (detail in `README.md`): **push** = event → debounce → hash → diff
vs sync-state → upload missing chunks → `upsertFile` (bumps version). **pull** =
paginated query on `version > lastSeen` → fetch content by id → decrypt → write.
**Conflicts** = last-write-wins by `mtime`, loser saved as a
`name (conflict <stamp>).md` copy, resolved in exactly one place (the pull path).
Local changes go to a **durable outbound queue** that survives restart.

### Metadata / content split (the load-bearing design choice)

Convex caps a transaction at 16 MiB / 32k docs and returns whole documents. So
the reactive change-feed carries **metadata only** (`files` rows ordered by
`version`); content is fetched on demand by id. This is the line between "works
on 50 notes" and "works on 5000." Keep large blobs out of the `files` rows.

## Security secrets (two, by design — don't conflate)

- **Sync key** — authenticates to the server, gates who can fetch ciphertext +
  KDF salt. Server access control only; decrypts nothing.
- **Passphrase** — never sent to the server; the only thing that decrypts
  content.

## Tests

`vitest.config.ts` defaults to the `node` environment. Convex test files
(`convex/**/*.test.ts`) opt into `edge-runtime` per-file via a
`// @vitest-environment edge-runtime` pragma and use `convex-test`. Crypto and
sync tests live under `tests/`; `tests/sync/fakes.ts` holds in-memory port
fakes for engine tests.

## Reference docs

Design spec and per-phase implementation plans live in `docs/superpowers/`
(`specs/` = approved design + threat model, `plans/` = phase plans).
