# obsidian-convex-sync

An Obsidian plugin that syncs a vault (notes + attachments) across a user's
devices in near-real-time, using [Convex](https://www.convex.dev/)'s reactive
backend as the sync engine. **Single-user, multi-device** — no collaboration,
no sharing. **End-to-end encrypted**: the server stores ciphertext and opaque
HMAC ids only; it never sees paths, titles, or content.

> **Status:** under construction. Crypto core and the Convex backend are built
> and merged to `main`; the platform-agnostic sync engine is in progress on
> `feat/sync-engine`; the Obsidian plugin shell is not yet started. See
> [Roadmap](#roadmap).

## Why

Obsidian's own sync (and most alternatives) trust the server with your
plaintext. This project keeps Convex as a fast reactive transport while making
the backend zero-knowledge — a Convex breach or insider sees only encrypted
blobs, opaque ids, sizes, and chunk-repetition structure.

## How it works

Three parts:

1. **Obsidian plugin** (TypeScript) — bundles the Convex client, which runs over
   websocket in both Electron (desktop) and the mobile webview.
2. **Convex backend** (the user's own Cloud project) — schema + query / mutation
   / action functions. Every function validates the sync key and scopes all
   reads/writes to one workspace.
3. **Local sync-state store** (per device) — maps `fileId → {path, contentTag,
   syncedVersion, mtime}`, persisted in the plugin data dir. Breaks echo loops
   and powers conflict detection.

### Metadata / content split

Convex returns whole documents and caps a transaction at 16 MiB / 32k docs. So
the reactive change-feed carries **metadata only** (`files` rows, ordered by a
monotonic `version`); content is fetched on demand by id. This is the line
between "works on 50 notes" and "works on 5000."

- **Notes** are content-defined chunked (FastCDC-style) on the **plaintext**,
  then each chunk is id'd + encrypted and stored deduped in a `chunks` table. A
  one-char edit re-uploads ~one chunk, not the whole file.
- **Attachments** are encrypted whole and stored as one blob in Convex file
  storage, referenced by `storageId`.

### Sync model

- **Push:** vault event → debounce → hash → diff against sync-state → upload
  missing chunks / blob → `upsertFile` mutation bumps `version`.
- **Pull:** reactive paginated query on `version > lastSeen` → fetch changed
  content by id → decrypt → write to vault.
- **Conflicts:** last-write-wins by `mtime`; the losing version is written as a
  `name (conflict <timestamp>).md` copy — never discarded. Resolved in exactly
  one place (the pull path).
- **Offline-first:** local vault is the source of truth; local changes go to a
  durable outbound queue (persisted, survives restart) and replay on reconnect.
  The DEK is cached on-device after first unlock, so offline edits encrypt with
  no network call.

## Security

Two separate secrets by design:

- **Sync key** — a shared secret that authenticates to the server and gates who
  can fetch the ciphertext + KDF salt. Server access control only; decrypts
  nothing. Rotating it cuts off all devices at the server boundary.
- **Passphrase** — never sent to the server; the only thing that can decrypt
  content.

**Envelope encryption:** a random 256-bit DEK is generated once at bootstrap.
The passphrase + `kdfSalt` derive a KEK (**Argon2id** preferred, PBKDF2-HMAC-SHA256
≥ 600k iterations as a named-tradeoff fallback) which wraps the DEK
(`AES-GCM(KEK, DEK)`). From the DEK, HKDF derives `encKey` (AES-GCM for
content + paths) and domain-separated HMAC keys (`chunkMacKey`, `pathMacKey`,
`contentMacKey`) for deterministic dedup ids. A wrong passphrase fails the GCM
auth tag immediately — no canary, no corruption risk. An optional recovery key
wraps a second copy of the DEK; passphrase rotation just re-wraps the DEK with
no vault re-encryption.

- **Protects against:** a Convex breach or a Convex employee.
- **Does NOT protect against:** a compromised device, a malicious co-installed
  plugin, or a weak passphrase. The KDF cost and passphrase strength are
  load-bearing.
- **Residual leak:** identical chunks/paths share an id (equality/repetition),
  accepted in exchange for dedup. The server lacks the MAC keys, so it cannot
  test guessed plaintext against an id.

Full threat model and rationale: [design doc](docs/superpowers/specs/2026-06-03-obsidian-convex-sync-design.md).

## Repository layout

```
src/crypto/      Platform-agnostic crypto core (WebCrypto + hash-wasm)
                   bytes, aesgcm, hkdf, hmacId, kdf, envelope, chunker
src/sync/        Platform-agnostic sync engine (in progress)
                   ports (VaultPort/RemotePort/StatePort/Clock), codec, ...
convex/          User's Convex backend: schema + functions
                   workspaces, files, chunks, attachments, lib/{auth,version}
tests/           vitest unit tests (crypto/, sync/)
docs/superpowers/
  specs/         Approved design doc
  plans/         Per-phase implementation plans
```

The sync engine is pure TypeScript behind four injected **ports** so it is fully
unit-testable without Obsidian or a live Convex deployment. It never imports the
Obsidian or Convex client packages — only the crypto barrel and its own ports.

## Development

```bash
npm install
npm test          # vitest run (all unit tests)
npm run test:watch
npm run typecheck # tsc --noEmit
```

> **Convex codegen is hand-maintained.** Do not run `npx convex codegen` or
> `npx convex dev`; hand-edit `convex/_generated/api.ts` when adding a function
> module.

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Crypto core (chunker, AES-GCM, HKDF, KDF, envelope, HMAC ids) | done, on `main` |
| 2 | Convex backend (schema + auth-scoped functions) | done, on `main` |
| 3 | Sync engine (push / pull / conflict / offline, behind ports) | in progress |
| 4 | Obsidian plugin shell (settings UI, debounce timer, reactive subscription, mobile catch-up) | not started |

## Out of scope (YAGNI)

- Multi-user / collaboration / sharing.
- Real auth accounts / per-device revocation (sync key gates server access).
- CRDT character-level merge (chose LWW + conflict copy).
- **Sync while the mobile app is closed** — not achievable in Obsidian's plugin
  model. The mobile guarantee is reliable catch-up on open + zero data loss.

## License

Not yet specified. Personal project, pre-release.
