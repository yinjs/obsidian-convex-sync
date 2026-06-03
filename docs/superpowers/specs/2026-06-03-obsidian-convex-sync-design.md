# Obsidian ↔ Convex Sync Plugin — Design

**Date:** 2026-06-03
**Status:** Approved design, pre-implementation

## Goal

An Obsidian plugin that syncs a vault (notes + attachments) across a user's
devices in near-real-time, using Convex's reactive backend as the sync engine.
Single-user, multi-device. No collaboration, no sharing.

## Decisions

| Axis | Decision |
| --- | --- |
| Use case | Personal, multi-device (one person, several devices) |
| Backend | Convex Cloud, **end-to-end encrypted** (server sees ciphertext + opaque ids only) |
| Platforms | Desktop (Electron) + mobile (webview); desktop-first |
| Conflicts | Last-write-wins + conflict-copy file (no silent data loss) |
| Sync scope | Notes + attachments; optional `.obsidian` allowlist |
| Server auth | Sync key (shared secret, no accounts) — gates who can read the ciphertext |
| Encryption | Passphrase → envelope-wrapped DEK; **full E2E** (content + paths) |
| Mobile guarantee | Reliable catch-up on open + eventual consistency + zero data loss (foreground sync; not while app closed) |
| Offline | Offline-first: full local editing offline, durable outbound queue, reconcile on reconnect |
| Note storage | Uniform content-defined chunking for all note sizes |
| Attachment storage | Convex file storage (one encrypted blob per attachment) |

The sync key and the encryption passphrase are **two separate secrets** by
design: the sync key authenticates to the server and gates who can even read the
encrypted blobs+salt (removing the offline-dictionary-attack surface); the
passphrase is never sent to the server and is the only thing that can decrypt
content. See [Encryption (E2E)](#encryption-e2e).

## Verified Convex constraints (Context7, 2026-06-03)

These shape the architecture and were confirmed against current docs:

- **Document size cap: 1 MiB** per document.
- **Per-transaction caps:** 16 MiB read/written, 32,000 documents scanned,
  4,096 index-range reads per function. → the change-feed and cold start
  **must paginate**.
- **File storage:** 1 GB on the free tier (storage + backups), plus egress
  limits on serving/reading files.
- **Auth flows:** email+password and email-OTP are headless (no browser); OAuth
  and magic-link need a browser redirect. *(We chose sync-key, so none of these
  are used — recorded for context.)*
- **Queries return whole documents** (no server-side field projection). → never
  put note content in a doc that is part of the reactive feed.

## Architecture

Three parts:

1. **Obsidian plugin** (TypeScript) — bundles the Convex client, which runs over
   websocket in both Electron and the mobile webview.
2. **Convex backend** (the user's own Cloud project) — schema + query / mutation
   / action functions. Every function validates the sync key and scopes all
   reads/writes to one workspace.
3. **Local sync-state store** (per device) — maps `path → {fileId, hash,
   syncedVersion, mtime}`, persisted in the plugin data dir. Breaks echo loops
   and powers conflict detection.

### Why split metadata from content

Convex returns whole documents and caps a transaction at 16 MiB / 32k docs. If
note bodies lived in the doc that the reactive feed subscribes to, every feed
tick would ship content bytes and blow the cap on a real vault. So the feed
carries **metadata only**; content is fetched on demand by id. This is the line
between "works on 50 notes" and "works on 5000."

## Data model (Convex)

All user-meaningful fields (path, content) are encrypted client-side; the
server stores ciphertext and opaque HMAC ids. See
[Encryption (E2E)](#encryption-e2e) for how each field is protected.

```
workspaces                     // one row, created at bootstrap
  workspaceId    string        // non-secret scope label
  syncKeyHash    string        // verifier for the server-auth sync key
  kdfSalt        string        // salt for passphrase → KEK derivation (public)
  kdfParams      object        // algorithm + cost params (argon2id/pbkdf2)
  dekWrap        string        // AES-GCM(KEK, DEK) — passphrase-wrapped data key
  recoveryWrap   string?       // AES-GCM(recoveryKey, DEK) — optional recovery
  index by (workspaceId)

files
  workspaceId    string        // scope
  fileId         string        // STABLE random opaque id; path is mutable
  pathId         string        // HMAC(macKey, normalizedPath) — deterministic lookup
  pathCipher     string        // AES-GCM(encKey, path) + nonce — render client-side
  type           "note" | "attachment" | "config"
  contentTag     string        // HMAC(macKey, plaintext file hash) — change detect
  size           number        // ciphertext size (rough; plaintext size hidden)
  mtime          number
  deleted        boolean       // tombstone
  version        number        // monotonic per workspace; feed cursor
  baseVersion    number        // version this write was based on (conflict check)
  contentChunks  string[]?     // ordered chunk ids (HMAC of plaintext chunks)
  storageId      string?       // Convex file-storage id (encrypted attachment blob)
  index by (workspaceId, version)   // reactive change-feed (metadata only)
  index by (workspaceId, pathId)    // path lookup
  index by (workspaceId, fileId)    // stable-id lookup

chunks
  workspaceId    string
  chunkId        string        // HMAC(macKey, plaintextChunk) — dedup key, opaque
  cipher         string        // AES-GCM(encKey, plaintextChunk) + nonce (< 1 MiB)
  index by (workspaceId, chunkId)

counters
  workspaceId    string
  version        number        // bumped on every write to assign next version
```

Keying files by stable `fileId` (path as a mutable attribute) means a
rename/move is **one metadata update**, and version/conflict history survives
the move. Obsidian hands the plugin both old and new path on rename → map to the
existing `fileId`. `pathId` is a deterministic HMAC so a device can locate a
file's row by path without the server ever learning the path.

### Note storage — uniform content-defined chunking

Every note (and any allowlisted `.obsidian` text file), **regardless of size**,
runs through one path. **Chunk the plaintext first, then id + encrypt each
chunk** — never chunk ciphertext (both dedup and content-defined boundaries
break on ciphertext):

1. Split **plaintext** with a **rolling-hash / FastCDC-style** chunker →
   content-defined boundaries, each plaintext chunk bounded so its ciphertext
   stays well under 1 MiB.
2. For each chunk: `chunkId = HMAC(macKey, plaintextChunk)`; `cipher =
   AES-GCM(encKey, plaintextChunk)` with a fresh nonce. Store in `chunks` deduped
   by `chunkId` (skip ids already present).
3. The `files` row holds the ordered list of chunk ids in `contentChunks`.

Consequences:
- A 1-char edit re-chunks locally but only the chunk(s) around the edit get new
  ids → **upload is ~one chunk, not the whole file**.
- Tiny note = one chunk. No size special-case, one code path.
- Shared boilerplate/templates across notes dedup to the same chunks (the only
  leak is chunk *equality*; the server can't recover plaintext without `macKey`).

### Attachment storage — Convex file storage

Binary attachments are encrypted client-side (`AES-GCM(encKey, blob)` + nonce)
and the ciphertext blob goes to Convex file storage; the `files` row references
it via `storageId`. *Not* chunked into DB rows — that would bloat the document
store and forfeit the cheaper 1 GB blob tier and direct URL serving. Attachments
are typically replaced wholesale, so file-level dedup (by `contentTag`) is
enough. (obsidian-livesync chunks binaries because CouchDB has no blob tier; we
have one.)

## Sync engine (plugin)

### Push (local → remote)

Vault event (`create`/`modify`/`delete`/`rename`) → debounce (~1–2 s after the
last save) → hash content → compare to sync-state:
- **Note changed:** chunk plaintext → id + encrypt → upload missing chunks →
  mutation updates the `files` row (`contentChunks`, `contentTag`, `pathCipher`,
  mtime, `baseVersion`) and bumps `version`.
- **Attachment changed:** encrypt blob → request upload URL → `storage.store` →
  mutation sets `storageId` + `contentTag`, bumps `version`.
- Update local sync-state with the new content tag and version.

### Pull (remote → local)

Reactive **paginated** query on `files where workspaceId = mine AND version >
lastSeen`, ordered by `version`:
- For each changed row, if remote `contentTag` ≠ local sync-state tag → fetch
  content (chunk rows by `chunkId`, or storage URL for attachments) → decrypt →
  write to vault → advance the cursor and sync-state.
- **Delete** (tombstone) → move local file to system trash.
- **Rename** → move local file, matched by `fileId`.

### Conflict resolution (LWW + conflict copy)

Before applying a remote change, if the local file *also* changed since the last
synced version (local content tag ≠ sync-state tag **and** remote version >
synced version):
- Newer `mtime` wins.
- The losing version is written as `name (conflict 2026-06-03 14-22).md` — never
  discarded.

Symmetric on push: the mutation includes the base version it edited; the server
rejects a stale write; the client re-pulls and produces the conflict copy. No
data loss in either direction.

### Echo prevention

Applying a remote write updates sync-state to the new hash, so the resulting
Vault `modify` event is recognized as already-synced and is **not** re-pushed.

## Cold start / initial sync

- Paginate the full metadata feed (cursor-based) to respect the 32k-doc /
  16 MiB transaction caps.
- Three-way reconcile by hash: local-only → push; remote-only → pull;
  both-differ → conflict resolution.
- Build local sync-state from scratch on first run.

## Offline-first

Offline is a normal operating mode, not an error path. The plugin must never
block editing when there is no network.

- **Local vault is the source of truth.** Obsidian reads/writes local files
  regardless of connectivity; the plugin only observes and syncs. Editing,
  creating, renaming, deleting all work fully offline.
- **Durable outbound queue.** Local changes are recorded in a queue persisted to
  the plugin data dir (survives app restart while still offline). Nothing is held
  only in memory.
- **Offline encryption.** The DEK is cached locally after a one-time unlock, so
  offline edits are chunked, id'd, and encrypted into the queue without any
  network call. (First-ever unlock needs to fetch the wrapped DEK once; after
  that it is cached on-device.)
- **Reconnect reconciliation.** On regaining connectivity: drain the outbound
  queue (push), then run the incremental pull, then reconcile — producing
  conflict copies where both sides moved. Order guarantees no lost local work.
- **Persisted cursor + sync-state.** The feed cursor and per-file sync-state are
  persisted, so an offline restart resumes exactly where it left off instead of
  re-syncing from scratch.
- **We own the queue, not the Convex client.** Writes route through our durable
  queue rather than firing mutations directly, so an offline write is never lost
  or silently failed; it is committed locally and replayed on reconnect.

This is the same machinery the [cold start](#cold-start--initial-sync) and
[mobile catch-up](#mobile-behavior) paths use — offline-restart and
foreground-resume are the same reconcile.

## Server auth / scoping (sync key)

The sync key is **server access control only** — it does not decrypt anything.

- At bootstrap the plugin generates a high-entropy sync key and stores its
  verifier (`syncKeyHash`) in the `workspaces` row. The user pastes deployment
  URL + `workspaceId` + sync key into the plugin settings on each device.
- Every function does a constant-time compare of the supplied key against
  `syncKeyHash` and scopes all reads/writes to that `workspaceId`. Invalid key →
  reject before any data is read.
- **Why separate from the passphrase:** the sync key gates who can even fetch the
  ciphertext + KDF salt. Without it, a network attacker can't pull the wrapped
  DEK to mount an offline dictionary attack on the passphrase. Rotating the sync
  key cuts off all devices at the server boundary; it has no effect on
  encryption.

## Encryption (E2E)

> Highest-risk subsystem. Gets its own focused review pass before implementation.

### Threat model

- **Protects against:** a Convex breach or a Convex employee. They see ciphertext,
  opaque HMAC ids, blob sizes, and chunk-repetition structure — nothing else. No
  paths, no titles, no content.
- **Does NOT protect against:** a compromised device, a malicious Obsidian
  plugin running alongside, or a weak passphrase. The KDF is the only wall
  between a server-side adversary (who can read salt + wrapped DEK) and the
  plaintext — so passphrase strength and KDF cost are load-bearing.

### Key hierarchy (envelope encryption)

Envelope, not passphrase→content-key directly — so the passphrase can rotate and
a recovery key can exist without re-encrypting the vault:

1. **DEK** (Data Encryption Key) — random 256-bit key, generated once at
   bootstrap. Everything is encrypted under keys derived from the DEK.
2. **KEK** (Key Encryption Key) — derived from the passphrase + `kdfSalt` via
   **Argon2id** (preferred). Store `dekWrap = AES-GCM(KEK, DEK)`.
3. **Unlock** = derive KEK → unwrap DEK. A wrong passphrase fails the GCM auth
   tag immediately → no separate canary needed, no risk of corrupting data.
4. From the DEK, derive via HKDF: `encKey` (AES-GCM content/path encryption) and
   `macKey` (HMAC for deterministic chunk ids and `pathId`).

### KDF choice

- **Argon2id** via a lightweight WASM lib is the target — verify it runs in the
  Obsidian **mobile** webview during spike.
- If Argon2 genuinely won't run there, fall back to **PBKDF2-HMAC-SHA256 ≥
  600,000 iterations** (native WebCrypto) **and** enforce a strong-passphrase
  requirement at setup. This fallback is weaker — it is a named tradeoff, not a
  convenience default.

### Recovery & rotation (envelope payoffs)

- **Recovery key:** at setup, generate a random recovery code, show it once, and
  store `recoveryWrap = AES-GCM(recoveryKey, DEK)`. Losing the passphrase is
  otherwise unrecoverable (true E2E) — warn loudly.
- **Passphrase rotation:** re-derive KEK from the new passphrase and re-wrap the
  DEK. No vault re-encryption.

### What is encrypted, and the residual leak

- **Content** (note chunks, attachment blobs): `AES-GCM(encKey, …)`, fresh
  CSPRNG 96-bit nonce per encryption, nonce stored with the ciphertext, never
  reused under one key.
- **Paths/filenames:** `pathCipher = AES-GCM(encKey, path)`; lookups use
  `pathId = HMAC(macKey, normalizedPath)`.
- **Dedup ids:** `chunkId = HMAC(macKey, plaintextChunk)`. The server lacks
  `macKey`, so it cannot test guessed plaintext against an id. The only residual
  leak is *equality/repetition* — identical chunks or paths share an id. Accepted
  as a weak leak in exchange for dedup.

Reference: obsidian-livesync ships passphrase-based E2EE and revised its scheme
across versions to fix path-obfuscation weaknesses — study what it encrypts and
the pitfalls it hit.

## Mobile behavior

Obsidian suspends plugin JS when the mobile app is backgrounded, and exposes no
background-fetch/background-task API to plugins. So **sync while the app is
closed is not achievable in the plugin model** (Obsidian's own Sync has the same
limit). The production guarantee is therefore about *consistency*, not
*always-on*:

- **Reliable catch-up on open:** on plugin load / app foreground, run the
  cursor-based pull to land on latest before the user edits.
- **Eventual consistency + zero data loss:** nothing is dropped; conflict copies
  preserve every version. Edits made offline propagate as soon as any device is
  foregrounded.
- **Foreground sync loop:** stays subscribed while open; flush pending pushes on
  background/unload.
- **Optional desktop-always-on relay (recommended setup):** a desktop left
  running is the always-online node, so changes are always in Convex ready for
  mobile to pull on open. Documented as a recommendation, not a requirement.
- **Lazy attachment download** (opt-in): don't pull large media until a note
  referencing it is opened, to save mobile bandwidth/storage.

## Limits surfaced to the user

- Chunker keeps every chunk under the 1 MiB doc cap automatically.
- Attachments count against the **1 GB free-tier** file storage → show a usage
  indicator and warn as it fills.
- Content is fetched only on `contentTag` change, to limit egress.

## Settings UI

- Convex deployment URL, `workspaceId`, sync key, workspace name.
- Encryption: passphrase entry/unlock; recovery-key display at setup + restore
  flow; passphrase-rotation action.
- `.obsidian` allowlist (which config files to sync).
- Lazy-attachment toggle.
- Status indicator: synced / syncing / locked / error + last-sync time.
- Force-full-resync button.

## Error handling

- **Offline:** queue pushes locally with backoff retry; the reactive query
  auto-reconnects.
- **Failed upload:** mark the path dirty in sync-state, retry.
- **Oversized / corrupt file:** skip + notify, never crash the sync loop.
- **Stale version:** conflict copy, never lose data.

## Production readiness

Beyond features, "production-ready" means robustness + operability:

- **Convex cost control:** Convex bills per function call. Debounce pushes,
  batch chunk uploads into one mutation, coalesce rapid edits, and cap feed
  re-subscription churn so a large/active vault stays within call limits.
- **Observability:** structured logs with a verbosity toggle, an in-plugin sync
  diagnostics panel (queue depth, last error, cursor position, storage usage),
  and surfaced last-error state — not silent failures.
- **Schema/data migration:** a `schemaVersion` on the workspace; forward
  migrations so future schema changes don't break existing workspaces. Plugin
  refuses to sync against a newer schema than it understands (prompt to update).
- **Corrupt-state recovery:** if the local sync-state index is lost or
  inconsistent, rebuild it by re-reconciling vault against remote (the cold-start
  path) — never lose data, never duplicate.
- **Encryption-state safety:** wrong passphrase fails fast at unlock (GCM tag);
  refuse to write plaintext if the key is unavailable; recovery-key flow tested.
- **Release pipeline:** `manifest.json` + semver, `versions.json`, CI (lint +
  typecheck + tests), BRAT-installable builds, and community-plugin submission
  checklist.

## Testing

- **Unit:** chunker boundaries + dedup, encrypt/decrypt round-trip, envelope
  wrap/unwrap + recovery key + passphrase rotation, HMAC id determinism,
  conflict decisions, `fileId`↔path mapping, sync-state transitions.
- **Integration:** two simulated clients against a Convex dev deployment —
  concurrent edit, offline→online, rename, delete, attachment upload,
  conflict-copy creation, cold start with a pre-populated remote, a second device
  joining with the passphrase + recovering via recovery key, wrong-passphrase
  rejection, and corrupt sync-state rebuild.
- **Manual:** a real desktop + mobile device pair, including
  background→foreground catch-up on mobile.

## Reference

`obsidian-livesync` (CouchDB/PouchDB-based) solved this same problem; borrow its
content-defined chunking and conflict patterns. Its design validates the
metadata/content split. Key divergence: we use Convex file storage for binaries
instead of chunking them into the database.

## Out of scope (YAGNI)

- Multi-user / collaboration / sharing.
- Real auth accounts / per-device revocation (chose sync key for server access).
- CRDT character-level merge (chose LWW + conflict copy).
- **Sync while the mobile app is closed** — not achievable in Obsidian's plugin
  model. Would require a separate companion app outside Obsidian. Excluded; the
  mobile guarantee is reliable catch-up on open + no data loss.
