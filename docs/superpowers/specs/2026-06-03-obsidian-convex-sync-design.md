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
| Backend | Convex Cloud, contents stored plaintext (user trusts Convex) |
| Platforms | Desktop (Electron) + mobile (webview); desktop-first |
| Conflicts | Last-write-wins + conflict-copy file (no silent data loss) |
| Sync scope | Notes + attachments; optional `.obsidian` allowlist |
| Auth | Sync key (shared secret, no accounts) |
| Note storage | Uniform content-defined chunking for all note sizes |
| Attachment storage | Convex file storage (one blob per attachment) |

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

```
files
  workspaceId    string        // scope, derived from sync key
  fileId         string        // STABLE id; path is mutable
  path           string        // current vault-relative path
  type           "note" | "attachment" | "config"
  hash           string        // content hash of the whole file
  size           number
  mtime          number
  deleted        boolean       // tombstone
  version        number        // monotonic per workspace; feed cursor
  contentChunks  string[]?     // ordered chunk hashes (notes/config text)
  storageId      string?       // Convex file-storage id (attachments)
  index by (workspaceId, version)   // reactive change-feed
  index by (workspaceId, path)      // path lookup
  index by (workspaceId, fileId)    // stable-id lookup

chunks
  workspaceId    string
  hash           string        // content hash of the chunk; dedup key
  text           string        // chunk body (bounded < 1 MiB by chunker)
  index by (workspaceId, hash)

counters
  workspaceId    string
  version        number        // bumped on every write to assign next version
```

Keying files by stable `fileId` (path as a mutable attribute) means a
rename/move is **one metadata update**, and version/conflict history survives
the move. Obsidian hands the plugin both old and new path on rename → map to the
existing `fileId`.

### Note storage — uniform content-defined chunking

Every note (and any allowlisted `.obsidian` text file), **regardless of size**,
runs through one path:

1. Split with a **rolling-hash / FastCDC-style** chunker → content-defined
   boundaries, each chunk bounded well under 1 MiB.
2. Hash each chunk; store in `chunks` deduped by hash (skip chunks already
   present).
3. The `files` row holds the ordered list of chunk hashes in `contentChunks`.

Consequences:
- A 1-char edit re-chunks locally but only the chunk(s) around the edit get new
  hashes → **upload is ~one chunk, not the whole file**.
- Tiny note = one chunk. No size special-case, one code path.
- Shared boilerplate/templates across notes dedup to the same chunks.

### Attachment storage — Convex file storage

Binary attachments go to Convex file storage as a single blob; the `files` row
references it via `storageId`. *Not* chunked into DB rows — that would bloat the
document store and forfeit the cheaper 1 GB blob tier and direct URL serving.
Attachments are typically replaced wholesale, so file-level hash dedup is
enough. (obsidian-livesync chunks binaries because CouchDB has no blob tier; we
have one.)

## Sync engine (plugin)

### Push (local → remote)

Vault event (`create`/`modify`/`delete`/`rename`) → debounce (~1–2 s after the
last save) → hash content → compare to sync-state:
- **Note changed:** chunk → upload missing chunks → mutation updates the `files`
  row (`contentChunks`, hash, mtime) and bumps `version`.
- **Attachment changed:** request upload URL → `storage.store` → mutation sets
  `storageId` + hash, bumps `version`.
- Update local sync-state with the new hash and version.

### Pull (remote → local)

Reactive **paginated** query on `files where workspaceId = mine AND version >
lastSeen`, ordered by `version`:
- For each changed row, if remote hash ≠ local sync-state hash → fetch content
  (chunk rows by hash, or storage URL for attachments) → write to vault →
  advance the cursor and sync-state.
- **Delete** (tombstone) → move local file to system trash.
- **Rename** → move local file, matched by `fileId`.

### Conflict resolution (LWW + conflict copy)

Before applying a remote change, if the local file *also* changed since the last
synced version (local hash ≠ sync-state hash **and** remote version > synced
version):
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

## Auth / scoping (sync key)

- User generates one sync key, stores the matching secret as a Convex env var
  and a `workspaceId`. Pastes deployment URL + sync key into the plugin settings
  on each device.
- Every function does a constant-time compare of the supplied key against the
  stored secret and scopes all reads/writes to the workspace. Invalid key →
  reject.
- **Security:** the sync key grants full read/write to the workspace's plaintext
  notes. Treat it like a password. No per-device revocation (rotate the key to
  cut off all devices). Documented as an accepted single-user tradeoff.

## Mobile behavior

- **Foreground-only sync:** subscribe on plugin load / app foreground; flush
  pending pushes on background/unload. Obsidian suspends plugins in the
  background, so continuous background sync is **not** promised — stated
  expectation, not a bug.
- **Lazy attachment download** (opt-in): don't pull large media until a note
  referencing it is opened, to save mobile bandwidth/storage.

## Limits surfaced to the user

- Chunker keeps every chunk under the 1 MiB doc cap automatically.
- Attachments count against the **1 GB free-tier** file storage → show a usage
  indicator and warn as it fills.
- Content is fetched only on hash change, to limit egress.

## Settings UI

- Convex deployment URL, sync key, workspace name.
- `.obsidian` allowlist (which config files to sync).
- Lazy-attachment toggle.
- Status indicator: synced / syncing / error + last-sync time.
- Force-full-resync button.

## Error handling

- **Offline:** queue pushes locally with backoff retry; the reactive query
  auto-reconnects.
- **Failed upload:** mark the path dirty in sync-state, retry.
- **Oversized / corrupt file:** skip + notify, never crash the sync loop.
- **Stale version:** conflict copy, never lose data.

## Testing

- **Unit:** chunker boundaries + dedup, hash/diff, conflict decisions,
  `fileId`↔path mapping, sync-state transitions.
- **Integration:** two simulated clients against a Convex dev deployment —
  concurrent edit, offline→online, rename, delete, attachment upload,
  conflict-copy creation, cold start with a pre-populated remote.
- **Manual:** a real desktop + mobile device pair.

## Reference

`obsidian-livesync` (CouchDB/PouchDB-based) solved this same problem; borrow its
content-defined chunking and conflict patterns. Its design validates the
metadata/content split. Key divergence: we use Convex file storage for binaries
instead of chunking them into the database.

## Out of scope (YAGNI)

- Multi-user / collaboration / sharing.
- End-to-end encryption (chose plaintext).
- Real auth accounts / per-device revocation (chose sync key).
- CRDT character-level merge (chose LWW + conflict copy).
- Guaranteed mobile background sync.
