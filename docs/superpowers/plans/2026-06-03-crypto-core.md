# Crypto Core Implementation Plan (Plan 1 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the pure-TypeScript crypto + chunking library that the Obsidian↔Convex sync plugin depends on — content-defined chunking, AES-GCM content/path encryption, HMAC dedup ids, and passphrase-based envelope key management (wrap/unwrap, recovery key, passphrase rotation).

**Architecture:** A standalone `src/crypto/` module with no Obsidian or Convex imports, so it runs and tests entirely under Node/Vitest using WebCrypto (`globalThis.crypto.subtle`). Envelope encryption: a random Data Encryption Key (DEK) is wrapped by a passphrase-derived Key Encryption Key (KEK); content/path keys (`encKey`, `macKey`) are HKDF-derived from the DEK. This isolates the highest-risk subsystem and validates the Argon2id-in-webview spike before any consumer exists.

**Tech Stack:** TypeScript, Vitest, WebCrypto (`SubtleCrypto`), `hash-wasm` (Argon2id), FastCDC (implemented here).

**Spec:** `docs/superpowers/specs/2026-06-03-obsidian-convex-sync-design.md` — see the *Encryption (E2E)* and *Note storage* sections.

---

## File Structure (this plan)

```
package.json                 # deps + scripts (created Task 0)
tsconfig.json                # strict TS config
vitest.config.ts             # test runner config
src/crypto/
  bytes.ts                   # base64 / hex / utf8 encode-decode helpers
  aesgcm.ts                  # AES-GCM encrypt/decrypt + Ciphertext serialize
  hkdf.ts                    # DEK -> { encKey, macKey } via HKDF-SHA256
  hmacId.ts                  # deterministic HMAC id (chunkId, pathId)
  kdf.ts                     # passphrase + salt -> KEK (argon2id | pbkdf2)
  envelope.ts                # DEK lifecycle: bootstrap/unlock/recovery/rotate
  chunker.ts                 # FastCDC content-defined chunking
  index.ts                   # public re-exports
tests/crypto/
  aesgcm.test.ts
  hkdf.test.ts
  hmacId.test.ts
  kdf.test.ts
  envelope.test.ts
  chunker.test.ts
```

**Responsibilities (one per file):**
- `bytes.ts` — encoding only; no crypto. Every other file uses it for string↔bytes.
- `aesgcm.ts` — symmetric encryption primitive + a storable `{nonce, data}` shape.
- `hkdf.ts` — turns a DEK into the two working keys.
- `hmacId.ts` — turns plaintext into a deterministic opaque id for dedup/lookup.
- `kdf.ts` — the load-bearing passphrase→key step; pluggable algorithm.
- `envelope.ts` — orchestrates DEK + KEK: bootstrap, unlock, recovery, rotation.
- `chunker.ts` — splits plaintext on content-defined boundaries.

---

## Task 0: Project scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "obsidian-convex-sync",
  "version": "0.0.1",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "typescript": "^5.4.0",
    "vitest": "^1.6.0",
    "@types/node": "^20.12.0"
  },
  "dependencies": {
    "hash-wasm": "^4.11.0"
  }
}
```

- [ ] **Step 2: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "types": ["node"]
  },
  "include": ["src", "tests"]
}
```

- [ ] **Step 3: Create `vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
```

- [ ] **Step 4: Install and verify the toolchain**

Run: `npm install && npx vitest run`
Expected: install succeeds; vitest reports "No test files found" (exit 0 or the "no tests" notice — no compile errors).

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json vitest.config.ts package-lock.json
git commit -m "chore: scaffold TS + vitest toolchain for crypto core"
```

---

## Task 1: Byte encoding helpers

**Files:**
- Create: `src/crypto/bytes.ts`
- Test: `tests/crypto/aesgcm.test.ts` (encoding is exercised indirectly; add a focused test here)
- Test: `tests/crypto/bytes.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/bytes.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { utf8ToBytes, bytesToUtf8, bytesToBase64, base64ToBytes, bytesToHex } from "../../src/crypto/bytes";

describe("bytes", () => {
  it("round-trips utf8", () => {
    const s = "héllo 世界";
    expect(bytesToUtf8(utf8ToBytes(s))).toBe(s);
  });

  it("round-trips base64", () => {
    const b = new Uint8Array([0, 1, 2, 250, 255]);
    expect(base64ToBytes(bytesToBase64(b))).toEqual(b);
  });

  it("hex is lowercase and fixed width", () => {
    expect(bytesToHex(new Uint8Array([0, 15, 255]))).toBe("000fff");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/bytes.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/bytes`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/bytes.ts`:

```ts
export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesToBase64(b: Uint8Array): string {
  let bin = "";
  for (const byte of b) bin += String.fromCharCode(byte);
  return btoa(bin);
}

export function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/bytes.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/bytes.ts tests/crypto/bytes.test.ts
git commit -m "feat(crypto): byte encoding helpers"
```

---

## Task 2: AES-GCM encrypt/decrypt

**Files:**
- Create: `src/crypto/aesgcm.ts`
- Test: `tests/crypto/aesgcm.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/aesgcm.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { importAesKey, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8, randomBytes } from "../../src/crypto/bytes";

describe("aesgcm", () => {
  it("encrypt then decrypt round-trips", async () => {
    const key = await importAesKey(randomBytes(32));
    const pt = utf8ToBytes("secret note body");
    const ct = await aesGcmEncrypt(key, pt);
    expect(bytesToUtf8(await aesGcmDecrypt(key, ct))).toBe("secret note body");
  });

  it("uses a fresh nonce each time (no reuse)", async () => {
    const key = await importAesKey(randomBytes(32));
    const pt = utf8ToBytes("same plaintext");
    const a = await aesGcmEncrypt(key, pt);
    const b = await aesGcmEncrypt(key, pt);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.data).not.toEqual(b.data);
  });

  it("tampered ciphertext fails to decrypt", async () => {
    const key = await importAesKey(randomBytes(32));
    const ct = await aesGcmEncrypt(key, utf8ToBytes("x"));
    ct.data[0] ^= 0xff;
    await expect(aesGcmDecrypt(key, ct)).rejects.toThrow();
  });

  it("serialize then deserialize round-trips", async () => {
    const key = await importAesKey(randomBytes(32));
    const ct = await aesGcmEncrypt(key, utf8ToBytes("store me"));
    const restored = deserializeCiphertext(serializeCiphertext(ct));
    expect(bytesToUtf8(await aesGcmDecrypt(key, restored))).toBe("store me");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/aesgcm.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/aesgcm`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/aesgcm.ts`:

```ts
import { randomBytes, bytesToBase64, base64ToBytes } from "./bytes";

export interface Ciphertext {
  nonce: Uint8Array; // 12 bytes
  data: Uint8Array; // ciphertext + 16-byte GCM tag
}

const NONCE_LEN = 12;

export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function aesGcmEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Ciphertext> {
  const nonce = randomBytes(NONCE_LEN);
  const buf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return { nonce, data: new Uint8Array(buf) };
}

export async function aesGcmDecrypt(key: CryptoKey, ct: Ciphertext): Promise<Uint8Array> {
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ct.nonce }, key, ct.data);
  return new Uint8Array(buf);
}

// Storage format: base64(nonce) + "." + base64(data)
export function serializeCiphertext(ct: Ciphertext): string {
  return `${bytesToBase64(ct.nonce)}.${bytesToBase64(ct.data)}`;
}

export function deserializeCiphertext(s: string): Ciphertext {
  const dot = s.indexOf(".");
  if (dot < 0) throw new Error("malformed ciphertext");
  return {
    nonce: base64ToBytes(s.slice(0, dot)),
    data: base64ToBytes(s.slice(dot + 1)),
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/aesgcm.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/aesgcm.ts tests/crypto/aesgcm.test.ts
git commit -m "feat(crypto): AES-GCM encrypt/decrypt with serialization"
```

---

## Task 3: HKDF subkey derivation

**Files:**
- Create: `src/crypto/hkdf.ts`
- Test: `tests/crypto/hkdf.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/hkdf.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { deriveSubkeys } from "../../src/crypto/hkdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8 } from "../../src/crypto/bytes";

describe("hkdf", () => {
  it("derives an encKey usable for AES-GCM", async () => {
    const dek = new Uint8Array(32).fill(7);
    const { encKey } = await deriveSubkeys(dek);
    const ct = await aesGcmEncrypt(encKey, utf8ToBytes("hi"));
    expect(bytesToUtf8(await aesGcmDecrypt(encKey, ct))).toBe("hi");
  });

  it("derives a macKey usable for HMAC signing", async () => {
    const dek = new Uint8Array(32).fill(7);
    const { macKey } = await deriveSubkeys(dek);
    const sig = await crypto.subtle.sign("HMAC", macKey, utf8ToBytes("x"));
    expect(new Uint8Array(sig).length).toBe(32);
  });

  it("is deterministic for the same DEK and divergent for different DEKs", async () => {
    const a = await deriveSubkeys(new Uint8Array(32).fill(1));
    const b = await deriveSubkeys(new Uint8Array(32).fill(1));
    const c = await deriveSubkeys(new Uint8Array(32).fill(2));
    const sign = (k: CryptoKey) => crypto.subtle.sign("HMAC", k, utf8ToBytes("m")).then((s) => new Uint8Array(s).join(","));
    expect(await sign(a.macKey)).toBe(await sign(b.macKey));
    expect(await sign(a.macKey)).not.toBe(await sign(c.macKey));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/hkdf.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/hkdf`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/hkdf.ts`:

```ts
import { utf8ToBytes } from "./bytes";

export interface Subkeys {
  encKey: CryptoKey; // AES-GCM
  macKey: CryptoKey; // HMAC-SHA256, sign only
}

// Fixed, non-secret salt for HKDF — the DEK is the secret input.
const HKDF_SALT = utf8ToBytes("obsidian-convex-sync/hkdf/v1");

export async function deriveSubkeys(dek: Uint8Array): Promise<Subkeys> {
  const base = await crypto.subtle.importKey("raw", dek, "HKDF", false, ["deriveKey"]);

  const encKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes("enc") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const macKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8ToBytes("mac") },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );

  return { encKey, macKey };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/hkdf.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/hkdf.ts tests/crypto/hkdf.test.ts
git commit -m "feat(crypto): HKDF derivation of encKey and macKey from DEK"
```

---

## Task 4: HMAC deterministic ids

**Files:**
- Create: `src/crypto/hmacId.ts`
- Test: `tests/crypto/hmacId.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/hmacId.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { deriveSubkeys } from "../../src/crypto/hkdf";
import { hmacId } from "../../src/crypto/hmacId";
import { utf8ToBytes } from "../../src/crypto/bytes";

describe("hmacId", () => {
  it("is deterministic: same input -> same id", async () => {
    const { macKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const a = await hmacId(macKey, utf8ToBytes("chunk body"));
    const b = await hmacId(macKey, utf8ToBytes("chunk body"));
    expect(a).toBe(b);
  });

  it("different input -> different id", async () => {
    const { macKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const a = await hmacId(macKey, utf8ToBytes("a"));
    const b = await hmacId(macKey, utf8ToBytes("b"));
    expect(a).not.toBe(b);
  });

  it("returns a 64-char lowercase hex string", async () => {
    const { macKey } = await deriveSubkeys(new Uint8Array(32).fill(3));
    const id = await hmacId(macKey, utf8ToBytes("x"));
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/hmacId.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/hmacId`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/hmacId.ts`:

```ts
import { bytesToHex } from "./bytes";

/**
 * Deterministic opaque id for dedup (chunkId) and lookup (pathId).
 * The server never holds macKey, so it cannot test guessed plaintext.
 */
export async function hmacId(macKey: CryptoKey, data: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", macKey, data);
  return bytesToHex(new Uint8Array(sig));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/hmacId.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/hmacId.ts tests/crypto/hmacId.test.ts
git commit -m "feat(crypto): deterministic HMAC ids for dedup and path lookup"
```

---

## Task 5: KDF (Argon2id spike + PBKDF2 fallback)

This is the load-bearing step — it is the only wall between a server-side adversary and plaintext. Implement both algorithms behind one interface; the consumer records which was used in `kdfParams`.

**Files:**
- Create: `src/crypto/kdf.ts`
- Test: `tests/crypto/kdf.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/kdf.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { deriveKek, defaultKdfParams, type KdfParams } from "../../src/crypto/kdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "../../src/crypto/aesgcm";
import { utf8ToBytes, bytesToUtf8 } from "../../src/crypto/bytes";

const salt = new Uint8Array(16).fill(9);
const pbkdf2: KdfParams = { algo: "pbkdf2", iterations: 600000 };
const argon2: KdfParams = { algo: "argon2id", iterations: 3, memoryKiB: 65536, parallelism: 1 };

describe("kdf", () => {
  it("pbkdf2: derives a wrapping key that round-trips AES-GCM", async () => {
    const kek = await deriveKek("correct horse", salt, pbkdf2);
    const ct = await aesGcmEncrypt(kek, utf8ToBytes("dek-bytes"));
    expect(bytesToUtf8(await aesGcmDecrypt(kek, ct))).toBe("dek-bytes");
  });

  it("pbkdf2: same passphrase+salt -> same key; different passphrase -> different", async () => {
    const k1 = await deriveKek("pw", salt, pbkdf2);
    const ct = await aesGcmEncrypt(k1, utf8ToBytes("m"));
    const k1b = await deriveKek("pw", salt, pbkdf2);
    await expect(aesGcmDecrypt(k1b, ct)).resolves.toBeDefined();
    const k2 = await deriveKek("other", salt, pbkdf2);
    await expect(aesGcmDecrypt(k2, ct)).rejects.toThrow();
  });

  it("argon2id: derives a usable wrapping key (webview-feasibility spike)", async () => {
    const kek = await deriveKek("correct horse", salt, argon2);
    const ct = await aesGcmEncrypt(kek, utf8ToBytes("dek-bytes"));
    expect(bytesToUtf8(await aesGcmDecrypt(kek, ct))).toBe("dek-bytes");
  });

  it("defaultKdfParams is argon2id", () => {
    expect(defaultKdfParams().algo).toBe("argon2id");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/kdf.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/kdf`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/kdf.ts`:

```ts
import { argon2id } from "hash-wasm";
import { importAesKey } from "./aesgcm";
import { utf8ToBytes } from "./bytes";

export type KdfParams =
  | { algo: "pbkdf2"; iterations: number }
  | { algo: "argon2id"; iterations: number; memoryKiB: number; parallelism: number };

export function defaultKdfParams(): KdfParams {
  // Argon2id is the target; tune cost during the spike on real mobile hardware.
  return { algo: "argon2id", iterations: 3, memoryKiB: 65536, parallelism: 1 };
}

export async function deriveKek(
  passphrase: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<CryptoKey> {
  const raw = await deriveRawKek(passphrase, salt, params);
  return importAesKey(raw);
}

async function deriveRawKek(passphrase: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  if (params.algo === "argon2id") {
    const hash = await argon2id({
      password: utf8ToBytes(passphrase),
      salt,
      iterations: params.iterations,
      memorySize: params.memoryKiB,
      parallelism: params.parallelism,
      hashLength: 32,
      outputType: "binary",
    });
    return hash as Uint8Array;
  }
  // pbkdf2 fallback (native WebCrypto)
  const base = await crypto.subtle.importKey("raw", utf8ToBytes(passphrase), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: "SHA-256" },
    base,
    256,
  );
  return new Uint8Array(bits);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/kdf.test.ts`
Expected: PASS (4 tests). If the argon2id test fails to load WASM under Node, record it — the spike's purpose is to surface that before mobile.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/kdf.ts tests/crypto/kdf.test.ts
git commit -m "feat(crypto): KDF with argon2id default and pbkdf2 fallback"
```

---

## Task 6: Envelope (DEK lifecycle)

Ties the pieces together: bootstrap a workspace's keys, unlock on another device, recover with a recovery code, rotate the passphrase. The DEK is wrapped, never stored raw.

**Files:**
- Create: `src/crypto/envelope.ts`
- Test: `tests/crypto/envelope.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/envelope.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { bootstrap, unlock, unlockWithRecovery, rewrapForNewPassphrase } from "../../src/crypto/envelope";
import { hmacId } from "../../src/crypto/hmacId";
import { utf8ToBytes } from "../../src/crypto/bytes";

const sameChunkId = async (a: { macKey: CryptoKey }, b: { macKey: CryptoKey }) => {
  const ia = await hmacId(a.macKey, utf8ToBytes("chunk"));
  const ib = await hmacId(b.macKey, utf8ToBytes("chunk"));
  return ia === ib;
};

describe("envelope", () => {
  it("bootstrap then unlock with the same passphrase yields the same working keys", async () => {
    const boot = await bootstrap("hunter2");
    const keys = await unlock("hunter2", boot.wrapped);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
  });

  it("wrong passphrase fails to unlock (GCM tag)", async () => {
    const boot = await bootstrap("hunter2");
    await expect(unlock("wrong", boot.wrapped)).rejects.toThrow();
  });

  it("recovery code recovers the same DEK", async () => {
    const boot = await bootstrap("hunter2");
    const keys = await unlockWithRecovery(boot.recovery.code, boot.recovery.recoveryWrap);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
  });

  it("passphrase rotation: new passphrase unlocks, old does not, keys unchanged", async () => {
    const boot = await bootstrap("old-pass");
    const rewrapped = await rewrapForNewPassphrase("new-pass", boot.wrapped, "old-pass");
    const keys = await unlock("new-pass", rewrapped);
    expect(await sameChunkId(boot.keys, keys)).toBe(true);
    await expect(unlock("old-pass", rewrapped)).rejects.toThrow();
  });

  it("bootstrap emits a sync key and its verifier hash", async () => {
    const boot = await bootstrap("hunter2");
    expect(boot.syncKey).toMatch(/^[0-9a-f]{64}$/);
    expect(boot.syncKeyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(boot.syncKeyHash).not.toBe(boot.syncKey);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/envelope.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/envelope`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/envelope.ts`:

```ts
import { randomBytes, bytesToBase64, base64ToBytes, bytesToHex, utf8ToBytes } from "./bytes";
import { importAesKey, aesGcmEncrypt, aesGcmDecrypt, serializeCiphertext, deserializeCiphertext } from "./aesgcm";
import { deriveKek, defaultKdfParams, type KdfParams } from "./kdf";
import { deriveSubkeys, type Subkeys } from "./hkdf";

/** Stored on the server in the `workspaces` row (all non-secret-at-rest). */
export interface WrappedDek {
  kdfSalt: string; // base64
  kdfParams: KdfParams;
  dekWrap: string; // serialized Ciphertext of the DEK under the KEK
}

export interface BootstrapResult {
  wrapped: WrappedDek;
  recovery: { code: string; recoveryWrap: string };
  keys: Subkeys;
  syncKey: string; // give to the user; paste on each device
  syncKeyHash: string; // store on server as the verifier
}

const RECOVERY_SALT = utf8ToBytes("obsidian-convex-sync/recovery/v1");

async function deriveSubkeysAndWrap(passphrase: string, dek: Uint8Array, params: KdfParams, salt: Uint8Array): Promise<WrappedDek> {
  const kek = await deriveKek(passphrase, salt, params);
  const dekWrap = serializeCiphertext(await aesGcmEncrypt(kek, dek));
  return { kdfSalt: bytesToBase64(salt), kdfParams: params, dekWrap };
}

async function unwrapDek(passphrase: string, wrapped: WrappedDek): Promise<Uint8Array> {
  const kek = await deriveKek(passphrase, base64ToBytes(wrapped.kdfSalt), wrapped.kdfParams);
  return aesGcmDecrypt(kek, deserializeCiphertext(wrapped.dekWrap)); // throws on wrong passphrase
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

export async function bootstrap(passphrase: string): Promise<BootstrapResult> {
  const dek = randomBytes(32);
  const params = defaultKdfParams();
  const salt = randomBytes(16);
  const wrapped = await deriveSubkeysAndWrap(passphrase, dek, params, salt);

  // Recovery: wrap the same DEK under a key derived from a random recovery code.
  const code = bytesToHex(randomBytes(16)); // 32-char recovery code, shown once
  const recoveryKek = await importAesKey(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...RECOVERY_SALT, ...utf8ToBytes(code)]))),
  );
  const recoveryWrap = serializeCiphertext(await aesGcmEncrypt(recoveryKek, dek));

  const syncKey = bytesToHex(randomBytes(32));
  const syncKeyHash = await sha256Hex(utf8ToBytes(syncKey));

  return {
    wrapped,
    recovery: { code, recoveryWrap },
    keys: await deriveSubkeys(dek),
    syncKey,
    syncKeyHash,
  };
}

export async function unlock(passphrase: string, wrapped: WrappedDek): Promise<Subkeys> {
  return deriveSubkeys(await unwrapDek(passphrase, wrapped));
}

export async function unlockWithRecovery(code: string, recoveryWrap: string): Promise<Subkeys> {
  const recoveryKek = await importAesKey(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...RECOVERY_SALT, ...utf8ToBytes(code)]))),
  );
  const dek = await aesGcmDecrypt(recoveryKek, deserializeCiphertext(recoveryWrap));
  return deriveSubkeys(dek);
}

export async function rewrapForNewPassphrase(
  newPassphrase: string,
  wrapped: WrappedDek,
  oldPassphrase: string,
): Promise<WrappedDek> {
  const dek = await unwrapDek(oldPassphrase, wrapped); // verifies old passphrase
  const params = defaultKdfParams();
  const salt = randomBytes(16);
  return deriveSubkeysAndWrap(newPassphrase, dek, params, salt);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/envelope.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/envelope.ts tests/crypto/envelope.test.ts
git commit -m "feat(crypto): envelope DEK lifecycle — bootstrap, unlock, recovery, rotation"
```

---

## Task 7: FastCDC content-defined chunker

Splits plaintext on content-defined boundaries so a local edit re-uploads only nearby chunks. Implemented with a gear-hash rolling function and min/avg/max bounds.

**Files:**
- Create: `src/crypto/chunker.ts`
- Test: `tests/crypto/chunker.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/crypto/chunker.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { chunk, CHUNK_MIN, CHUNK_MAX } from "../../src/crypto/chunker";
import { randomBytes } from "../../src/crypto/bytes";

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

describe("chunker", () => {
  it("reassembles to the original bytes", () => {
    const data = randomBytes(200_000);
    expect(concat(chunk(data))).toEqual(data);
  });

  it("small input is a single chunk", () => {
    const data = randomBytes(100);
    expect(chunk(data).length).toBe(1);
  });

  it("respects min/max bounds (except the final chunk may be short)", () => {
    const data = randomBytes(300_000);
    const chunks = chunk(data);
    chunks.slice(0, -1).forEach((c) => {
      expect(c.length).toBeGreaterThanOrEqual(CHUNK_MIN);
      expect(c.length).toBeLessThanOrEqual(CHUNK_MAX);
    });
  });

  it("is deterministic", () => {
    const data = randomBytes(150_000);
    const a = chunk(data).map((c) => c.length);
    const b = chunk(data).map((c) => c.length);
    expect(a).toEqual(b);
  });

  it("an edit near the front leaves most later chunks unchanged (locality)", () => {
    const base = randomBytes(300_000);
    const edited = new Uint8Array(base);
    edited.set(randomBytes(10), 50); // mutate 10 bytes near the front
    const join = (cs: Uint8Array[]) => cs.map((c) => Array.from(c).join(","));
    const a = join(chunk(base));
    const b = join(chunk(edited));
    const shared = a.filter((c) => b.includes(c)).length;
    // Most chunks past the edit point should be byte-identical.
    expect(shared).toBeGreaterThan(a.length / 2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/crypto/chunker.test.ts`
Expected: FAIL — cannot find module `../../src/crypto/chunker`.

- [ ] **Step 3: Write minimal implementation**

Create `src/crypto/chunker.ts`:

```ts
// FastCDC-style content-defined chunking with a gear hash.
// Bounds chosen so each plaintext chunk's ciphertext stays well under Convex's 1 MiB doc cap.
export const CHUNK_MIN = 16 * 1024; // 16 KiB
export const CHUNK_AVG = 64 * 1024; // 64 KiB target
export const CHUNK_MAX = 256 * 1024; // 256 KiB

// Mask with ~log2(CHUNK_AVG) one-bits → boundary roughly every CHUNK_AVG bytes.
const MASK = 0xffff; // 16 one-bits ≈ 64 KiB average

// Deterministic 256-entry gear table (fixed seed, no randomness).
const GEAR = buildGear();
function buildGear(): Uint32Array {
  const g = new Uint32Array(256);
  let x = 0x9e3779b1 >>> 0; // fixed seed
  for (let i = 0; i < 256; i++) {
    // xorshift32 — deterministic
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    g[i] = x >>> 0;
  }
  return g;
}

function nextBoundary(data: Uint8Array, start: number): number {
  const end = Math.min(start + CHUNK_MAX, data.length);
  let hash = 0;
  let i = start;
  const minEnd = Math.min(start + CHUNK_MIN, data.length);
  // Skip the minimum region (no boundary allowed before CHUNK_MIN).
  for (; i < minEnd; i++) {
    hash = ((hash << 1) + GEAR[data[i]!]!) >>> 0;
  }
  for (; i < end; i++) {
    hash = ((hash << 1) + GEAR[data[i]!]!) >>> 0;
    if ((hash & MASK) === 0) return i + 1; // boundary
  }
  return end; // hit CHUNK_MAX or end of data
}

export function chunk(data: Uint8Array): Uint8Array[] {
  if (data.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array[] = [];
  let pos = 0;
  while (pos < data.length) {
    const next = nextBoundary(data, pos);
    out.push(data.subarray(pos, next));
    pos = next;
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/crypto/chunker.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/chunker.ts tests/crypto/chunker.test.ts
git commit -m "feat(crypto): FastCDC content-defined chunker"
```

---

## Task 8: Public surface + full suite + typecheck

**Files:**
- Create: `src/crypto/index.ts`

- [ ] **Step 1: Write the public re-export barrel**

Create `src/crypto/index.ts`:

```ts
export * from "./bytes";
export * from "./aesgcm";
export * from "./hkdf";
export * from "./hmacId";
export * from "./kdf";
export * from "./envelope";
export * from "./chunker";
```

- [ ] **Step 2: Run the full test suite**

Run: `npm test`
Expected: PASS — all crypto test files green.

- [ ] **Step 3: Typecheck the whole module**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/crypto/index.ts
git commit -m "feat(crypto): public crypto-core barrel; full suite green"
```

---

## Done criteria for Plan 1

- `npm test` and `npm run typecheck` both pass.
- Envelope round-trips: bootstrap → unlock → recover → rotate, with wrong-passphrase rejection.
- Chunker reassembles exactly, respects bounds, and demonstrates edit-locality.
- Argon2id-under-Node feasibility recorded (input to the mobile-webview spike in Plan 4). If Argon2id is infeasible on mobile, the consumer switches `defaultKdfParams()` to pbkdf2 — no API change.

**Next:** Plan 2 (Convex backend) consumes `chunkId`/`pathId` ids and serialized ciphertext from this module. The crypto API surface above (`bootstrap`, `unlock`, `deriveSubkeys`, `hmacId`, `chunk`, `serializeCiphertext`) is the contract Plans 2–4 build against.
