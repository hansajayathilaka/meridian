<!-- Source: Phase-12 planning architect consult (T11). -->
> **Nav:** [ADR index](./README.md) · [system design §6](../architecture/system-design.md#6-per-platform-client-strategy) ·
> [data-model.md §2](../architecture/data-model.md#2-client-local-store-encrypted-via-secretstore-key) ·
> precedent [ADR 0021](./0021-client-local-store-config-formats.md) (terminal client, same sealing intent, different substrate)

# ADR 0026: Browser client-local store — WebCrypto non-extractable keys + IndexedDB sealing

**Scope-corrected by [ADR 0028](./0028-async-secretstore-bridge.md):** Decision B's "zero trait changes"
claim below is factually wrong — `SecretStore`'s sync trait cannot genuinely reach `crypto.subtle`'s
Promise-only API — see ADR 0028 for the async bridge this actually requires. The backing choice itself
(`WebCryptoSecretStore` via non-extractable `CryptoKey`s) is unaffected and remains binding.

**Options — `SecretStore` backing for the account/device keys:** (A) derive a raw seed and hand it to
a WASM-side `FileSecretStore`-style at-rest wrapper (mirrors the headless CLI); (B) **a new
`WebCryptoSecretStore` impl backed by non-extractable `CryptoKey`s via `crypto.subtle`, imported once
at account creation and never read back as raw bytes (chosen)**; (C) keep the seed in WASM linear
memory for the session only, no persistence.

**Trade-offs.** A throws away the one genuinely new security property the browser platform offers —
WebCrypto's `extractable: false` import — leaving `SecretStore::nonextractable()` report `false` for
the browser exactly as it already does for `OsSecretStore` (`apps/store/src/os.rs`'s own honest
caveat), a worse posture than necessary. C loses the account across page reloads, failing T11's own
acceptance criterion ("browser refresh restores sessions from IndexedDB"). B is implementable against
the existing `SecretStore` trait with **zero trait changes**: `store()` imports the given raw seed via
`SubtleCrypto.importKey('raw', ..., extractable: false, ...)` and discards the JS reference to the raw
bytes afterward; `use_key`/`derive_key` compute results (`sign`/`deriveBits` for HKDF) via
`crypto.subtle`'s non-extractable-key operations, which return only the computed output, never the key
material — this already matches the trait's existing contract (`use_key`/`derive_key` return *computed*
results, not the raw secret). **Decision: B.** `nonextractable()` returns `true` for this impl — the
first `SecretStore` in the tree that can honestly claim it.

**Options — at-rest sealing of `contacts/`, `history/`, `outbox/`, `sessions/` (mirroring ADR 0021's
sealing boundary):** (A) **reuse `meridian_crypto::at_rest::seal` (XChaCha20-Poly1305) compiled to
WASM, fed by a derived, extractable 32-byte sealing key (`SecretStore::derive_key`, itself computed via
a non-extractable-key HKDF operation whose *output* is extractable bits — the base account key stays
non-extractable throughout; only the derived per-purpose sealing key ever exists as raw bytes in WASM
memory) — same AEAD, same `at_rest` module, same code path as `sessions.bin` and ADR 0021's TUI store
use today (chosen)**; (B) use WebCrypto's native AES-GCM instead, bypassing `meridian-crypto::at_rest`
entirely.

**Trade-offs.** B forks the sealing primitive per platform for no protocol benefit — `data-model.md`
§2 already treats each client's at-rest encoding as client-local, so there is no cross-client
sealed-blob compatibility requirement to preserve — and adds a second AEAD implementation to review,
against the "never bespoke, one audited path" posture ([crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md))
even though AES-GCM itself is fine in isolation. A reuses code already shipped and reviewed (ADR 0021,
task 4.2); WASM builds of the RustCrypto primitives `meridian-crypto` composes are a known-good,
already-relied-upon story (`stack.md` §1: "compiles to WASM" is `meridian-core`'s whole raison d'être).
**Decision: A** — the derived-key/extractable-output split above is what makes this possible without
ever making the account key itself extractable.

**Container:** one IndexedDB object store per ADR-0021-style bucket (`identity`, `sessions`,
`contacts`, `history`, `outbox`), each record `at_rest::seal`-wrapped. Same schema-versioning discipline
as ADR 0021 condition 5: every record carries a top-level `"v"` field, migrates forward on a version
bump, and **refuses to open a record whose version is newer than the running build understands** —
fail closed, never silently discarding unknown fields. Same condition-5b posture: an AEAD
authentication failure on any sealed record is a hard, fail-closed error, never a silent
reinitialize-to-empty (this matters identically here — a browser-side `contacts`'s pinned-key history
defeats the same server key-substitution attack ADR 0021 condition 5b names).

**Options — `config`/`state`-equivalent (ADR 0021's two unsealed exceptions):** (A) carry the same
split — a small, non-identifying UI-state IndexedDB record stays unsealed (view geometry, opaque
conversation handles only, same condition-2-style content restriction: no petname, message body, key
material, or contact-identifying content); org-pushed config defaults stay a plain (non-secret) blob;
no TOML/`figment` equivalent, since there is no filesystem to hand-edit in a browser sandbox (**chosen**);
(B) invent a browser-side settings-file analog anyway.

**Trade-offs.** B has no real user to serve — nothing in a browser sandbox is hand-edited the way
`config.toml` is — and would just be a second config-loading path to maintain for no benefit. A is the
honest, minimal carry-over of ADR 0021's intent, with the config-format condition explicitly and
deliberately dropped (not silently missed) because its premise (a human-editable file on disk) doesn't
hold in this substrate. **Decision: A.**

## Binding conditions

1. **`WebCryptoSecretStore`** (new, browser-only `SecretStore` impl) imports the account seed as a
   non-extractable `CryptoKey` at account creation; no code path may export or log the raw seed after
   import. `derive_key` outputs (used only as at-rest sealing keys, never persisted) are the sole
   extractable byte material this store ever produces.
2. **Sealing** of `identity`/`sessions`/`contacts`/`history`/`outbox` IndexedDB records uses
   `meridian_crypto::at_rest::seal`/`open` unmodified (compiled to WASM), keyed by a `derive_key`
   output with a purpose-specific `info` string, mirroring `STORE_KEY_INFO`'s existing pattern.
3. **Schema versioning and fail-closed behavior** match ADR 0021 conditions 5 and 5b exactly, applied
   per IndexedDB record instead of per file.
4. **`state`-equivalent record** carries only view geometry and opaque, locally-generated conversation
   handles — the same content restriction as ADR 0021 condition 2, enforced the same way (a browser-side
   equivalent of the 4.27 at-rest-audit harness scans it for petname/body/key/contact-identifier-shaped
   content).
5. **No config-file equivalent.** Browser-side settings (if any) are either compiled-in defaults, an
   org-pushed non-secret config blob fetched at load time, or per-user UI preferences in the unsealed
   `state`-equivalent record subject to condition 4's restriction — never a hand-edited file.

## Accepted residual risk

**R1 — IndexedDB storage is subject to browser eviction policy** (e.g. Safari's 7-day ITP cap on
script-writable storage in some configurations, or a user clearing site data) in a way a native
filesystem or OS keychain is not. This is a browser-platform constraint, not a Meridian design gap —
consistent with `system-design.md` §6's own honest caveat that "a web app is only as trustworthy as its
served JS." No mitigation beyond documenting it in the web-deployment guide (T11 deliverable 3); a
future Storage Access API / persistent-storage permission request is optional follow-up, not required
by this ADR.

## Consequence

Binds a new `meridian-wasm`-or-`apps/store`-side WASM-gated `store` module and the IndexedDB schema
T11's browser store task implements directly — no alternative sealing scheme or extractability story
may be introduced without amending this ADR, the same posture ADR 0021 takes for the terminal client.
