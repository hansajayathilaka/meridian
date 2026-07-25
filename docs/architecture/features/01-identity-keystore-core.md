<!-- Source: tasks/T01-identity-keystore-core.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T01 — Identity & Keystore Core

**Priority:** P0 (first task — everything downstream consumes this) · **Design refs:** §3.1, §4.1, ADR-1 · **Depends on:** none · **Indicative effort:** 1–2 eng-weeks

## Goal
Implement the self-certifying identity layer as a standalone Rust crate (`meridian-identity`) plus a CLI that exercises it, so the ID format, key handling, and signature semantics are frozen and testable before any networking exists.

## Scope
In: Ed25519 account keygen; `mrd1:<base32(multicodec‖pubkey‖crc)>@domain` encode/parse/validate (checksum, canonical form, hint extraction); detached sign/verify API used by every later envelope; `SecretStore` trait with two impls — OS keystore (DPAPI/Keychain via `keyring`) and passphrase-wrapped file (age/scrypt) for headless; QR encode/decode of IDs; test vectors published as JSON (these become the cross-platform conformance fixtures for T11/T12).
Out: prekeys (T02), device subkeys (T13), any I/O beyond local disk.

## Deliverables
1. `meridian-identity` crate, well-covered encode/parse (property tests: round-trip, checksum corruption, homoglyph domain rejection) — measured, see "Coverage" below.
2. `meridian id` CLI subcommands: `new`, `show [--qr]`, `parse <id>`, `sign <file>`, `verify <file> <sig> <id>`, `export/import` (encrypted).
3. `test-vectors/identity-v1.json` — canonical fixtures.
4. Doc: `identity-format.md` — the wire-frozen spec (versioned; PQ slot noted per §4.2).

## Working output (demo script)
```
$ meridian id new --store file --out alice.key        # prompts passphrase
Created mrd1:kq3f…x9dm@chat.example
$ meridian id show --qr                               # scannable QR in terminal
$ echo "hello" > m.txt && meridian id sign m.txt > m.sig
$ meridian id verify m.txt m.sig mrd1:kq3f…x9dm@chat.example   # → OK
$ meridian id parse mrd1:WRONGCHECKSUM@x               # → error: checksum mismatch
```

## Acceptance criteria
Round-trip on 10⁶ fuzzed IDs; a flipped bit anywhere in the key part is rejected; the same key with two different `@hints` compares as the *same principal* in the API; keys created with `--store os` never appear on disk in plaintext (verified by test harness). 

### Coverage (F22 / task 1.21)
The original deliverable named "**≥90% branch coverage**". That figure was unmeasurable, and not only
because the project had no coverage tooling: **Rust on stable emits no branch-coverage data at all** —
`cargo llvm-cov`'s Branches column is empty (`0 / 0 / -`) on the toolchain this repo pins in
`rust-toolchain.toml`. Branch coverage needs a nightly `-Z coverage-options=branch` build. So the metric
itself was unachievable, independent of effort.

Resolution: the tooling now exists and the number is measured rather than asserted.

```
just coverage          # cargo llvm-cov --workspace --summary-only
just coverage-html     # drill into uncovered lines
```

CI runs it as a **non-blocking, measurement-only** job (`coverage` in `.github/workflows/ci.yml`,
`continue-on-error: true`, no threshold) and uploads an lcov artifact. Gating on a threshold is a
separate, later decision — deliberately not made here.

**Measured (region / line, `cargo llvm-cov`):** `meridian-identity`'s `id.rs` — the encode/parse code
this criterion is actually about — is **91.58% region, 88.71% line** under the crate's own property
tests. Workspace-wide is **75.98% region, 78.96% line**. The crate's `keys.rs` and `qr.rs` show 0% in a
crate-scoped run because their exercise comes from CLI-level tests, so read the workspace number, not
the per-crate one, for those.

## Risks / notes
Freeze the multicodec prefix and checksum length now — this string ends up on business cards; changing it later is a user-facing migration. Keep the crate `no_std`-friendly where feasible for future embedded use.
