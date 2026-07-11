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
1. `meridian-identity` crate, ≥90% branch coverage on encode/parse (property tests: round-trip, checksum corruption, homoglyph domain rejection).
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

## Risks / notes
Freeze the multicodec prefix and checksum length now — this string ends up on business cards; changing it later is a user-facing migration. Keep the crate `no_std`-friendly where feasible for future embedded use.
