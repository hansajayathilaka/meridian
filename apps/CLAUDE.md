# CLAUDE.md — apps/ (application code)

Scoped memory for the application crates and clients. Inherits the root
[CLAUDE.md](../CLAUDE.md); this adds app-local rules.

## Contents
Rust workspace crates (each has its own scoped `CLAUDE.md` where the rules are sharpest):
- `proto/` — `meridian-proto`: shared wire types (envelopes, bundles, ctrl/signal). The **only** crate
  the server depends on. `OpaqueBlob` encodes the payloads-stay-opaque invariant.
- `core/` — `meridian-core` facade. Public API canonical in
  [docs/api/core-api-contracts.md](../docs/api/core-api-contracts.md).
- `identity/` — `meridian-identity`: `mrd1:` IDs, keys, QR (wire-critical, conformance-vectored).
- `store/` — `meridian-store`: `SecretStore`, encrypted at rest.
- `crypto/` — `meridian-crypto`: X3DH + Double Ratchet (composed from RustCrypto primitives, ADR 0015),
  fingerprints, at-rest. Never bespoke.
- `transport/` — `meridian-transport`: `Transport` trait, WebRTC data channels, ICE/relay.
- `signaling/` — `meridian-signaling`: session signaling frames.
- `cli/` — `meridian-cli`: terminal client; the reference client and demo driver.
- `rendezvous/` — `meridian-rendezvous` (axum + sqlx): the signaling server. **Only** depends on `meridian-proto`.
- `web/` — browser client (SvelteKit + WASM core).

Real crate layout and dependency direction: [docs/architecture/stack.md](../docs/architecture/stack.md)
and the [core-modules diagram](../docs/architecture/diagrams/core-modules.mermaid).

## App-local rules
- **`rendezvous/` must not depend on `meridian-core`** — only on `meridian-proto` (shared wire types).
  This keeps session/ratchet code out of the server. Enforced conceptually by the
  [architect](../.claude/agents/architect.md) subagent.
- **All wire types come from `meridian-proto`.** Don't redefine envelope/bundle/ctrl shapes; follow the
  [api-contracts skill](../.claude/skills/api-contracts/SKILL.md).
- **Additive stream types** register via the stream registry only — no core edits.
- **Adversarial-input mindset:** every byte off the wire is hostile; verify signatures before
  deserializing payloads.
- Match each feature's acceptance demo in
  [docs/architecture/features/](../docs/architecture/features/).
