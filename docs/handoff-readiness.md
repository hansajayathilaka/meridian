# Handoff Readiness — Decisions Log

<!-- Every item raised in the pre-handoff review, decided, with pros/cons and where it landed.
     Architecture decisions became ADRs; process/scaffold decisions are recorded here. -->
> **Nav:** [docs index](./INDEX.md) · [ADRs](./adr/README.md) · [CONTRIBUTING](../CONTRIBUTING.md)

This log makes the scaffold Claude-Code-ready: the two open architectural decisions are resolved, the
workspace builds and enforces its own invariants, and the missing agents/skills/commands/docs exist.

## A. Architectural decisions (now resolved → ADRs)

### D1 — Ratchet library → **vodozemac + hand-wired X3DH** ([ADR 0011](./adr/0011-ratchet-library.md))
- **Options:** libsignal-client (A) · vodozemac + thin X3DH (B) · RustCrypto assembly (C).
- **Pros of B:** Apache-2.0 (libsignal is AGPL — copyleft across a self-hostable, redistributed
  product); library built for embedding; clean wasm32/aarch64 builds; independently audited.
- **Cons of B (mitigated):** X3DH wired ourselves (small, well-specified, own vectors + external review);
  less brand-name battle-testing than libsignal (but production-proven in Matrix); header-encryption +
  PQ slot confirmed via one time-boxed spike.
- **Why this fits the end goal:** an org can deploy and modify Meridian without AGPL legal review. This
  was the deciding factor.

### D2 — Real-time media stack → **libwebrtc for media, webrtc-rs for data** ([ADR 0014](./adr/0014-media-stack.md))
- **Options:** pure webrtc-rs + build audio 3A (A) · all-libwebrtc (B) · hybrid split at the media
  boundary (C).
- **Pros of C:** ships a good call experience now (AEC/AGC/NS, NetEQ, hardware codecs) instead of a
  multi-quarter media port; data plane stays pure-Rust and identical on all five targets; the
  `Transport` trait already hides the split; mobile needs libwebrtc anyway, so we pay once.
- **Cons of C (mitigated):** heavy C++ dep (confined to `meridian-media-sys`, vendored prebuilt);
  two transports (they meet only at the trait); no CLI video (already the design's position).

## B. Blocking-tier scaffolding (now done)

| Item | Decision | Landed in |
|------|----------|-----------|
| Open ADRs on the critical path | Resolved D1, D2 above | ADR 0011, 0014 |
| Workspace doesn't build | Added `rust-toolchain.toml`, **`meridian-proto`** crate, real `Justfile`, `xtask` crate; minimal-dep so it compiles | `Cargo.toml`, `apps/proto/`, `tools/xtask/`, `Justfile` |
| `meridian-proto` missing (server's only core dep) | Created; server & core depend on it; `OpaqueBlob` type encodes the "payloads stay opaque" invariant | `apps/proto/` |
| Security invariants unenforceable | Three CI lints + harness stubs, wired into CI and `just lint`/`just test` | `tools/lint-*.sh`, `harnesses/`, `.github/workflows/ci.yml` |
| Conformance vectors have no home | `test-vectors/` with placeholders + `xtask -- vectors` | `test-vectors/` |

**The three enforcement lints (real, run today):**
1. `lint-server-no-core` — `meridian-rendezvous` must not depend on `meridian-core` ([ADR 0008](./adr/0008-infra-topology.md)).
2. `lint-no-serde-on-blob` — no structured (de)serialization of opaque envelope payloads server-side
   ([anonymity model](./security/anonymity-and-retention.md) "must never" #1).
3. `lint-metrics-allowlist` — the server exports only allowlisted metrics ([monitoring](./operations/monitoring.md)).

## C. High-value additions (now done)

| Item | Decision & rationale | Landed in |
|------|----------------------|-----------|
| `crypto-protocols` skill | Crypto-heavy project; `api-contracts` covered the wire but not crypto discipline | `.claude/skills/crypto-protocols/` |
| `webrtc-nat-traversal` skill | WebRTC connectivity is the hardest debugging surface; encodes fingerprint/relay invariants | `.claude/skills/webrtc-nat-traversal/` |
| `stream-type-authoring` skill | The "ultimate sharing platform" property depends on this exact pattern | `.claude/skills/stream-type-authoring/` |
| `connectivity-debugger` agent | No existing agent owned opaque ICE/NAT/relay failures | `.claude/agents/connectivity-debugger.md` |
| `/adr` command | ADRs are binding and creation shouldn't be freehand | `.claude/commands/adr.md` |
| `/spike` command | Forces open *implementation* forks to end in a recorded decision | `.claude/commands/spike.md` |
| `verification-ux.md` | Canonical, un-softenable warning wording; the malicious-server defense rests on it | `docs/security/verification-ux.md` |

## D. Worth-having (now done)
`CONTRIBUTING.md` (+ global Definition of Done) · `docs/glossary.md` · `LICENSE` (Apache-2.0 stub,
tied to D1) · `infra/deploy/bootstrap-ca.sh` + `two-orgs.compose.yml` so `just two-orgs` can run.

## E. Deliberately skipped (with reasons)
- **Dedicated crypto agent** — folded into [security-reviewer](../.claude/agents/security-reviewer.md)
  + the [crypto-protocols skill](../.claude/skills/crypto-protocols/SKILL.md); a separate agent would
  fragment ownership.
- **Separate docs agent** — the [/doc-sync](../.claude/commands/doc-sync.md) command covers it.
- **MCP connector config** — add only when real external tools (GitHub/CI) are connected; premature now.

## F. Remaining spikes (tracked, not blocking) — run via [/spike](../.claude/commands/spike.md)
1. `ratchet-header-enc` — confirm vodozemac exposes header encryption; else layer it in `meridian-crypto`.
2. `libwebrtc-packaging` — vendor prebuilt vs maintained `-sys` crate ([ADR 0014](./adr/0014-media-stack.md)).
Both leave the data-plane features (03/04/09/16) unblocked.

## G. Still `TODO: confirm` (org-specific, correctly not invented)
Alert thresholds & on-call ([operations](./operations/monitoring.md), [runbook](./operations/runbook.md));
final verification copy ([verification-ux](./security/verification-ux.md)); CODEOWNERS once the GitHub
org exists; full Apache-2.0 text before public release.
