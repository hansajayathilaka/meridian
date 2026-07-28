<!-- Source: DOC-05-test-and-verification-strategy. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](../security/threat-model.md) · [threat→mitigation matrix](../security/threat-mitigation-matrix.md) · [test-engineer agent](../../.claude/agents/test-engineer.md)

# Test & Verification Strategy

Companion to every task's "acceptance criteria" and DOC-03. The thesis: security claims that aren't wired into CI decay into folklore. Each layer below runs on a defined trigger.

## 1. Conformance vectors (cross-implementation truth)
JSON fixtures from T01 (IDs, checksums) and T08 (safety numbers, fingerprints). Every client — CLI, WASM, desktop, mobile — must reproduce them **byte-identically**. Runs in CI per platform (wasm32, aarch64, x86_64). A drift here means two clients disagree on identity — treated as a release blocker.

## 2. Opacity audits (the A1/A7 guarantee, mechanized)
A proxy/harness (T03, extended by T04/T06/T07) captures every byte each server component handles for scripted flows and asserts: no plaintext substrings, encrypted ratchet headers (no visible counters), SDP never in cleartext, mailbox DB pages carry only opaque blobs. Green on every commit; a regression fails the build.

## 3. Adversarial harnesses (the A2/A6/A7 guarantees)
- `meridian-mitm-sim` (T08): malicious rendezvous substitutes keys/bundles against `tofu` and `verified` states → matrix must show **0 silent successes outside the enumerated accepted residuals**. (The re-scoping is required by [ADR 0016](../adr/0016-envelope-deniability.md), which records the conflict: an unqualified "0 silent successes" contradicts the ADR's own accepted residual R1 — under envelope v2 the signed-prekey-compromise/KCI row *is* an attacker success. "Enumerated" means listed as an accepted residual in [ADR 0016](../adr/0016-envelope-deniability.md) or [threat-model.md §1.3](../security/threat-model.md) — deliberately *not* "in any ADR", which is an open set a future decision could quietly extend. Anything not on that list is a failure. **The exception is not live under envelope v1**, which is what ships today: no enumerated residual applies to this matrix, so the current requirement is 0 silent successes, unqualified. Extending the enumerated list requires a new ADR with security-reviewer sign-off; the list is not extended to make a harness go green.) Also (task 1.28) a rendezvous actively **rewriting routed blobs** in transit during a real `dial`/`answer`: the rewrite is detected at envelope authentication and no session establishes, with a control case through an honest relay so the assertion cannot pass vacuously. Task **1.32** adds the relay attacks that *pass* the signature check because they never touch the bytes — forged `Deliver.from` (→ `SenderMismatch`), replay (→ refused by the ratchet), reorder (tolerated, nothing lost or forged), drop (denial stays denial), cross-delivery (→ `UnknownPrekey`) — plus [ADR 0016](../adr/0016-envelope-deniability.md)'s X3DH preamble-mutation cells, which assert the anti-DoS property that a rejected prekey envelope consumes no one-time prekey and installs no session.
- Ghost-device harness (T13): forged record (bad sig → reject) and key-theft variant (→ blocking alert on verified contacts).
- FS/PCS harness (T03): snapshot ratchet at N, prove <N undecryptable; simulate state theft, prove self-heal within one round-trip.
- Fingerprint-mismatch (T04): forced DTLS fp mismatch tears down 100% (`LoopbackTransport::new_mitm`,
  backend-agnostic session-layer check). Real-backend counterpart (1.15): a peer whose SDP-declared
  fingerprint doesn't match its actual DTLS certificate can never complete the handshake at all —
  `apps/transport/tests/webrtc_backend.rs::tampered_remote_fingerprint_never_connects`.

## 4. Network realism (NAT matrix)
netns-based rig (T04/T05) — no cloud dependency — covering full-cone / port-restricted / symmetric×symmetric / UDP-blocked, plus loss+latency profiles (1% / 80 ms) for the file (T09) and call (T10) soak tests. Mid-session failover (direct→relay, Wi-Fi→LTE) is a scripted case, not a manual check.

Wire-level pcap assertions (1.27, `tools/netns-nat-matrix.sh`'s `assert_*` helpers, run via `harnesses/nat-matrix/run.sh` in CI when root/`NET_ADMIN` is available, else a documented manual/gated run) turn the above into strict, fail-closed pass/fail checks against real captures rather than trusting the CLI's self-report: (a) negotiated path/rung corroboration for the 3 real-connecting cells; (b) zero host/srflx address leak, gated on relay-only policy (not on connect success/failure) — proves A4/A5's relay-only IP-hiding claim on the wire for `udp-blocked`; (c) TURN relays only DTLS ciphertext, never plaintext, via a known-plaintext oracle scan; (d) `udp-blocked` fails fast with the documented 1.30 error signature, not a hang. Known residual gap: the `direct`/`prefer-relay` cells' actual connecting session is the post-fallback relay round (1.29), which is not yet independently wire-verified for zero-leak the way `udp-blocked`'s relay-only session is — see 1.27's task file Risks section and the threat-mitigation matrix's A4/A5 rows.

## 5. Extension-contract validation
T09/T15/T16 acceptance includes: (a) implemented with zero core-crate changes (CODEOWNERS gate), (b) a "third-party implementability" test — an engineer off the task builds a toy stream type from `stream-types-v1.md` alone in <1 day. If the doc isn't sufficient, the contract fails, not the engineer.

## 6. Ops verification (continuous, not archaeological)
T14's demo scripts run in CI: compose stack weekly, air-gapped install per release (asserting zero uplink egress via capture), prekey-depletion drill fires the alert, upgrade+rollback both leave a green smoke suite.

## 7. External review gates (human, scheduled)
Before Phase 1 GA: independent crypto review of the X3DH/ratchet integration and the fingerprint-binding logic (the two places a subtle bug is catastrophic). Before Phase 4 (tunnels): a security team red-teams `tunnel-security.md` against the default-deny allowlist. These are named milestones in the roadmap, with the review artifact as the exit criterion.

## Test pyramid summary
Unit (crypto edges, ID parsing, framing) → property (fuzz IDs, out-of-order envelopes) → integration (per-task demos) → adversarial (harnesses above) → soak (files/calls under loss) → conformance (cross-platform vectors) → ops (deploy demos). CI runs unit→integration→adversarial→conformance on every commit; soak+ops on schedule/release.
