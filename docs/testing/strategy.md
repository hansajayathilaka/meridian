<!-- Source: DOC-05-test-and-verification-strategy. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](../security/threat-model.md) · [threat→mitigation matrix](../security/threat-mitigation-matrix.md) · [test-engineer agent](../../.claude/agents/test-engineer.md)

# Test & Verification Strategy

Companion to every task's "acceptance criteria" and DOC-03. The thesis: security claims that aren't wired into CI decay into folklore. Each layer below runs on a defined trigger.

## 1. Conformance vectors (cross-implementation truth)
JSON fixtures from T01 (IDs, checksums) and T08 (safety numbers, fingerprints). Every client — CLI, WASM, desktop, mobile — must reproduce them **byte-identically**. Runs in CI per platform (wasm32, aarch64, x86_64). A drift here means two clients disagree on identity — treated as a release blocker.

## 2. Opacity audits (the A1/A7 guarantee, mechanized)
A proxy/harness (T03, extended by T04/T06/T07) captures every byte each server component handles for scripted flows and asserts: no plaintext substrings, encrypted ratchet headers (no visible counters), SDP never in cleartext, mailbox DB pages carry only opaque blobs. Green on every commit; a regression fails the build.

## 3. Adversarial harnesses (the A2/A6/A7 guarantees)
- `meridian-mitm-sim` (T08): malicious rendezvous substitutes keys/bundles against `tofu` and `verified` states → matrix must show 0 silent successes.
- Ghost-device harness (T13): forged record (bad sig → reject) and key-theft variant (→ blocking alert on verified contacts).
- FS/PCS harness (T03): snapshot ratchet at N, prove <N undecryptable; simulate state theft, prove self-heal within one round-trip.
- Fingerprint-mismatch (T04): forced DTLS fp mismatch tears down 100%.

## 4. Network realism (NAT matrix)
netns-based rig (T04/T05) — no cloud dependency — covering full-cone / port-restricted / symmetric×symmetric / UDP-blocked, plus loss+latency profiles (1% / 80 ms) for the file (T09) and call (T10) soak tests. Mid-session failover (direct→relay, Wi-Fi→LTE) is a scripted case, not a manual check.

## 5. Extension-contract validation
T09/T15/T16 acceptance includes: (a) implemented with zero core-crate changes (CODEOWNERS gate), (b) a "third-party implementability" test — an engineer off the task builds a toy stream type from `stream-types-v1.md` alone in <1 day. If the doc isn't sufficient, the contract fails, not the engineer.

## 6. Ops verification (continuous, not archaeological)
T14's demo scripts run in CI: compose stack weekly, air-gapped install per release (asserting zero uplink egress via capture), prekey-depletion drill fires the alert, upgrade+rollback both leave a green smoke suite.

## 7. External review gates (human, scheduled)
Before Phase 1 GA: independent crypto review of the X3DH/ratchet integration and the fingerprint-binding logic (the two places a subtle bug is catastrophic). Before Phase 4 (tunnels): a security team red-teams `tunnel-security.md` against the default-deny allowlist. These are named milestones in the roadmap, with the review artifact as the exit criterion.

## Test pyramid summary
Unit (crypto edges, ID parsing, framing) → property (fuzz IDs, out-of-order envelopes) → integration (per-task demos) → adversarial (harnesses above) → soak (files/calls under loss) → conformance (cross-platform vectors) → ops (deploy demos). CI runs unit→integration→adversarial→conformance on every commit; soak+ops on schedule/release.
