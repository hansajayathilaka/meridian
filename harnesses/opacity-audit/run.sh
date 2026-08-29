#!/usr/bin/env bash
# opacity-audit harness — asserts the server/SDP path exposes only opaque bytes: no plaintext
# content, no header/counter leaks, no SDP/DTLS-fingerprint/ICE-candidate leakage into the
# server-visible transcript. Real check lives in apps/cli/src/opacity.rs (run_audit), driven here
# via its unit test so a regression there fails this named CI gate.
# See docs/testing/strategy.md and docs/architecture/features/ for the opacity acceptance criteria.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[opacity-audit] no-plaintext-on-the-wire audit (apps/cli/src/opacity.rs)…"
cargo test -q -p meridian-cli --bin meridian opacity::tests::opacity_audit_passes -- --exact
echo "[opacity-audit] OK: server-visible transcript contains zero plaintext leaks."

# 2.12 deliverable 4: opacity "at both servers" (Feature 06's acceptance criterion). Extends the
# local c2s audit above across a federation boundary: the SAME never-decoded envelope bytes,
# additionally captured in the real s2s `FedRoute`/`FedFrame` wire encoding the federation boundary
# introduces (apps/rendezvous/src/federation/outbound.rs: "moved, never inspected"). In-process and
# network-free, like the audit above, for the same determinism/CI reasons — see
# `opacity::run_federated_audit`'s doc comment for why that is faithful to the real wire shape
# rather than a lookalike. `federated_opacity_scan_is_sensitive_to_a_fed_only_leak` proves the scan
# genuinely inspects the fed-hop transcript (not just the local one) by construction, so this gate
# cannot pass vacuously on a scan that only ever looked at the c2s bytes.
echo "[opacity-audit] no-plaintext-at-either-server audit, cross-org (task 2.12)…"
cargo test -q -p meridian-cli --bin meridian opacity::tests::federated_opacity_audit_passes -- --exact
cargo test -q -p meridian-cli --bin meridian opacity::tests::federated_opacity_scan_is_sensitive_to_a_fed_only_leak -- --exact
echo "[opacity-audit] OK: zero plaintext leaks in EITHER the local c2s transcript or the federated"
echo "  s2s FedRoute transcript — grep -c plaintext == 0 at both servers."

# 8.12: opacity/at-rest audit for MAILBOX ROWS (T07's offline ciphertext mailbox, task 8.2). This
# is the first raw-DB-page scanner in this codebase (the two audits above scan wire transcripts,
# not on-disk bytes) — see apps/cli/src/opacity.rs's `run_mailbox_at_rest_audit` doc comment for
# why. Requires the meridian-rendezvous `sqlite` dev-dependency feature (apps/cli/Cargo.toml).
echo "[opacity-audit] no-plaintext-at-rest audit, mailbox rows (task 8.12)…"
cargo test -q -p meridian-cli --bin meridian opacity::tests::mailbox_at_rest_audit_passes -- --exact
cargo test -q -p meridian-cli --bin meridian opacity::tests::mailbox_at_rest_audit_catches_a_planted_plaintext_regression -- --exact
echo "[opacity-audit] OK: zero plaintext leaks in the raw on-disk mailbox .db bytes, AND the scan"
echo "  is proven non-vacuous (it catches a planted-plaintext regression)."
