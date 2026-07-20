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
