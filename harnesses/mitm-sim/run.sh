#!/usr/bin/env bash
# mitm-sim harness — a malicious rendezvous substitutes a prekey bundle under a different key; a
# correct client MUST verify the bundle under the exact requested key and abort (no downgrade).
#
# T02 wires the first, load-bearing case: the substituted-bundle abort at both the library layer
# (meridian-signaling::verify_bundle) and the CLI layer (`fetch-bundle --tamper` fails closed).
# T08 EXTENDS this harness with the tofu/verified trust-state matrix — do not delete these cases.
# See docs/testing/strategy.md §3 and docs/security/threat-mitigation-matrix.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[mitm-sim] substituted-bundle abort (library + CLI)…"
cargo test -q -p meridian-rendezvous --test rendezvous tampered_bundle_is_rejected
cargo test -q -p meridian-cli --test rendezvous_demo full_rendezvous_demo
echo "[mitm-sim] OK: client aborts on a bundle signed under any other key."
