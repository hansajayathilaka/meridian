#!/usr/bin/env bash
# mitm-sim harness — a malicious rendezvous substitutes a prekey bundle under a different key; a
# correct client MUST verify the bundle under the exact requested key and abort (no downgrade).
#
# T02 wires the first, load-bearing case: the substituted-bundle abort at both the library layer
# (meridian-signaling::verify_bundle) and the CLI layer (`fetch-bundle --tamper` fails closed).
# T04 EXTENDS it to the transport layer: SDP/ICE ride inside ratchet-encrypted envelopes, so a
# malicious relay cannot touch the inner SDP, and the DTLS fingerprint is cross-checked against the
# identity-bound value after the handshake — a mismatch (a MITM that terminated DTLS) tears the
# session down 100% of the time (§4.6).
# T08 EXTENDS this harness with the tofu/verified trust-state matrix — do not delete these cases.
# See docs/testing/strategy.md §3 and docs/security/threat-mitigation-matrix.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[mitm-sim] substituted-bundle abort (library + CLI)…"
cargo test -q -p meridian-rendezvous --test rendezvous tampered_bundle_is_rejected
cargo test -q -p meridian-cli --test rendezvous_demo full_rendezvous_demo
echo "[mitm-sim] OK: client aborts on a bundle signed under any other key."

echo "[mitm-sim] DTLS fingerprint-binding teardown (T04 §4.6)…"
cargo test -q -p meridian-core --test p2p_session fingerprint_mismatch_tears_down
cargo test -q -p meridian-core --test p2p_session malicious_relay_cannot_touch_inner_sdp
echo "[mitm-sim] OK: fingerprint mismatch tears the session down; inner SDP is untouchable."
