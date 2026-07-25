#!/usr/bin/env bash
# mitm-sim harness — a malicious rendezvous substitutes a prekey bundle under a different key; a
# correct client MUST verify the bundle under the exact requested key and abort (no downgrade).
#
# T02 wires the first, load-bearing case: the substituted-bundle abort at both the library layer
# (meridian-signaling::verify_bundle) and the CLI layer (`fetch-bundle --tamper` fails closed).
# T04 EXTENDS it to the transport layer: SDP/ICE ride inside ratchet-encrypted envelopes, so a relay
# seeing only ciphertext cannot read or forge the inner SDP, and the DTLS fingerprint is cross-checked
# against the identity-bound value after the handshake — a mismatch (a MITM that terminated DTLS)
# tears the session down 100% of the time (§4.6).
# Task 1.28 ADDS the relay-as-adversary case: a real rendezvous actively REWRITING routed blobs in
# transit, driven through a real dial/answer (below). Scope it precisely — a byte-level rewrite
# breaks the Ed25519 envelope signature, so it is stopped at envelope AUTHENTICATION, strictly
# EARLIER than the §4.6 fingerprint cross-check, which that path never reaches. No test exists in
# which a hostile *relay* causes §4.6 to fire, and none can by mutation: every envelope byte is
# either signed or is the signature, so any mutation fails CBOR decode or signature verification
# first. Fingerprint binding is proven separately, with an honest relay. Relay attacks that need no
# key material and WOULD pass the signature check (replay, reorder, drop, cross-delivery, and a
# forged Deliver.from) are still open — see docs/tasks/phase-1/1.28-active-relay-rewrite-test.md.
# T08 EXTENDS this harness with the tofu/verified trust-state matrix — do not delete these cases.
# See docs/testing/strategy.md §3 and docs/security/threat-mitigation-matrix.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[mitm-sim] substituted-bundle abort (library + CLI)…"
cargo test -q -p meridian-rendezvous --features test-tamper-hook --test rendezvous tampered_bundle_is_rejected
cargo test -q -p meridian-cli --test rendezvous_demo full_rendezvous_demo
echo "[mitm-sim] OK: client aborts on a bundle signed under any other key."

echo "[mitm-sim] DTLS fingerprint-binding teardown (T04 §4.6)…"
cargo test -q -p meridian-core --test p2p_session fingerprint_mismatch_tears_down
cargo test -q -p meridian-core --test p2p_session relay_path_connects_healthily
echo "[mitm-sim] OK: fingerprint mismatch tears the session down; a healthy relay path still binds"
echo "  matching fingerprints."

# 1.28: the relay itself is the adversary. A real meridian-rendezvous (test-tamper-hook +
# allow_test_route_tamper) rewrites every routed signaling blob while two peers run a real
# dial/answer. Asserts BOTH that no session establishes (fail-closed) and that the RESPONDER rejects
# at the envelope-authentication layer specifically (SessionError::Chat — matched on the variant, so
# it survives ADR 0016's move of the detector from the signature to the ratchet AEAD). Pinning the
# side and the error class is deliberate: accepting "either side errored somehow" would go green if
# the hook became inert and an unrelated relay error fired. Ships with a control case through an
# honest relay, so the adversarial assertion cannot pass vacuously either.
echo "[mitm-sim] active relay-rewrite of routed blobs (1.28)…"
cargo test -q -p meridian-cli --test relay_rewrite
echo "[mitm-sim] OK: a rendezvous rewriting routed blobs is detected at the envelope signature"
echo "  check (earlier than the §4.6 fingerprint check, which this path never reaches) and cannot"
echo "  establish a session; the same flow through an honest relay does establish."
