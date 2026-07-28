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
# first. Fingerprint binding is proven separately, with an honest relay.
# Task 1.32 ADDS the relay attacks that need no key material and DO pass the signature check because
# they never touch the bytes — a forged Deliver.from, replay, reorder, drop, cross-delivery — plus
# the X3DH preamble mutations ADR 0016 requires, which a relay cannot mount (no envelope types
# server-side) and which are therefore driven client-side.
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

# 1.32: the attacks a routing relay mounts WITHOUT touching the bytes, so the signature check waves
# them through and they reach the ratchet — which no earlier cell does. One server-side mode flag per
# attack (spoof_from / replay / reorder / drop / cross_deliver), each armed alone, each pinning the
# SPECIFIC error variant on the SPECIFIC side: SenderMismatch for a forged Deliver.from, a ratchet
# refusal for a byte-identical replay, UnknownPrekey for a cross-delivered envelope. Reorder is the
# deliberate exception: it must SUCCEED (a permutation of authentic messages is what the ratchet's
# skipped-key handling exists for), so that cell asserts nothing is lost or forged and proves the
# swap really happened. Drop asserts denial stays denial — the relay lies "delivered: true" and the
# message is simply gone. Each cell has a control through an honest relay.
echo "[mitm-sim] relay attacks that PASS the signature check (1.32)…"
cargo test -q -p meridian-cli --test relay_attacks
echo "[mitm-sim] OK: forged from / replay / cross-delivery are each refused with their own"
echo "  diagnosable error; reorder is tolerated without forgery; a dropped message stays dropped."

# 1.32 + ADR 0016 test obligations: X3DH preamble mutation (used_opk -> None, used_opk -> another
# held OTK, used_spk -> previous generation) and a forged prekey envelope claiming from = Alice.
# NOT a relay cell by construction: meridian-rendezvous has no envelope types (lint-server-no-core),
# so it cannot reach the preamble even in a test hook — these are driven directly against
# ChatState::open_inbound. Each asserts all four of ADR 0016's properties: rejected at the SIGNATURE
# specifically, OTK pool depth unchanged, no session installed, and the genuine envelope still opens
# afterwards. That last pair is the anti-DoS property: rejection costs the recipient nothing.
echo "[mitm-sim] X3DH preamble mutation + prekey-depletion (1.32 / ADR 0016)…"
cargo test -q -p meridian-core --test preamble_mutation
echo "[mitm-sim] OK: a mutated preamble is rejected before the vault is touched — no prekey burned,"
echo "  no poisoned session, and the genuine envelope still establishes."
