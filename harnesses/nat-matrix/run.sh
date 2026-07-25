#!/usr/bin/env bash
# nat-matrix harness (T05) — the NAT traversal & relay-policy acceptance, run deterministically in
# CI (no cloud, no NET_ADMIN) plus the netns wire-level rig when root is available.
#
# Proves, per docs/architecture/features/05-nat-traversal-relay-policy.md (amended bar, per
# 1.26/1.29/1.30/1.27 — see that doc's verification-status paragraphs; "all four cells connect" is
# stale wording, not this task's actual acceptance criterion):
#   * 3 of 4 NAT cells connect via relay (full-cone/port-restricted/symmetric:symmetric — 1.29's
#     session-level relay-only fallback; direct/srflx never nominates under the pinned
#     webrtc-ice 0.17.1); `udp-blocked` + `relay-only` fails fast and cleanly instead of connecting
#     or hanging — a documented, proven-impossible-at-this-dependency-version combination (1.30),
#     not a bug;
#   * TLS-443/TURN-TCP reachability is proven independently (turnutils probe) even though the real
#     ICE agent can't yet consume it client-side for udp-blocked (1.30's dependency gap);
#   * TURN credentials are ephemeral + distinct per request (expiry embedded; reuse of a captured
#     credential is quota-bounded server-side, not rejected outright);
#   * relay-only offers ONLY relay candidates — a peer never sees our host/srflx IPs — now proven at
#     the wire level (pcap assertions, 1.27), not just in-process/simulation.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[nat-matrix] loopback NAT-scenario + relay-only strip-before-gather…"
cargo test -q -p meridian-transport nat_matrix_selects_the_right_path
cargo test -q -p meridian-transport relay_only_strips_host_and_srflx_before_gathering

echo "[nat-matrix] three-level relay-policy resolution…"
cargo test -q -p meridian-core --test relay_policy

echo "[nat-matrix] ephemeral TURN credential minting, distinct per request…"
cargo test -q -p meridian-rendezvous --test rendezvous turn_credentials_are_minted_and_verify_under_the_secret
cargo test -q -p meridian-rendezvous --test rendezvous each_turn_request_mints_a_distinct_credential

echo "[nat-matrix] CLI: doctor connects all four cells; relay-only hides our IPs…"
cargo test -q -p meridian-cli --test nat_relay

echo "[nat-matrix] building meridian-cli with the webrtc feature for the netns rig…"
# The plain `cargo test` steps above build meridian-cli without --features webrtc (its default),
# which overwrites any previously-built ./target/debug/meridian at the same path with a
# webrtc-less binary — the netns rig needs the real WebRtcTransport backend (1.15) to run `session
# connect`, so it must be rebuilt with the feature immediately before invoking the rig, not assumed
# to still be present from an earlier, unrelated build.
cargo build -q -p meridian-cli --features webrtc

echo "[nat-matrix] netns wire-level rig + pcap assertions (skips without NET_ADMIN)…"
bash tools/netns-nat-matrix.sh matrix

echo "[nat-matrix] OK: 3/4 cells connect via relay with pcap-verified zero address leak (relay-only" \
     "cell) and DTLS-ciphertext-only on the wire; udp-blocked fails fast and cleanly by design;" \
     "creds are distinct per request (reuse quota-bounded, not rejected outright)."
