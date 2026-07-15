#!/usr/bin/env bash
# nat-matrix harness (T05) — the NAT traversal & relay-policy acceptance, run deterministically in
# CI (no cloud, no NET_ADMIN) plus the netns wire-level rig when root is available.
#
# Proves, per docs/architecture/features/05-nat-traversal-relay-policy.md:
#   * all four NAT cells connect (symmetric×symmetric via relay);
#   * TLS-443 fallback carries the UDP-blocked cell;
#   * TURN credentials are ephemeral + single-session (reuse-distinct, expiry embedded);
#   * relay-only offers ONLY relay candidates — a peer never sees our host/srflx IPs.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "[nat-matrix] loopback NAT-scenario + relay-only strip-before-gather…"
cargo test -q -p meridian-transport nat_matrix_selects_the_right_path
cargo test -q -p meridian-transport relay_only_strips_host_and_srflx_before_gathering

echo "[nat-matrix] three-level relay-policy resolution…"
cargo test -q -p meridian-core --test relay_policy

echo "[nat-matrix] ephemeral, single-session TURN credential minting…"
cargo test -q -p meridian-rendezvous --test rendezvous turn_credentials_are_minted_and_verify_under_the_secret
cargo test -q -p meridian-rendezvous --test rendezvous each_turn_grant_is_single_session

echo "[nat-matrix] CLI: doctor connects all four cells; relay-only hides our IPs…"
cargo test -q -p meridian-cli --test nat_relay

echo "[nat-matrix] netns wire-level rig (skips without NET_ADMIN)…"
bash tools/netns-nat-matrix.sh matrix

echo "[nat-matrix] OK: four cells connect; TLS-443 fallback works; creds are single-session; relay-only hides IPs."
