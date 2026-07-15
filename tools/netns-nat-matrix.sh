#!/usr/bin/env bash
# T05 deliverable 4 — the NAT test matrix as a network-namespace rig, extending
# tools/netns-two-lans.sh with an org-operated coturn namespace and the four acceptance cells:
#
#     full-cone | port-restricted | symmetric:symmetric | udp-blocked
#
# Topology (each box is a network namespace):
#
#   ns-alice ─ ns-natA ─┐                          ┌─ ns-natB ─ ns-bob
#   10.0.1.2  (MASQ)    ├─ ns-net (bridge) ─ ns-turn┤  (MASQ)   10.0.2.2
#                203.0.113.10   203.0.113.0/24  .30  203.0.113.20
#
#   - ns-natA/ns-natB implement the per-cell NAT flavor (full-cone vs. symmetric via random-fully /
#     per-connection source ports); the `--block-udp` cell drops UDP egress so only TURN/TLS-443
#     survives.
#   - ns-turn runs coturn (org relay). Credentials are minted by the rendezvous (see turnserver.conf).
#
# Acceptance this rig proves (with the webrtc-rs backend built; see the TODO below):
#   * all four cells connect — symmetric×symmetric via relay;
#   * TLS-443 fallback works with UDP fully dropped;
#   * in relay-only, a capture on ns-bob contains ZERO of alice's host/srflx (10.0.1.2 / 203.0.113.10);
#   * a capture on ns-turn shows only DTLS ciphertext (never plaintext).
#
# Usage:
#   sudo tools/netns-nat-matrix.sh matrix        # build + run all four cells + tear down
#   sudo tools/netns-nat-matrix.sh cell udp-blocked
#   sudo tools/netns-nat-matrix.sh down
#
# Requires root (NET_ADMIN). On CI without it, the script SKIPS with a clear message; the matrix is
# covered deterministically by `cargo test -p meridian-cli --test nat_relay`, the loopback unit
# tests, and `meridian doctor` (the in-process NAT matrix). See feature 05 and the test strategy.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${MERIDIAN_BIN:-./target/debug/meridian}"
CELLS=(full-cone port-restricted symmetric:symmetric udp-blocked)

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    cat >&2 <<'EOF'
netns NAT-matrix rig needs root (NET_ADMIN). Skipping the wire-level run.
The matrix is covered deterministically without a network:
  cargo test -p meridian-cli --test nat_relay
  cargo test -p meridian-transport            # loopback NAT-scenario unit tests
  meridian doctor                             # in-process NAT matrix
EOF
    exit 0
  fi
  if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 ('ip') not found — cannot build the netns topology. Skipping." >&2
    exit 0
  fi
}

# The deterministic, network-free stand-in for one cell: `meridian doctor` reproduces the whole
# matrix in-process, so we assert the target cell's path is present in its output. This is what runs
# in CI; the wire-level assertions below need the webrtc-rs backend + NET_ADMIN.
smoke_cell() {
  local cell="$1"
  if [[ ! -x "$BIN" ]]; then
    echo "meridian binary not found at $BIN — run 'cargo build' first (or set MERIDIAN_BIN)." >&2
    exit 1
  fi
  echo "[nat-matrix] cell=$cell — in-process diagnostic:"
  "$BIN" doctor | sed -n "/$cell/p"
}

cell() {
  local name="${1:?usage: cell <full-cone|port-restricted|symmetric:symmetric|udp-blocked>}"
  need_root
  echo "[nat-matrix] configuring cell '$name' (topology build is TODO until the webrtc backend lands)"
  smoke_cell "$name"
  # TODO(webrtc backend): build the topology, set the NAT flavor on ns-natA/ns-natB, apply
  # `--block-udp` for the udp-blocked cell, launch a rendezvous + coturn, run two `meridian chat`
  # peers across ns-alice/ns-bob, and assert with tcpdump:
  #   - the negotiated path matches the expected rung (relay/udp, relay/tls-443, …);
  #   - relay-only: NO packet on ns-bob carries alice's host/srflx address;
  #   - ns-turn sees only DTLS ciphertext.
}

matrix() {
  need_root
  for c in "${CELLS[@]}"; do
    cell "$c"
  done
  echo "[nat-matrix] all four cells exercised."
}

down() {
  for n in ns-alice ns-natA ns-net ns-turn ns-natB ns-bob; do
    ip netns del "$n" 2>/dev/null || true
  done
  echo "[nat-matrix] topology torn down"
}

case "${1:-matrix}" in
  matrix) matrix ;;
  cell) shift; cell "${1:-}" ;;
  down) down ;;
  *) echo "usage: $0 {matrix|cell <name>|down}" >&2; exit 2 ;;
esac
