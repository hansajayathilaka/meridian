#!/usr/bin/env bash
# T04 deliverable 3 — network-namespace rig simulating two LANs behind distinct NATs, for exercising
# the P2P session substrate over the real webrtc-rs backend (host → srflx → relay candidate ladder;
# TURN/relay itself is T05). See docs/architecture/features/04-p2p-session-substrate.md and the
# webrtc-nat-traversal skill.
#
# Topology (each box is a network namespace):
#
#     ns-alice ──veth── ns-natA ──veth── ns-net(bridge) ──veth── ns-natB ──veth── ns-bob
#   10.0.1.2/24        (MASQUERADE)        203.0.113.0/24        (MASQUERADE)     10.0.2.2/24
#
#   - ns-alice / ns-bob are the two "LANs": private RFC-1918 addresses, no direct route to each other.
#   - ns-natA / ns-natB are NAT routers doing source-NAT (MASQUERADE) onto the shared 203.0.113.0/24
#     "internet" segment, so each peer only reaches the other via its public-mapped address (srflx).
#   - Distinct NATs ⇒ this is the case the ICE ladder must solve; symmetric×symmetric would force
#     relay (T05), which this rig is structured to add a TURN namespace to later.
#
# Usage:
#   sudo tools/netns-two-lans.sh up        # build the topology
#   sudo tools/netns-two-lans.sh demo      # run the substrate demo across the two LANs
#   sudo tools/netns-two-lans.sh down      # tear it all down
#   sudo tools/netns-two-lans.sh           # up → demo → down
#
# Requires root (netns/veth/iptables) and a release build of `meridian`. On CI without NET_ADMIN the
# script skips with a clear message; the substrate's logic is covered deterministically by
# `cargo test -p meridian-core --test p2p_session` and `meridian session demo`.
set -euo pipefail

BIN="${MERIDIAN_BIN:-./target/debug/meridian}"
NS=(ns-alice ns-natA ns-net ns-natB ns-bob)

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "netns rig needs root (NET_ADMIN). Re-run with sudo, or use 'meridian session demo' for the"
    echo "network-free substrate demo. Skipping." >&2
    exit 0
  fi
  if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 ('ip') not found — cannot build the netns topology. Skipping." >&2
    exit 0
  fi
}

up() {
  need_root
  echo "[netns] creating namespaces: ${NS[*]}"
  for n in "${NS[@]}"; do ip netns add "$n" 2>/dev/null || true; done

  # ns-net acts as the shared L2 "internet" bridge.
  ip netns exec ns-net ip link add br0 type bridge
  ip netns exec ns-net ip link set br0 up

  # Alice LAN: ns-alice(10.0.1.2) <-> ns-natA(10.0.1.1 / 203.0.113.10)
  link_pair ns-alice a-eth ns-natA nA-lan
  ip netns exec ns-alice ip addr add 10.0.1.2/24 dev a-eth
  ip netns exec ns-natA  ip addr add 10.0.1.1/24 dev nA-lan
  ip netns exec ns-alice ip route add default via 10.0.1.1
  # NAT-A public leg onto the bridge.
  link_pair ns-natA nA-pub ns-net brA
  bridge_attach brA
  ip netns exec ns-natA ip addr add 203.0.113.10/24 dev nA-pub
  nat_router ns-natA nA-lan nA-pub

  # Bob LAN: ns-bob(10.0.2.2) <-> ns-natB(10.0.2.1 / 203.0.113.20)
  link_pair ns-bob b-eth ns-natB nB-lan
  ip netns exec ns-bob   ip addr add 10.0.2.2/24 dev b-eth
  ip netns exec ns-natB  ip addr add 10.0.2.1/24 dev nB-lan
  ip netns exec ns-bob   ip route add default via 10.0.2.1
  link_pair ns-natB nB-pub ns-net brB
  bridge_attach brB
  ip netns exec ns-natB ip addr add 203.0.113.20/24 dev nB-pub
  nat_router ns-natB nB-lan nB-pub

  echo "[netns] topology up: 10.0.1.2 (alice) and 10.0.2.2 (bob) behind distinct NATs on 203.0.113.0/24"
}

# Create a veth pair with one end in each namespace and bring both up.
link_pair() {
  local ns1="$1" if1="$2" ns2="$3" if2="$4"
  ip link add "$if1" netns "$ns1" type veth peer name "$if2" netns "$ns2"
  ip netns exec "$ns1" ip link set "$if1" up
  ip netns exec "$ns2" ip link set "$if2" up
  ip netns exec "$ns1" ip link set lo up
  ip netns exec "$ns2" ip link set lo up
}

bridge_attach() { ip netns exec ns-net ip link set "$1" master br0; }

# Turn a namespace into a MASQUERADE NAT router between its LAN and public interfaces.
nat_router() {
  local ns="$1" lan="$2" pub="$3"
  ip netns exec "$ns" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$pub" -j MASQUERADE
  ip netns exec "$ns" iptables -A FORWARD -i "$lan" -o "$pub" -j ACCEPT
  ip netns exec "$ns" iptables -A FORWARD -i "$pub" -o "$lan" -m state --state RELATED,ESTABLISHED -j ACCEPT
}

demo() {
  need_root
  if [[ ! -x "$BIN" ]]; then
    echo "meridian binary not found at $BIN — run 'cargo build' first (or set MERIDIAN_BIN)." >&2
    exit 1
  fi
  # Cross-process P2P over these NATs lands with the webrtc-rs backend (meridian-transport `webrtc`
  # feature). Until then, run the substrate demo inside Alice's namespace as a connectivity smoke
  # test that the binary starts and the substrate establishes end to end.
  echo "[netns] running 'meridian session demo' inside ns-alice…"
  ip netns exec ns-alice "$BIN" session demo
  echo "[netns] TODO: when the webrtc backend is built, launch a rendezvous on the bridge and run"
  echo "        two 'meridian chat' peers (ns-alice, ns-bob) to prove direct P2P across the NATs."
}

down() {
  for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
  echo "[netns] topology torn down"
}

case "${1:-all}" in
  up) up ;;
  demo) demo ;;
  down) down ;;
  all) up; demo; down ;;
  *) echo "usage: $0 {up|demo|down|all}" >&2; exit 2 ;;
esac
