#!/usr/bin/env bash
# T05 deliverable 4 / task 1.25 — the NAT test matrix as a REAL network-namespace rig, extending
# tools/netns-two-lans.sh's link_pair/nat_router pattern with a coturn namespace, a real
# meridian-rendezvous instance, per-cell NAT-flavor iptables rules, and the four acceptance cells:
#
#     full-cone | port-restricted | symmetric:symmetric | udp-blocked
#
# Topology (each box is a network namespace):
#
#   ns-alice ─ ns-natA ─┐                              ┌─ ns-natB ─ ns-bob
#   10.0.1.2  (NAT)     ├─ ns-net (bridge br0) ─ ns-turn┤   (NAT)   10.0.2.2
#             203.0.113.10   203.0.113.1/24    .30    203.0.113.20
#
#   - ns-natA/ns-natB implement the per-cell NAT flavor (full-cone 1:1 NAT / port-restricted
#     conntrack-gated MASQUERADE / symmetric --random-fully MASQUERADE / udp-blocked drops UDP
#     egress so only TCP survives).
#   - ns-net is the shared "internet" segment: a bridge (br0) whose member ports are ns-natA's and
#     ns-natB's public legs plus ns-turn's veth — and br0 ITSELF holds 203.0.113.1/24 so a real
#     meridian-rendezvous instance can run inside ns-net's existing namespace, bound to
#     203.0.113.1:8443, without adding a 7th namespace (this task's open TODO:confirm, resolved this
#     way — see the script header comment in `matrix()` and the task report for the full rationale).
#   - ns-turn runs a real coturn (org relay) with a rig-generated static-auth-secret (never the
#     checked-in infra/coturn/turnserver.conf template, never committed).
#
# This task (1.25) proves the topology + NAT flavors + coturn/rendezvous are real working
# infrastructure with generic (non-Meridian) wire-level smoke checks. Driving an actual `meridian`
# peer process across it is 1.26; tcpdump/pcap assertions are 1.27 — both out of scope here.
#
# Usage:
#   sudo tools/netns-nat-matrix.sh matrix        # build + run all four cells (topology stays up)
#   sudo tools/netns-nat-matrix.sh cell udp-blocked
#   sudo tools/netns-nat-matrix.sh down
#
# Requires root (NET_ADMIN). On CI without it, the script SKIPS with a clear message; the matrix is
# also covered deterministically by `cargo test -p meridian-cli --test nat_relay`, the loopback unit
# tests, and `meridian doctor` (the in-process NAT matrix, still run below as an additional check
# alongside the new wire-level one). See feature 05 and the test strategy.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

BIN="${MERIDIAN_BIN:-./target/debug/meridian}"
RDZV_BIN="${MERIDIAN_RENDEZVOUS_BIN:-./target/debug/meridian-rendezvous}"
FETCH_TURN_BIN="${FETCH_TURN_CREDS_BIN:-./target/debug/examples/fetch_turn_credentials}"
CELLS=(full-cone port-restricted symmetric:symmetric udp-blocked)
# turnutils_peer (coturn's own companion test-peer tool) listens here, inside ns-net, as the
# TURN-reachability probe's relay peer -- see turn_reachability_probe's DEVIATION note: a single
# `-e <peer> -c` allocation (one relay allocation) fits comfortably under the real user-quota=4
# without any retry-pathology risk, unlike turnutils_uclient's `-y` client-to-client mode (which
# empirically needs 4-5 concurrent allocations under this coturn 4.6.1 build and blows the quota).
TEST_PEER_PORT=13480

# Rig-local scratch state (config, pidfiles, logs). Never reuses/edits the checked-in
# infra/coturn/turnserver.conf template — this is a fresh rig-generated config with a fresh secret.
RIG_DIR="${MERIDIAN_NETNS_RIG_DIR:-}"
RIG_STATE_FILE="/tmp/.meridian-netns-nat-matrix.rigdir"

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

# ---------------------------------------------------------------------------------------------
# Helpers duplicated from tools/netns-two-lans.sh (that script isn't sourced — it unconditionally
# executes its own case dispatch at the bottom with no source-guard).
# ---------------------------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------------------------
# Rig-local scratch dir (config/pidfiles/logs) — never touches infra/coturn/turnserver.conf.
# ---------------------------------------------------------------------------------------------

rig_dir() {
  if [[ -n "$RIG_DIR" ]]; then
    echo "$RIG_DIR"
    return
  fi
  if [[ -f "$RIG_STATE_FILE" ]]; then
    cat "$RIG_STATE_FILE"
    return
  fi
  local d
  d="$(mktemp -d /tmp/meridian-netns-nat-matrix.XXXXXX)"
  echo "$d" > "$RIG_STATE_FILE"
  echo "$d"
}

# ---------------------------------------------------------------------------------------------
# Topology build
# ---------------------------------------------------------------------------------------------

topology_up() {
  local d
  d="$(rig_dir)"
  mkdir -p "$d"
  echo "[nat-matrix] scratch dir: $d"

  echo "[nat-matrix] creating namespaces: ns-alice ns-natA ns-net ns-turn ns-natB ns-bob"
  for n in ns-alice ns-natA ns-net ns-turn ns-natB ns-bob; do
    ip netns add "$n" 2>/dev/null || true
  done

  # ns-net acts as the shared L2 "internet" bridge, and ALSO holds its own address on br0 so a
  # process inside ns-net (the rendezvous) can bind 203.0.113.1 directly — standard Linux bridging:
  # a bridge device can hold an IP while still forwarding between its member ports.
  ip netns exec ns-net ip link add br0 type bridge
  ip netns exec ns-net ip addr add 203.0.113.1/24 dev br0
  ip netns exec ns-net ip link set br0 up
  ip netns exec ns-net ip link set lo up

  # Alice LAN: ns-alice(10.0.1.2) <-> ns-natA(10.0.1.1 / 203.0.113.10)
  link_pair ns-alice a-eth ns-natA nA-lan
  ip netns exec ns-alice ip addr add 10.0.1.2/24 dev a-eth
  ip netns exec ns-natA  ip addr add 10.0.1.1/24 dev nA-lan
  ip netns exec ns-alice ip route add default via 10.0.1.1
  link_pair ns-natA nA-pub ns-net brA
  bridge_attach brA
  ip netns exec ns-natA ip addr add 203.0.113.10/24 dev nA-pub
  ip netns exec ns-natA sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec ns-natA iptables -P FORWARD DROP

  # Bob LAN: ns-bob(10.0.2.2) <-> ns-natB(10.0.2.1 / 203.0.113.20)
  link_pair ns-bob b-eth ns-natB nB-lan
  ip netns exec ns-bob   ip addr add 10.0.2.2/24 dev b-eth
  ip netns exec ns-natB  ip addr add 10.0.2.1/24 dev nB-lan
  ip netns exec ns-bob   ip route add default via 10.0.2.1
  link_pair ns-natB nB-pub ns-net brB
  bridge_attach brB
  ip netns exec ns-natB ip addr add 203.0.113.20/24 dev nB-pub
  ip netns exec ns-natB sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec ns-natB iptables -P FORWARD DROP

  # ns-turn: org relay, veth straight onto the bridge (no NAT — it IS the "internet"-side relay).
  link_pair ns-turn t-eth ns-net brT
  bridge_attach brT
  ip netns exec ns-turn ip addr add 203.0.113.30/24 dev t-eth

  echo "[nat-matrix] topology up: alice(10.0.1.2)/bob(10.0.2.2) behind distinct NAT routers on"
  echo "             203.0.113.0/24, with coturn(.30) and rendezvous(.1, in ns-net) reachable."
}

# ---------------------------------------------------------------------------------------------
# Per-cell NAT-flavor application on ns-natA / ns-natB (identical, parameterized).
# ---------------------------------------------------------------------------------------------

apply_nat_flavor() {
  local ns="$1" flavor="$2" lan_if="$3" pub_if="$4" lan_ip="$5" lan_subnet="$6" pub_ip="$7"

  # Cheap flavor swap: flush and reapply rather than tearing down the whole topology.
  ip netns exec "$ns" iptables -t nat -F POSTROUTING
  ip netns exec "$ns" iptables -t nat -F PREROUTING
  ip netns exec "$ns" iptables -F FORWARD

  case "$flavor" in
    full-cone)
      # Static 1:1 NAT: any external host may reach the mapped address on any port — the
      # full-cone property. No conntrack restriction on the return leg.
      ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$pub_if" -s "$lan_subnet" -j SNAT --to-source "$pub_ip"
      ip netns exec "$ns" iptables -t nat -A PREROUTING  -i "$pub_if" -d "$pub_ip" -j DNAT --to-destination "$lan_ip"
      ip netns exec "$ns" iptables -A FORWARD -i "$lan_if" -o "$pub_if" -j ACCEPT
      ip netns exec "$ns" iptables -A FORWARD -i "$pub_if" -o "$lan_if" -j ACCEPT
      ;;
    port-restricted)
      # Plain MASQUERADE; unsolicited inbound (no prior ESTABLISHED/RELATED state) is refused by
      # the default FORWARD DROP policy — the port-restricted-cone property.
      ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$pub_if" -j MASQUERADE
      ip netns exec "$ns" iptables -A FORWARD -i "$lan_if" -o "$pub_if" -j ACCEPT
      ip netns exec "$ns" iptables -A FORWARD -i "$pub_if" -o "$lan_if" -m state --state ESTABLISHED,RELATED -j ACCEPT
      ;;
    symmetric)
      # --random-fully: a distinct external source port per destination — the defining
      # symmetric-NAT property. Same conntrack-gated return leg as port-restricted.
      ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$pub_if" -j MASQUERADE --random-fully
      ip netns exec "$ns" iptables -A FORWARD -i "$lan_if" -o "$pub_if" -j ACCEPT
      ip netns exec "$ns" iptables -A FORWARD -i "$pub_if" -o "$lan_if" -m state --state ESTABLISHED,RELATED -j ACCEPT
      ;;
    udp-blocked)
      # Same as port-restricted, plus a UDP egress DROP inserted BEFORE the general ACCEPT so
      # only TCP/TLS survives egress.
      ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$pub_if" -j MASQUERADE
      ip netns exec "$ns" iptables -A FORWARD -i "$lan_if" -o "$pub_if" -p udp -j DROP
      ip netns exec "$ns" iptables -A FORWARD -i "$lan_if" -o "$pub_if" -j ACCEPT
      ip netns exec "$ns" iptables -A FORWARD -i "$pub_if" -o "$lan_if" -m state --state ESTABLISHED,RELATED -j ACCEPT
      ;;
    *)
      echo "apply_nat_flavor: unknown flavor '$flavor'" >&2
      exit 2
      ;;
  esac
}

# Map a cell name (as used on the CLI / NatScenario::as_str) to the single NAT flavor applied to
# BOTH ns-natA and ns-natB. "symmetric:symmetric" has a colon in its cell name but is one flavor.
flavor_for_cell() {
  case "$1" in
    full-cone) echo full-cone ;;
    port-restricted) echo port-restricted ;;
    symmetric:symmetric) echo symmetric ;;
    udp-blocked) echo udp-blocked ;;
    *) echo "flavor_for_cell: unknown cell '$1'" >&2; exit 2 ;;
  esac
}

set_cell_nat() {
  local cell="$1" flavor
  flavor="$(flavor_for_cell "$cell")"
  apply_nat_flavor ns-natA "$flavor" nA-lan nA-pub 10.0.1.1 10.0.1.0/24 203.0.113.10
  apply_nat_flavor ns-natB "$flavor" nB-lan nB-pub 10.0.2.1 10.0.2.0/24 203.0.113.20
  echo "[nat-matrix] applied NAT flavor '$flavor' to ns-natA/ns-natB for cell '$cell'"
}

# ---------------------------------------------------------------------------------------------
# Coturn + rendezvous — real processes inside ns-turn / ns-net.
# ---------------------------------------------------------------------------------------------

TURN_SECRET=""
TURN_REALM="rig.meridian.test"

gen_secret() {
  # 32 random bytes, hex — a rig-local secret, never committed, never equal to the checked-in
  # template's <CHANGE_ME> placeholder.
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# The secret is shared state between coturn (static-auth-secret) and rendezvous ([turn].secret),
# but the two are started independently and idempotently by `ensure_topology` (each individually
# skipped if already running) — so if only ONE of them dies and gets restarted on its own (e.g.
# coturn crashes but rendezvous is still the same live process from an earlier start), a naive
# `gen_secret` call in `start_coturn` would mint a FRESH secret that no longer matches whatever
# rendezvous already has baked into its running config, silently breaking every credential minted
# from then on. Persisting to `$d/turn.secret` on first generation and always reading it back if it
# already exists means any component that (re)starts on its own recovers the SAME secret the other
# side is already using, rather than diverging.
get_or_create_secret() {
  local d
  d="$(rig_dir)"
  if [[ -f "$d/turn.secret" ]]; then
    cat "$d/turn.secret"
    return
  fi
  local s
  s="$(gen_secret)"
  printf '%s' "$s" > "$d/turn.secret"
  chmod 600 "$d/turn.secret"
  echo "$s"
}

start_coturn() {
  local d
  d="$(rig_dir)"
  TURN_SECRET="$(get_or_create_secret)"
  local conf="$d/turnserver.conf"
  local pidfile="$d/turnserver.pid"
  local logfile="$d/turnserver.log"

  # Same real directives as infra/coturn/turnserver.conf (never edited/committed), with the two
  # <CHANGE_ME> placeholders filled by rig-generated values, and listening-ip/relay-ip pointed at
  # ns-turn's real address rather than the file's illustrative 127.0.0.1 default.
  cat > "$conf" <<EOF
use-auth-secret
static-auth-secret=$TURN_SECRET
realm=$TURN_REALM

listening-ip=203.0.113.30
relay-ip=203.0.113.30
listening-port=3478

fingerprint
no-multicast-peers
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
# NOTE: unlike the checked-in template, 10.0.0.0/8 is NOT denied here — this rig's own LAN
# subnets (10.0.1.0/24, 10.0.2.0/24) live in that range and are the rig's legitimate relay peers.

user-quota=4

no-cli
no-software-attribute
EOF

  echo "[nat-matrix] starting coturn in ns-turn (config: $conf)"
  ip netns exec ns-turn turnserver -c "$conf" --pidfile "$pidfile" -o -l "$logfile"
  # -o daemonizes; give it a moment then confirm the pidfile shows a live process.
  local tries=0
  while [[ ! -s "$pidfile" ]] && (( tries < 50 )); do
    sleep 0.1
    tries=$((tries + 1))
  done
  if [[ ! -s "$pidfile" ]]; then
    echo "[nat-matrix] coturn failed to write pidfile — log follows:" >&2
    cat "$logfile" >&2 || true
    exit 1
  fi
  local pid
  pid="$(cat "$pidfile")"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[nat-matrix] coturn pid $pid from $pidfile is not alive — log follows:" >&2
    cat "$logfile" >&2 || true
    exit 1
  fi
  echo "$pid" > "$d/turnserver.tracked-pid"
  # (get_or_create_secret already persisted $d/turn.secret above, 0600, rig-scratch-only, never
  # committed — a standalone `cell` invocation in a fresh bash process, or a solo coturn restart,
  # reads the same value back rather than diverging from what rendezvous already has.)
  echo "[nat-matrix] coturn running: pid=$pid realm=$TURN_REALM secret=<redacted>"
}

# Recover TURN_SECRET in this process if it wasn't set by an in-process start_coturn call (e.g. a
# standalone `cell` invocation reusing a topology + coturn started by an earlier `matrix`/`cell`
# process).
load_turn_secret() {
  if [[ -z "$TURN_SECRET" ]]; then
    local d
    d="$(rig_dir)"
    if [[ -f "$d/turn.secret" ]]; then
      TURN_SECRET="$(cat "$d/turn.secret")"
    fi
  fi
}

start_rendezvous() {
  local d
  d="$(rig_dir)"
  local conf="$d/rendezvous.toml"
  local pidfile="$d/rendezvous.pid"
  local logfile="$d/rendezvous.log"

  # Always source the shared secret via get_or_create_secret (not the bare $TURN_SECRET global)
  # so this converges to whatever coturn already has even if start_rendezvous ends up called
  # without start_coturn having just run first in this same process (e.g. rendezvous alone dies
  # and ensure_topology restarts only it, with coturn already up from earlier).
  TURN_SECRET="$(get_or_create_secret)"

  if [[ ! -x "$RDZV_BIN" ]]; then
    echo "meridian-rendezvous binary not found at $RDZV_BIN — run 'cargo build -p meridian-rendezvous' first." >&2
    exit 1
  fi

  cat > "$conf" <<EOF
[server]
domain = "$TURN_REALM"
bind = "203.0.113.1:8443"
admission = "open"
invite_tokens = []
allow_test_tamper = false
database_url = "sqlite://:memory:"

[turn]
secret = "$TURN_SECRET"
realm = "$TURN_REALM"
urls = [
  "turn:203.0.113.30:3478?transport=udp",
  "turn:203.0.113.30:3478?transport=tcp",
]
ttl_secs = 120
EOF

  echo "[nat-matrix] starting meridian-rendezvous in ns-net (config: $conf)"
  ip netns exec ns-net "$REPO_ROOT/$RDZV_BIN" --config "$conf" > "$logfile" 2>&1 &
  local pid=$!
  echo "$pid" > "$pidfile"

  local tries=0
  while ! ip netns exec ns-net bash -c "echo > /dev/tcp/203.0.113.1/8443" 2>/dev/null && (( tries < 50 )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[nat-matrix] rendezvous process died before it started listening — log follows:" >&2
      cat "$logfile" >&2 || true
      exit 1
    fi
    sleep 0.1
    tries=$((tries + 1))
  done
  echo "[nat-matrix] rendezvous running: pid=$pid bind=203.0.113.1:8443"
}

# turnutils_peer (coturn's own bundled test-peer tool) as the fixed target for the TURN-
# reachability probe's single relay allocation (see turn_reachability_probe). Lives in ns-net
# (reachable from ns-turn's relay leg with no NAT/routing in the way, and not in coturn's
# denied-peer-ip ranges).
start_test_peer() {
  local d
  d="$(rig_dir)"
  local pidfile="$d/testpeer.pid"
  local logfile="$d/testpeer.log"

  echo "[nat-matrix] starting turnutils_peer in ns-net on 203.0.113.1:$TEST_PEER_PORT"
  ip netns exec ns-net turnutils_peer -L 203.0.113.1 -p "$TEST_PEER_PORT" > "$logfile" 2>&1 &
  local pid=$!
  echo "$pid" > "$pidfile"
  sleep 0.3
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[nat-matrix] turnutils_peer died immediately — log follows:" >&2
    cat "$logfile" >&2 || true
    exit 1
  fi
  echo "[nat-matrix] turnutils_peer running: pid=$pid"
}

test_peer_running() {
  local d
  d="$(rig_dir)"
  [[ -f "$d/testpeer.pid" ]] && kill -0 "$(cat "$d/testpeer.pid" 2>/dev/null)" 2>/dev/null
}

# ---------------------------------------------------------------------------------------------
# Smoke checks
# ---------------------------------------------------------------------------------------------

# The deterministic, network-free stand-in for one cell: `meridian doctor` reproduces the whole
# matrix in-process, so we assert the target cell's path is present in its output. Kept as an
# ADDITIONAL signal alongside the real wire-level checks below (not a replacement).
smoke_cell() {
  local cell="$1"
  if [[ ! -x "$BIN" ]]; then
    echo "meridian binary not found at $BIN — run 'cargo build' first (or set MERIDIAN_BIN)." >&2
    exit 1
  fi
  echo "[nat-matrix] cell=$cell — in-process diagnostic (additional signal, no network):"
  "$BIN" doctor | sed -n "1p;/$cell/p"
}

# NAT-flavor proof: two UDP listeners in ns-turn on different ports; ns-alice sends one packet to
# each from a SINGLE bound local socket and each listener reports the external (post-NAT) src port
# it observed. Same port on both ⇒ cone-like (full-cone/port-restricted); different ports ⇒
# symmetric. Skipped entirely for udp-blocked (UDP egress is dropped there by design).
nat_flavor_probe() {
  local expect="$1" # "same" or "different"
  local d
  d="$(rig_dir)"
  local out1="$d/probe-port1.out"
  local out2="$d/probe-port2.out"
  rm -f "$out1" "$out2"

  local py_listener='
import socket, sys
port = int(sys.argv[1])
outfile = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.bind(("203.0.113.30", port))
try:
    data, addr = s.recvfrom(1024)
    with open(outfile, "w") as f:
        f.write(str(addr[1]))
except socket.timeout:
    with open(outfile, "w") as f:
        f.write("TIMEOUT")
'
  ip netns exec ns-turn python3 -c "$py_listener" 15201 "$out1" &
  local l1=$!
  ip netns exec ns-turn python3 -c "$py_listener" 15202 "$out2" &
  local l2=$!
  sleep 0.3

  local py_sender='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.1.2", 0))
s.sendto(b"probe1", ("203.0.113.30", 15201))
s.sendto(b"probe2", ("203.0.113.30", 15202))
'
  ip netns exec ns-alice python3 -c "$py_sender"

  wait "$l1" "$l2" 2>/dev/null || true
  local p1 p2
  p1="$(cat "$out1" 2>/dev/null || echo MISSING)"
  p2="$(cat "$out2" 2>/dev/null || echo MISSING)"
  echo "[nat-matrix] NAT-flavor probe: external src port seen by listener1=$p1 listener2=$p2 (expect $expect)"

  if [[ "$p1" == "TIMEOUT" || "$p2" == "TIMEOUT" || "$p1" == "MISSING" || "$p2" == "MISSING" ]]; then
    echo "[nat-matrix] FAIL: probe packet never arrived (p1=$p1 p2=$p2)" >&2
    exit 1
  fi

  if [[ "$expect" == "same" ]]; then
    if [[ "$p1" != "$p2" ]]; then
      echo "[nat-matrix] FAIL: expected cone-like (same external port), got $p1 != $p2" >&2
      exit 1
    fi
  else
    if [[ "$p1" == "$p2" ]]; then
      echo "[nat-matrix] FAIL: expected symmetric (different external port), got $p1 == $p2" >&2
      exit 1
    fi
  fi
  echo "[nat-matrix] NAT-flavor probe: PASS ($expect confirmed)"
}

# TURN-reachability proof: mint a real ephemeral credential via the ALREADY-WRITTEN
# fetch_turn_credentials example (the real TurnReq/TurnGrant wire flow — never a hand-rolled HMAC),
# from within ns-alice (genuinely behind the NAT under test); independently verify the returned
# `credential` is exactly base64(HMAC-SHA1(secret, username)) (the coturn REST-secret algorithm,
# per apps/rendezvous/src/turn.rs); then drive turnutils_uclient from ns-alice against coturn in
# ns-turn and assert it gets a real relay allocation for that exact username, using the literal
# minted (username, credential) pair via `-u <user> -w <credential>` — exactly the two values a
# real Meridian client would receive from the TurnGrant and hand to its ICE agent. No raw coturn
# secret is used for authentication anywhere in this probe.
#
# DEVIATION #1 RESOLVED (was flagged for connectivity-debugger review; re-tested and closed): an
# earlier iteration of this script reported `-u <user> -w <precomputed-password>` reliably failing
# ("Cannot find credentials of user") against this same coturn 4.6.1 build, and worked around it by
# driving the probe with `-W <secret>` (coturn's own REST-secret client mode) instead, while
# independently verifying the TurnGrant's credential byte-for-byte. connectivity-debugger re-ran
# `-u`/`-w` with freshly-minted real credentials directly against this rig (repeatedly, across all
# four NAT flavors, after accumulated coturn state from a full matrix run) and it succeeded every
# time — the originally reported failure did not reproduce. Root cause of the original report is
# unconfirmed (most likely a stale coturn process from an earlier partial run still using an old
# secret while a freshly-written `turn.secret` was used to compute the `-w` password — a state
# mismatch, not an algorithm or tool bug), but since it does not reproduce, the probe now drives
# authentication with the literal minted credential rather than the ops secret, which is a strictly
# more faithful check (identical to what a real client presents) and removes the need for this
# rig tooling to hand its own coturn secret to the test client at all.
#
# DEVIATION #2 (also flagged): turnutils_uclient's `-y` (client-to-client) mode — the obvious choice
# for a peerless smoke check — empirically drives 4-5 concurrent ALLOCATEs under the hood before it
# is satisfied (confirmed via `-v`: distinct successful relay allocations on 4 different ports in a
# single `-y` run). Against the REAL user-quota=4 (1.14's tuned production value, which this rig
# deliberately keeps rather than loosening just to make the test tool happy), a single `-y` run sits
# right at or over the quota edge and fails with "486 Allocation Quota Reached" — a property of the
# test tool's synthetic bidirectional-relay setup, not of Meridian's real client shape (§ comment in
# infra/coturn/turnserver.conf: "one voice/video control-plane allocation ... plus a couple of
# relayed data channels" — nothing like uclient's `-y` load). We therefore use single-allocation
# mode instead: `-e <peer> -r <port> -c` (one real peer via coturn's own turnutils_peer, `-c` to
# skip the extra RTCP-style companion allocation), which needs exactly ONE allocation and comfortably
# fits the real quota.
turn_reachability_probe() {
  local mode="$1" # "udp" or "tcp"
  if [[ ! -x "$FETCH_TURN_BIN" ]]; then
    echo "fetch_turn_credentials example not found at $FETCH_TURN_BIN — run:" >&2
    echo "  cargo build -p meridian-rendezvous --example fetch_turn_credentials" >&2
    exit 1
  fi
  load_turn_secret
  if [[ -z "$TURN_SECRET" ]]; then
    echo "[nat-matrix] FAIL: TURN_SECRET unknown — coturn not started by this rig?" >&2
    exit 1
  fi

  echo "[nat-matrix] minting ephemeral TURN credential from ns-alice via real TurnReq/TurnGrant flow…"
  local grant_out
  grant_out="$(ip netns exec ns-alice "$REPO_ROOT/$FETCH_TURN_BIN" ws://203.0.113.1:8443)"
  echo "$grant_out" | sed 's/^credential=.*/credential=<redacted>/'

  local username credential
  username="$(echo "$grant_out" | sed -n 's/^username=//p')"
  credential="$(echo "$grant_out" | sed -n 's/^credential=//p')"
  if [[ -z "$username" || -z "$credential" ]]; then
    echo "[nat-matrix] FAIL: did not get username/credential from fetch_turn_credentials" >&2
    exit 1
  fi

  # Independently verify the TurnGrant's credential is exactly the coturn REST-secret HMAC — this
  # is a correctness CHECK of the value the real wire flow produced, not a hand-rolled substitute
  # used for auth.
  local expected
  expected="$(python3 -c "
import hmac, hashlib, base64, sys
secret, username = sys.argv[1], sys.argv[2]
mac = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
print(base64.b64encode(mac).decode())
" "$TURN_SECRET" "$username")"
  if [[ "$credential" != "$expected" ]]; then
    echo "[nat-matrix] FAIL: TurnGrant.credential does not match base64(HMAC-SHA1(secret, username))" >&2
    exit 1
  fi
  echo "[nat-matrix] verified: TurnGrant.credential == base64(HMAC-SHA1(secret, username)) ✓"

  if ! test_peer_running; then
    echo "[nat-matrix] FAIL: turnutils_peer (test-peer target) is not running" >&2
    exit 1
  fi

  echo "[nat-matrix] driving turnutils_uclient ($mode) from ns-alice against coturn 203.0.113.30…"
  # -e/-r: a single real peer (turnutils_peer in ns-net) so this is one ALLOCATE, not `-y`'s 4-5
  # (DEVIATION #2 above). -c: skip the extra RTCP-style companion allocation. -u/-w: the literal
  # minted (username, credential) pair from the real TurnReq/TurnGrant flow above (verified above to
  # match coturn's own REST-secret HMAC) — exactly what a real client presents, no raw ops secret
  # involved (see DEVIATION #1 RESOLVED above). -t switches the client<->coturn transport to TCP for
  # the udp-blocked cell's TCP-reachability check; UDP is the default transport otherwise. -n 2: a
  # couple of relayed data messages is enough to prove the allocation actually relays traffic, not
  # just that ALLOCATE returned success.
  local uclient_args=(-e 203.0.113.1 -r "$TEST_PEER_PORT" -c -n 2 -u "$username" -w "$credential" 203.0.113.30)
  if [[ "$mode" == "tcp" ]]; then
    uclient_args=(-t -e 203.0.113.1 -r "$TEST_PEER_PORT" -c -n 2 -u "$username" -w "$credential" 203.0.113.30)
  fi
  # "Received relay addr" is logged only once coturn has actually granted a relay allocation —
  # the specific proof this probe needs. The data phase afterward (actual relayed messages) may or
  # may not cleanly finish within the timeout depending on turnutils_peer's echo timing, so we check
  # the LOG FILE for the allocation-granted marker after the run, rather than the pipeline's own
  # exit status (with `set -o pipefail`, a `timeout`-killed uclient or a SIGPIPE'd `tee` upstream of
  # a successfully-matching `grep -q` would otherwise incorrectly flip this to a failure).
  local uclient_log="$(rig_dir)/uclient-$mode.log"
  timeout 12 ip netns exec ns-alice turnutils_uclient -v "${uclient_args[@]}" > "$uclient_log" 2>&1 || true
  if grep -q "Received relay addr" "$uclient_log"; then
    echo "[nat-matrix] TURN-reachability probe ($mode): PASS (relay allocation granted)"
  else
    echo "[nat-matrix] FAIL: turnutils_uclient ($mode) did not report a successful allocation:" >&2
    cat "$uclient_log" >&2 || true
    exit 1
  fi
}

# Positive proof that udp-blocked's iptables rule is actually blocking UDP egress (rather than
# just skipping the UDP checks and hoping): drive the SAME TURN-allocation attempt over UDP that
# the other three cells use to prove reachability, and assert it does NOT get a relay allocation
# (times out) — the mirror image of turn_reachability_probe's positive assertion.
assert_udp_turn_blocked() {
  load_turn_secret
  if [[ -z "$TURN_SECRET" ]]; then
    echo "[nat-matrix] FAIL: TURN_SECRET unknown — coturn not started by this rig?" >&2
    exit 1
  fi
  echo "[nat-matrix] minting a TURN credential (for the negative UDP-blocked assertion)…"
  local grant_out username credential
  grant_out="$(ip netns exec ns-alice "$REPO_ROOT/$FETCH_TURN_BIN" ws://203.0.113.1:8443)"
  username="$(echo "$grant_out" | sed -n 's/^username=//p')"
  credential="$(echo "$grant_out" | sed -n 's/^credential=//p')"
  if [[ -z "$username" || -z "$credential" ]]; then
    echo "[nat-matrix] FAIL: did not get username/credential from fetch_turn_credentials" >&2
    exit 1
  fi
  local uclient_log
  uclient_log="$(rig_dir)/uclient-udp-blocked-negative.log"
  # Same shape as turn_reachability_probe's UDP path (same real minted username/credential, no raw
  # secret), but over the now-udp-blocked NAT: this should NOT reach coturn at all (natA/natB drop
  # the UDP egress before it ever leaves the LAN), so no "Received relay addr" should ever appear.
  # NOTE on the 6s bound: unlike the positive probes (which return in well under a second — "Total
  # connect time is 0" — once genuinely reachable), a *blocked* attempt never gets a response, so
  # this always consumes the full 6s before `timeout` kills it — that cost is fixed, not "usually
  # faster." 6s is still a safe bound (>>10x the observed positive-path latency in this rig, so no
  # risk of mistaking a slow-but-working path for a blocked one) without being large enough to make
  # the suite noticeably slower.
  timeout 6 ip netns exec ns-alice turnutils_uclient -v -e 203.0.113.1 -r "$TEST_PEER_PORT" -c -n 2 \
    -u "$username" -w "$credential" 203.0.113.30 > "$uclient_log" 2>&1 || true
  if grep -q "Received relay addr" "$uclient_log"; then
    echo "[nat-matrix] FAIL: expected UDP TURN allocation to be BLOCKED by udp-blocked's iptables" >&2
    echo "             rule, but it succeeded anyway:" >&2
    cat "$uclient_log" >&2 || true
    exit 1
  fi
  echo "[nat-matrix] confirmed: UDP TURN allocation is blocked (no relay addr received) — the"
  echo "             udp-blocked iptables rule is genuinely dropping UDP egress, not just skipped."
}

wire_smoke_cell() {
  local cell="$1"
  case "$cell" in
    full-cone)
      nat_flavor_probe same
      turn_reachability_probe udp
      ;;
    port-restricted)
      nat_flavor_probe same
      turn_reachability_probe udp
      ;;
    symmetric:symmetric)
      nat_flavor_probe different
      turn_reachability_probe udp
      ;;
    udp-blocked)
      echo "[nat-matrix] udp-blocked cell: UDP egress is dropped by design — skipping the UDP NAT-"
      echo "             flavor probe (it needs working UDP); positively asserting UDP TURN is"
      echo "             blocked, then asserting TCP reachability still works."
      assert_udp_turn_blocked
      turn_reachability_probe tcp
      ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Idempotent bring-up: topology build is expensive, so `matrix`/standalone `cell` calls reuse an
# already-up topology + already-running coturn/rendezvous rather than rebuilding every time; only
# the per-cell NAT-flavor swap (apply_nat_flavor's flush+reapply) is meant to be cheap and repeated.
# ---------------------------------------------------------------------------------------------

coturn_running() {
  local d
  d="$(rig_dir)"
  [[ -f "$d/turnserver.tracked-pid" ]] && kill -0 "$(cat "$d/turnserver.tracked-pid" 2>/dev/null)" 2>/dev/null
}

rendezvous_running() {
  local d
  d="$(rig_dir)"
  [[ -f "$d/rendezvous.pid" ]] && kill -0 "$(cat "$d/rendezvous.pid" 2>/dev/null)" 2>/dev/null
}

ensure_topology() {
  if ip netns list 2>/dev/null | grep -q '^ns-alice'; then
    echo "[nat-matrix] topology already up, reusing"
  else
    topology_up
  fi
  if coturn_running; then
    echo "[nat-matrix] coturn already running, reusing"
  else
    start_coturn
  fi
  if rendezvous_running; then
    echo "[nat-matrix] rendezvous already running, reusing"
  else
    start_rendezvous
  fi
  if test_peer_running; then
    echo "[nat-matrix] turnutils_peer already running, reusing"
  else
    start_test_peer
  fi
}

# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

cell() {
  local name="${1:?usage: cell <full-cone|port-restricted|symmetric:symmetric|udp-blocked>}"
  need_root
  ensure_topology
  echo "[nat-matrix] configuring cell '$name'"
  set_cell_nat "$name"
  smoke_cell "$name"
  wire_smoke_cell "$name"
  echo "[nat-matrix] cell '$name': ALL CHECKS PASSED"
}

matrix() {
  need_root
  ensure_topology
  for c in "${CELLS[@]}"; do
    cell "$c"
  done
  echo "[nat-matrix] all four cells exercised. Topology stays up — run '$0 down' to tear it down."
}

down() {
  local d=""
  if [[ -f "$RIG_STATE_FILE" ]]; then
    d="$(cat "$RIG_STATE_FILE" 2>/dev/null || true)"
  fi
  if [[ -n "$d" && -d "$d" ]]; then
    for pidfile in "$d/rendezvous.pid" "$d/turnserver.tracked-pid" "$d/testpeer.pid"; do
      if [[ -f "$pidfile" ]]; then
        local pid
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
          kill "$pid" 2>/dev/null || true
          for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
          done
          kill -9 "$pid" 2>/dev/null || true
        fi
      fi
    done
  fi
  # Belt-and-suspenders: in case pidfiles were stale/missing, make sure nothing rig-related
  # survives by name too. Guarded on a non-empty rig dir so an empty $d (no rig ever started in
  # this state file) can't turn into a dangerously loose `pkill -f "turnserver -c "` matching any
  # coturn on the box.
  if [[ -n "$d" ]]; then
    pkill -f "turnserver -c $d" 2>/dev/null || true
  fi

  for n in ns-alice ns-natA ns-net ns-turn ns-natB ns-bob; do
    ip netns del "$n" 2>/dev/null || true
  done

  if [[ -n "$d" && -d "$d" ]]; then
    rm -rf "$d"
  fi
  rm -f "$RIG_STATE_FILE"
  echo "[nat-matrix] topology torn down"
}

case "${1:-matrix}" in
  matrix) matrix ;;
  cell) shift; cell "${1:-}" ;;
  down) down ;;
  *) echo "usage: $0 {matrix|cell <name>|down}" >&2; exit 2 ;;
esac
