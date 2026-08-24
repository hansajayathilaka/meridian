#!/usr/bin/env bash
# demo/p2p-wire-proof/run-wire-proof.sh — Docker-based wire-level proof of Meridian's core P2P
# claim (see README.md): a chat message crosses the network directly, client-to-client, and the
# rendezvous (signaling) server never carries or logs its content — proven from a real packet
# capture, not from the CLI's self-report.
#
# What it does, in order:
#   1. Builds the two binaries on the HOST (not inside the image — see Dockerfile's header) and
#      brings up rendezvous + coturn + alice + bob on a static-IP docker-compose network.
#   2. Starts a packet-capture sidecar (`monitor`, network_mode: host, tcpdump -i any) that sees
#      every container's traffic. NOTE: capturing on the compose network's own bridge master
#      device (e.g. `br-xxxx`) does NOT show container-to-container unicast traffic in this
#      environment (verified experimentally: a bridge-device capture recorded zero packets for a
#      real, successful ping between two containers on that bridge) — only `-i any` (Linux's
#      capture-every-interface pseudo-device, which taps each veth individually) does. This means
#      every packet is recorded twice (once per interface it crosses) — harmless for the
#      presence/absence assertions below, which only ever check "was there traffic" or "was the
#      payload present", not exact counts. Scoped to the demo's own subnet via a capture filter so
#      the host's own unrelated traffic (real internet egress on the host's actual interface,
#      also visible under `-i any` + `network_mode: host`) is never recorded at all.
#   3. alice/bob create identities and register with the rendezvous.
#   4. Phase A (direct policy, the default): both sides run `meridian session connect --transport
#      webrtc`. Asserts, from the capture: alice<->bob carries real traffic (the P2P exchange
#      actually happened on that flow); NO flow, including alice<->bob's own direct leg, ever
#      shows the chat payload in cleartext — it's end-to-end encrypted, so that absence is
#      expected everywhere, not just at the server (see the assertion-helpers comment below).
#   5. Phase B (relay-only policy): both sides set `config set policy relay-only` and connect
#      again. Asserts: alice<->bob direct traffic is EMPTY (candidates never even offered); TURN
#      (coturn) relay traffic exists (real packet volume) but, like every other flow, never in
#      cleartext.
#   6. Greps the rendezvous container's own logs for the chat payload — zero occurrences (mirrors
#      demo/two-orgs's convention).
#   7. Stops rendezvous + coturn, then shows a second `session connect` attempt fails — an honest
#      demonstration of what the server is actually needed for (bootstrapping a NEW session via
#      signaling) versus not needed for (carrying already-established message content), so this
#      demo never overclaims "the server is needed for nothing at all".
#
# Assertion style mirrors tools/netns-nat-matrix.sh's pcap assertions (tcpdump -r/-A + grep -a,
# deliberately no tshark/bespoke parser) and its fail-closed posture: a missing/empty/unreadable
# capture is always a FAIL, never a silent PASS.
#
# Usage: bash run-wire-proof.sh   (tears the stack down on exit; KEEP_UP=1 to leave it running)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PROJECT=p2p-wire-proof
NET="${PROJECT}_p2p-net"
CAPTURE_DIR="$(pwd)/capture"
RENDEZVOUS="ws://172.30.0.10:8443"
ALICE_IP=172.30.0.21
BOB_IP=172.30.0.22
RENDEZVOUS_IP=172.30.0.10
COTURN_IP=172.30.0.11
# The literal, fixed chat strings apps/cli/src/session_connect.rs's `run_webrtc` sends as real
# application data over the established P2P session (initiator/responder respectively) — the
# same known-plaintext oracle tools/netns-nat-matrix.sh uses.
MARKER_A='hello over p2p'
MARKER_B='hi back — no server in the path'

log() { echo "[wire-proof] $*"; }
fail() { echo "[wire-proof] FAIL: $*" >&2; exit 1; }

MONITOR_STARTED=0
cleanup() {
  local status=$?
  if [[ "${KEEP_UP:-0}" == "1" ]]; then
    log "KEEP_UP=1 — leaving the stack running. Tear down with:"
    log "  docker rm -f ${PROJECT}-monitor >/dev/null 2>&1; docker compose -p $PROJECT down -v"
    exit "$status"
  fi
  [[ "$MONITOR_STARTED" == "1" ]] && docker rm -f "${PROJECT}-monitor" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" down -v >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

exec_alice() { docker compose -p "$PROJECT" exec -T -e MERIDIAN_HOME=/home/meridian -e MERIDIAN_PASSPHRASE=wire-proof-demo alice "$@"; }
exec_bob()   { docker compose -p "$PROJECT" exec -T -e MERIDIAN_HOME=/home/meridian -e MERIDIAN_PASSPHRASE=wire-proof-demo bob "$@"; }

# ---------------------------------------------------------------------------------------------
# 1. Bring up the stack
# ---------------------------------------------------------------------------------------------
mkdir -p "$CAPTURE_DIR"
rm -f "$CAPTURE_DIR"/*.pcap "$CAPTURE_DIR"/rendezvous.log

log "building meridian-rendezvous (--features sqlite) + meridian (--features webrtc) on the host…"
(cd ../.. && cargo build --release -p meridian-rendezvous --features sqlite -p meridian-cli --features meridian-cli/webrtc)
mkdir -p bin
cp ../../target/release/meridian-rendezvous ../../target/release/meridian bin/

export TURN_SHARED_SECRET
TURN_SHARED_SECRET="$(openssl rand -hex 32)"

log "docker compose up (build + start rendezvous, coturn, alice, bob)…"
docker compose -p "$PROJECT" up -d --build

log "waiting for rendezvous to accept connections…"
for _ in $(seq 1 30); do
  exec_alice /usr/local/bin/meridian doctor --json >/dev/null 2>&1 && break || true
  sleep 1
done

# ---------------------------------------------------------------------------------------------
# 2. Start the capture sidecar
# ---------------------------------------------------------------------------------------------
docker network inspect "$NET" >/dev/null || fail "compose network $NET not found — cannot attach the capture sidecar"

docker rm -f "${PROJECT}-monitor" >/dev/null 2>&1 || true
docker run -d --name "${PROJECT}-monitor" --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$CAPTURE_DIR:/capture" nicolaka/netshoot \
  tcpdump -i any -w /capture/live.pcap -U net 172.30.0.0/24 >/dev/null
MONITOR_STARTED=1
sleep 2
docker exec "${PROJECT}-monitor" sh -c 'pgrep tcpdump >/dev/null' || fail "tcpdump did not start in the monitor container"
log "capture running: ${PROJECT}-monitor → capture/live.pcap"

split_capture() {
  # Snapshot the live capture into a phase-named file and truncate what's tracked so each phase's
  # assertions only see that phase's traffic. tcpdump -U flushes per-packet, so the snapshot is
  # current as of "now" within one packet's latency.
  local name="$1"
  docker exec "${PROJECT}-monitor" sh -c "pkill -INT tcpdump" >/dev/null 2>&1 || true
  sleep 1
  cp "$CAPTURE_DIR/live.pcap" "$CAPTURE_DIR/$name.pcap"
  docker rm -f "${PROJECT}-monitor" >/dev/null 2>&1 || true
  rm -f "$CAPTURE_DIR/live.pcap"
  docker run -d --name "${PROJECT}-monitor" --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$CAPTURE_DIR:/capture" nicolaka/netshoot \
    tcpdump -i any -w /capture/live.pcap -U net 172.30.0.0/24 >/dev/null
  sleep 1
}

# ---------------------------------------------------------------------------------------------
# 3. Identities + registration
# ---------------------------------------------------------------------------------------------
log "creating identities and registering with the rendezvous…"
exec_alice /usr/local/bin/meridian id new --store file --out /home/meridian/alice.key --hint p2pdemo.local >/dev/null
exec_bob   /usr/local/bin/meridian id new --store file --out /home/meridian/bob.key   --hint p2pdemo.local >/dev/null
ALICE_ID="$(exec_alice /usr/local/bin/meridian id show)"
BOB_ID="$(exec_bob   /usr/local/bin/meridian id show)"
log "alice = $ALICE_ID"
log "bob   = $BOB_ID"
exec_alice /usr/local/bin/meridian register --server "$RENDEZVOUS" >/dev/null
exec_bob   /usr/local/bin/meridian register --server "$RENDEZVOUS" >/dev/null

# ---------------------------------------------------------------------------------------------
# Assertion helpers (mirror tools/netns-nat-matrix.sh's style: tcpdump -r/-A + grep -a, fail
# closed on a missing/empty/unreadable capture — never treat "couldn't check" as a pass).
#
# Analysis runs INSIDE the monitor container (netshoot has tcpdump; the host may not — the whole
# point of the sidecar design is that a capture-analysis tool ships with the demo, not as an
# assumed host dependency). $1 below is always a pcap BASENAME (e.g. "phaseA.pcap"); the file
# lives at both "$CAPTURE_DIR/<name>" on the host (for the existence check) and "/capture/<name>"
# inside the monitor container (bind-mounted, same volume) — see run.
# ---------------------------------------------------------------------------------------------
pcap_exec() { docker exec "${PROJECT}-monitor" "$@"; }

flow_count() { # $1=pcap-basename $2=hostA $3=hostB -> IP-layer packet count on that host pair
  # "and ip" excludes ARP (L2 address resolution — no payload, not itself an exposure of a
  # host/srflx candidate or any application data; matches what tools/netns-nat-matrix.sh's own
  # zero-leak assertion cares about: real IP-layer traffic reaching the peer, not neighbor-table
  # chatter). Verified experimentally: relay-only sessions on this rig always show a handful of
  # ARP frames between alice/bob (harmless OS-level neighbor resolution) but zero IP packets.
  pcap_exec tcpdump -r "/capture/$1" -n "host $2 and host $3 and ip" 2>/dev/null | wc -l
}
flow_marker_hits() { # $1=pcap-basename $2=hostA $3=hostB -> combined occurrences of both markers
  local text hitsA hitsB
  text="$(pcap_exec tcpdump -r "/capture/$1" -n -A "host $2 and host $3 and ip" 2>/dev/null || true)"
  hitsA="$(printf '%s' "$text" | grep -a -c -F -- "$MARKER_A" || true)"
  hitsB="$(printf '%s' "$text" | grep -a -c -F -- "$MARKER_B" || true)"
  echo "$((hitsA + hitsB))"
}

assert_no_leak() { # $1=phase $2=pcap-basename $3=label $4=hostA $5=hostB
  local phase="$1" pcap="$2" label="$3" a="$4" b="$5"
  [[ -s "$CAPTURE_DIR/$pcap" ]] || fail "$phase: capture $pcap is missing or empty — cannot verify $label"
  local hits
  hits="$(flow_marker_hits "$pcap" "$a" "$b")"
  [[ "$hits" == "0" ]] || fail "$phase: $label carries the chat payload ($hits hit(s)) — a server/relay must never see message content"
  log "$phase: PASS — $label carries zero occurrences of the chat payload"
}

# NOTE: there is deliberately no "assert the plaintext chat marker appears here" check anywhere,
# on ANY flow — including alice<->bob's own direct leg. Meridian is end-to-end encrypted: the
# ratchet encrypts the chat body itself, and T04 additionally wraps SDP/ICE in ratchet-encrypted
# envelopes and DTLS-encrypts the data-channel bytes on top of that. The marker string is
# therefore never expected to appear as cleartext on ANY wire, direct or relayed or
# server-routed — that absence, everywhere, uniformly, IS the E2EE guarantee. "Proof of direct
# delivery" below is instead traffic PRESENCE (packet counts) on the right flow, not content.

assert_nonempty_flow() { # $1=phase $2=pcap-basename $3=label $4=hostA $5=hostB (packets MUST exist here)
  local phase="$1" pcap="$2" label="$3" a="$4" b="$5"
  [[ -s "$CAPTURE_DIR/$pcap" ]] || fail "$phase: capture $pcap is missing or empty — cannot verify $label"
  local n
  n="$(flow_count "$pcap" "$a" "$b")"
  [[ "$n" -gt "0" ]] || fail "$phase: $label saw zero packets — the exchange did not actually happen on this flow"
  log "$phase: PASS — $label carried $n packet(s) — confirmed real traffic on this path"
}

assert_empty_flow() { # $1=phase $2=pcap-basename $3=label $4=hostA $5=hostB (zero packets at all)
  local phase="$1" pcap="$2" label="$3" a="$4" b="$5"
  [[ -s "$CAPTURE_DIR/$pcap" ]] || fail "$phase: capture $pcap is missing or empty — cannot verify $label"
  local n
  n="$(flow_count "$pcap" "$a" "$b")"
  [[ "$n" == "0" ]] || fail "$phase: $label is supposed to be silent under relay-only policy but saw $n packet(s) — a host/srflx candidate leaked"
  log "$phase: PASS — $label is silent (0 packets) under relay-only policy"
}

# `session connect` is a one-shot, stateless-across-runs command (no persisted ChatState — see
# session_connect.rs's header) with no internal retry for the dial/route step, unlike `chat`'s
# bounded-resend loop. A fresh rendezvous connection's "is this account online for routing"
# bookkeeping can lag its own bundle-publish by a beat, which shows up as a one-shot "recipient
# offline" on the dialer's side even though the peer is genuinely up and about to answer — so
# retry the WHOLE pair (never just one side) a bounded number of times rather than treating a
# single attempt as authoritative.
connect_both() { # $1=out-prefix (e.g. capture/phaseA)
  local prefix="$1" attempt
  for attempt in 1 2 3 4 5; do
    set +e
    exec_alice /usr/local/bin/meridian session connect "$BOB_ID"   --server "$RENDEZVOUS" --transport webrtc --json > "${prefix}-alice.json" 2>&1 &
    local pid_a=$!
    exec_bob   /usr/local/bin/meridian session connect "$ALICE_ID" --server "$RENDEZVOUS" --transport webrtc --json > "${prefix}-bob.json"   2>&1 &
    local pid_b=$!
    wait "$pid_a"; local rc_a=$?
    wait "$pid_b"; local rc_b=$?
    set -e
    if [[ "$rc_a" == "0" && "$rc_b" == "0" ]]; then
      return 0
    fi
    log "connect attempt $attempt/5 did not succeed on both sides (rc_a=$rc_a rc_b=$rc_b) — retrying"
    sleep 2
  done
  cat "${prefix}-alice.json" "${prefix}-bob.json" >&2
  fail "session connect did not succeed on both sides after 5 attempts"
}

# ---------------------------------------------------------------------------------------------
# 4. Phase A — direct policy (the default): real P2P over the docker bridge
# ---------------------------------------------------------------------------------------------
log "=== Phase A: direct policy — establishing a real P2P session ==="
connect_both "$CAPTURE_DIR/phaseA"
grep -q '"established":true' "$CAPTURE_DIR/phaseA-alice.json" || fail "Phase A: alice never reported established:true"
grep -q '"established":true' "$CAPTURE_DIR/phaseA-bob.json"   || fail "Phase A: bob never reported established:true"
log "both sides report established:true — $(grep -o '"path":"[^"]*"' "$CAPTURE_DIR/phaseA-alice.json")"

split_capture phaseA

assert_nonempty_flow phaseA phaseA.pcap "alice<->bob direct traffic"   "$ALICE_IP" "$BOB_IP"
assert_no_leak  phaseA phaseA.pcap "alice<->bob direct traffic (plaintext check)" "$ALICE_IP" "$BOB_IP"
assert_no_leak  phaseA phaseA.pcap "rendezvous<->alice traffic"        "$RENDEZVOUS_IP" "$ALICE_IP"
assert_no_leak  phaseA phaseA.pcap "rendezvous<->bob traffic"          "$RENDEZVOUS_IP" "$BOB_IP"

# ---------------------------------------------------------------------------------------------
# 5. Phase B — relay-only policy: forced through coturn
# ---------------------------------------------------------------------------------------------
log "=== Phase B: relay-only policy — forcing the session through TURN ==="
exec_alice /usr/local/bin/meridian config set policy relay-only >/dev/null
exec_bob   /usr/local/bin/meridian config set policy relay-only >/dev/null

connect_both "$CAPTURE_DIR/phaseB"
grep -q '"established":true' "$CAPTURE_DIR/phaseB-alice.json" || fail "Phase B: alice never reported established:true"
log "both sides report established:true — $(grep -o '"path":"[^"]*"' "$CAPTURE_DIR/phaseB-alice.json")"

split_capture phaseB

assert_empty_flow phaseB phaseB.pcap "alice<->bob direct traffic"     "$ALICE_IP" "$BOB_IP"
# coturn must carry the relayed session (checked below via packet count) but never in cleartext —
# it relays DTLS ciphertext only, the same "known-plaintext oracle" proof as nat-matrix's
# assert_dtls_ciphertext_only.
assert_no_leak     phaseB phaseB.pcap "alice<->coturn relay traffic (plaintext check)" "$ALICE_IP" "$COTURN_IP"
assert_no_leak     phaseB phaseB.pcap "bob<->coturn relay traffic (plaintext check)"   "$BOB_IP"   "$COTURN_IP"
assert_no_leak     phaseB phaseB.pcap "rendezvous<->alice traffic"    "$RENDEZVOUS_IP" "$ALICE_IP"
assert_no_leak     phaseB phaseB.pcap "rendezvous<->bob traffic"      "$RENDEZVOUS_IP" "$BOB_IP"

n_alice_coturn="$(flow_count phaseB.pcap "$ALICE_IP" "$COTURN_IP")"
n_bob_coturn="$(flow_count phaseB.pcap "$BOB_IP" "$COTURN_IP")"
[[ "$n_alice_coturn" -gt 0 && "$n_bob_coturn" -gt 0 ]] || fail "Phase B: relay-only policy connected but no traffic reached coturn — the relay path was not actually exercised"
log "PASS — coturn actually carried the session (alice: $n_alice_coturn pkts, bob: $n_bob_coturn pkts), zero of it in cleartext"

# ---------------------------------------------------------------------------------------------
# 6. Server-side log check (mirrors demo/two-orgs's convention)
# ---------------------------------------------------------------------------------------------
docker compose -p "$PROJECT" logs rendezvous > "$CAPTURE_DIR/rendezvous.log" 2>&1
if grep -qF -- "$MARKER_A" "$CAPTURE_DIR/rendezvous.log" || grep -qF -- "$MARKER_B" "$CAPTURE_DIR/rendezvous.log"; then
  fail "the rendezvous server's own logs contain the chat payload"
fi
log "PASS — rendezvous server logs contain zero occurrences of the chat payload"

# ---------------------------------------------------------------------------------------------
# 7. Honest boundary check: the server IS required to bootstrap a NEW session (never overclaim)
# ---------------------------------------------------------------------------------------------
log "=== Boundary check: stopping rendezvous + coturn, then trying to start a THIRD session ==="
docker compose -p "$PROJECT" stop rendezvous coturn >/dev/null
set +e
timeout 15 docker compose -p "$PROJECT" exec -T -e MERIDIAN_HOME=/home/meridian -e MERIDIAN_PASSPHRASE=wire-proof-demo \
  alice /usr/local/bin/meridian session connect "$BOB_ID" --server "$RENDEZVOUS" --transport webrtc --json \
  > "$CAPTURE_DIR/phaseC-alice.json" 2>&1
RC_C=$?
set -e
if [[ "$RC_C" == "0" ]]; then
  fail "a NEW session connect succeeded with rendezvous+coturn stopped — this would mean signaling isn't actually required to bootstrap, contradicting the architecture"
fi
log "PASS — with the rendezvous stopped, a NEW session cannot be established (rc=$RC_C) — confirms the server's actual role: bootstrapping only, never message content"

log ""
log "=== ALL ASSERTIONS PASSED ==="
log "Phase A (direct):     alice<->bob carried the session directly, client-to-client."
log "Phase B (relay-only): alice<->bob was silent; coturn carried the (encrypted) session instead."
log "Everywhere, always:    zero occurrences of the chat payload in cleartext — rendezvous, coturn, and even alice<->bob's own direct leg."
log "Server logs:           zero occurrences of the chat payload."
log "Boundary:              the server is needed to bootstrap a NEW session, never to carry an established one's content."
log "Captures kept at: $CAPTURE_DIR/{phaseA,phaseB}.pcap"
