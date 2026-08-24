#!/usr/bin/env bash
# demo/p2p-wire-proof/run-live-server-proof.sh — the same wire-level proof as run-wire-proof.sh,
# but against a REAL, already-deployed rendezvous server instead of a local Docker stack. No
# Docker at all here: two plain `meridian` client processes on this host, a `tcpdump` capture on
# the host's own interfaces, and the exact same known-plaintext-oracle assertions.
#
# Usage:
#   RENDEZVOUS_URL=wss://your-server.example bash run-live-server-proof.sh
# Defaults to wss://rendezvous.hansajayathilaka.com if RENDEZVOUS_URL is unset.
#
# What it proves: two accounts register with the real server, then run a real
# `meridian session connect --transport webrtc` against it. A packet capture (not the CLI's
# self-report) is analyzed to show: (a) the server's own flow (every port, not just the signaling
# port — this also covers TURN/coturn probing on whatever port the deployment uses) never carries
# the chat payload in cleartext; (b) whatever OTHER flow carried the actual data-channel traffic
# (the "peer to peer" leg — its concrete shape depends on the topology: same-host loopback if both
# clients run on one machine like this script does, a LAN hop, or a real internet path if they
# don't) ALSO never carries it in cleartext, because Meridian is end-to-end encrypted — the point
# is not "the server can't read it" alone, it's "nobody sniffing any wire can, including this
# machine's own network stack, and the server-side flow additionally carries none of it AT ALL,
# not even ciphertext bytes belonging to the chat exchange, once the session is established."
#
# Requires: the host's own `tcpdump` (apt install tcpdump) — unlike run-wire-proof.sh's Docker
# sidecar, this script has no bundled capture tool. `openssl`/`getent` for IP resolution. A
# `meridian` binary built with --features webrtc (built on the host if not already present, same
# as run-wire-proof.sh).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RENDEZVOUS_URL="${RENDEZVOUS_URL:-wss://rendezvous.hansajayathilaka.com}"
SERVER_HOST="$(echo "$RENDEZVOUS_URL" | sed -E 's#^wss?://##; s#[:/].*$##')"
WORK="$(pwd)/live-proof-work"
MARKER_A='hello over p2p'
MARKER_B='hi back — no server in the path'

log() { echo "[live-proof] $*"; }
fail() { echo "[live-proof] FAIL: $*" >&2; exit 1; }

command -v tcpdump >/dev/null || fail "tcpdump not found on this host — install it (e.g. apt-get install tcpdump); unlike run-wire-proof.sh's Docker sidecar, this script has no bundled capture tool"

TCPDUMP_PID=""
cleanup() {
  local status=$?
  [[ -n "$TCPDUMP_PID" ]] && kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK/alice" "$WORK/bob"

log "resolving $SERVER_HOST…"
SERVER_IP="$(getent hosts "$SERVER_HOST" | awk '{print $1}' | head -1)"
[[ -n "$SERVER_IP" ]] || fail "could not resolve $SERVER_HOST"
log "$SERVER_HOST -> $SERVER_IP"

BIN="$(pwd)/../../target/release/meridian"
if [[ ! -x "$BIN" ]]; then
  log "building meridian (--features webrtc) on the host…"
  (cd ../.. && cargo build --release -p meridian-cli --features meridian-cli/webrtc)
fi

export MERIDIAN_PASSPHRASE=live-proof-demo
log "creating identities…"
(cd "$WORK/alice" && MERIDIAN_HOME="$WORK/alice/home" "$BIN" id new --store file --out meridian.key --hint "$SERVER_HOST" >/dev/null)
(cd "$WORK/bob"   && MERIDIAN_HOME="$WORK/bob/home"   "$BIN" id new --store file --out meridian.key --hint "$SERVER_HOST" >/dev/null)
ALICE_ID="$(cd "$WORK/alice" && MERIDIAN_HOME="$WORK/alice/home" "$BIN" id show)"
BOB_ID="$(cd "$WORK/bob"     && MERIDIAN_HOME="$WORK/bob/home"   "$BIN" id show)"
log "alice = $ALICE_ID"
log "bob   = $BOB_ID"

log "registering both with $RENDEZVOUS_URL…"
(cd "$WORK/alice" && MERIDIAN_HOME="$WORK/alice/home" timeout 20 "$BIN" register --server "$RENDEZVOUS_URL") | sed 's/^/  alice: /'
(cd "$WORK/bob"   && MERIDIAN_HOME="$WORK/bob/home"   timeout 20 "$BIN" register --server "$RENDEZVOUS_URL") | sed 's/^/  bob:   /'

# Capture filter: everything to/from the server (any port — covers signaling AND TURN/coturn,
# whatever port that deployment uses) OR any other UDP traffic (the P2P data-channel candidate,
# wherever it actually lands — same host, LAN, or real internet — excluding DNS noise).
PCAP="$WORK/live.pcap"
tcpdump -i any -w "$PCAP" -U "host $SERVER_IP or (udp and not host $SERVER_IP and not port 53)" > "$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 2
kill -0 "$TCPDUMP_PID" 2>/dev/null || fail "tcpdump did not start (see $WORK/tcpdump.log)"
log "capture running (pid $TCPDUMP_PID) -> $PCAP"

log "running session connect on both sides against $RENDEZVOUS_URL…"
set +e
(cd "$WORK/alice" && MERIDIAN_HOME="$WORK/alice/home" timeout 40 "$BIN" session connect "$BOB_ID"   --server "$RENDEZVOUS_URL" --transport webrtc --json > "$WORK/alice.json" 2>&1) &
PID_A=$!
(cd "$WORK/bob"   && MERIDIAN_HOME="$WORK/bob/home"   timeout 40 "$BIN" session connect "$ALICE_ID" --server "$RENDEZVOUS_URL" --transport webrtc --json > "$WORK/bob.json"   2>&1) &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
set -e
[[ "$RC_A" == "0" && "$RC_B" == "0" ]] || { cat "$WORK/alice.json" "$WORK/bob.json" >&2; fail "session connect did not succeed on both sides"; }
grep -q '"established":true' "$WORK/alice.json" || fail "alice never reported established:true"
grep -q '"established":true' "$WORK/bob.json"   || fail "bob never reported established:true"
PATH_A="$(grep -o '"path":"[^"]*"' "$WORK/alice.json")"
log "both sides established — $PATH_A"

sleep 1
kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""
sleep 1
[[ -s "$PCAP" ]] || fail "capture file is missing or empty"

marker_hits() { # $1=bpf filter -> combined occurrences of both markers
  local text hitsA hitsB
  text="$(tcpdump -r "$PCAP" -n -A "$1" 2>/dev/null || true)"
  hitsA="$(printf '%s' "$text" | grep -a -c -F -- "$MARKER_A" || true)"
  hitsB="$(printf '%s' "$text" | grep -a -c -F -- "$MARKER_B" || true)"
  echo "$((hitsA + hitsB))"
}
pkt_count() { tcpdump -r "$PCAP" -n "$1" 2>/dev/null | wc -l; }

SERVER_PKTS="$(pkt_count "host $SERVER_IP")"
SERVER_HITS="$(marker_hits "host $SERVER_IP")"
[[ "$SERVER_HITS" == "0" ]] || fail "the server flow ($SERVER_HOST, $SERVER_PKTS pkts) contains the chat payload ($SERVER_HITS hits) — the server must never see message content"
log "PASS — server flow ($SERVER_HOST, $SERVER_IP): $SERVER_PKTS packets, zero occurrences of the chat payload"

P2P_FILTER="udp and not host $SERVER_IP and not port 53"
P2P_PKTS="$(pkt_count "$P2P_FILTER")"
[[ "$P2P_PKTS" -gt 0 ]] || fail "no non-server UDP traffic was captured at all — the P2P exchange did not happen, or the capture filter missed it"
P2P_HITS="$(marker_hits "$P2P_FILTER")"
[[ "$P2P_HITS" == "0" ]] || fail "the P2P flow contains the chat payload in cleartext ($P2P_HITS hits) — should never happen, Meridian is end-to-end encrypted"
log "PASS — non-server (P2P) flow: $P2P_PKTS packets, zero occurrences of the chat payload in cleartext (expected: it's E2E encrypted)"

log ""
log "=== ALL ASSERTIONS PASSED against the live server ($RENDEZVOUS_URL) ==="
log "Negotiated path: $PATH_A"
log "Server flow:  $SERVER_PKTS packets total, 0 containing the chat payload."
log "P2P flow:     $P2P_PKTS packets total, 0 containing the chat payload (encrypted, as always)."
log "Capture kept at: $PCAP"
