#!/usr/bin/env bash
# demo/two-orgs/run-walkthrough.sh — the scripted feature-06 §7.1 walkthrough (task 2.11).
#
# Brings up the two-org federation demo under ONE discovery mode (static federation map — the
# air-gap default — or DNS SRV), then drives the real `meridian` CLI inside the `client` container
# (see docker-compose.yml's header) to:
#   1. create + register alice@org-a.test and bob@org-b.test (each publishes a prekey bundle),
#   2. send a chat message across the org boundary and confirm it lands in the recipient's
#      message-request queue, then is delivered once accepted (task 2.10's first-contact gate),
#   3. (unless SKIP_P2P=1) establish a real P2P session across the same org boundary — real
#      ICE/DTLS, using the stack's own coturn relays for ephemeral-credentialed TURN — and check
#      both sides report a verified DTLS fingerprint,
#   4. prove neither rendezvous ever saw the plaintext, by grepping its own container logs for the
#      literal message body this run generated (see the "plaintext" note below on why a literal
#      grep for the word "plaintext" is a trap, not a check).
#
# Exits non-zero on ANY failed assertion — this is the acceptance demo, not a smoke test.
#
# Usage:
#   bash run-walkthrough.sh [static|srv]     # discovery mode; default static (the air-gap default)
#   KEEP_UP=1   bash run-walkthrough.sh       # leave the stack running after the script exits
#   SKIP_P2P=1  bash run-walkthrough.sh       # skip the `session connect` (real WebRTC/DTLS) leg
#
# See README.md for the full narrative, both modes, and troubleshooting.

set -euo pipefail

MODE="${1:-static}"
case "$MODE" in
  static|srv) ;;
  *) echo "usage: $0 [static|srv]" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------------------------
for bin in docker openssl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done
if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose (v2, the 'docker compose' plugin) is required" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable — start it (e.g. 'dockerd &') first" >&2
  exit 1
fi

COMPOSE=(docker compose -f docker-compose.yml -f "docker-compose.$MODE.yml")
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/meridian-two-orgs.XXXXXX")"
PASS="demo-not-a-real-secret"  # local file-store passphrase for this ephemeral run only

log() { printf '\n>>> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  # Best-effort: never let cleanup itself mask the real exit code.
  set +e
  # `docker compose down` below tears down the exec streams these belong to anyway, but kill them
  # explicitly rather than relying on that implicitly — especially on a `fail` path before either
  # process would otherwise exit on its own.
  [ -n "${RESP_PID:-}" ] && kill "$RESP_PID" 2>/dev/null
  [ -n "${INIT_PID:-}" ] && kill "$INIT_PID" 2>/dev/null
  if [ "${KEEP_UP:-0}" != "1" ]; then
    log "tearing down ($MODE mode)"
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  else
    log "KEEP_UP=1 — leaving the stack running (docker compose -f docker-compose.yml -f docker-compose.$MODE.yml ...)"
  fi
  rm -rf "$SCRATCH"
  exit "$code"
}
trap cleanup EXIT

exec_client() {
  # exec_client <MERIDIAN_HOME> <cli args...> — runs `meridian` in the client container as a given
  # identity's home. `-T`: no TTY, this is scripted.
  local home="$1"; shift
  "${COMPOSE[@]}" exec -T -e "MERIDIAN_HOME=$home" -e "MERIDIAN_PASSPHRASE=$PASS" client meridian "$@"
}

retry() {
  # retry <tries> <cmd...> — polls until <cmd> succeeds or <tries> attempts are exhausted.
  local tries="$1"; shift
  local n=0
  until "$@" >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -ge "$tries" ] && return 1
    sleep 1
  done
  return 0
}

wait_for() {
  # wait_for <file> <pattern> <timeout_s> — polls a log file for a substring.
  local f="$1" pat="$2" timeout="${3:-30}" waited=0
  while ! grep -qF "$pat" "$f" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge $((timeout * 2)) ]; then
      echo "--- timed out waiting for '$pat' in $f ---" >&2
      cat "$f" >&2 2>/dev/null || true
      return 1
    fi
    sleep 0.5
  done
}

container_healthy() {
  local cid
  cid="$("${COMPOSE[@]}" ps -q "$1" 2>/dev/null)"
  [ -n "$cid" ] || return 1
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = "healthy" ]
}

# ---------------------------------------------------------------------------------------------
# 0. Private CA (reuses infra/deploy/bootstrap-ca.sh — never forked) + ephemeral TURN secret
# ---------------------------------------------------------------------------------------------
log "bootstrapping the private CA into ./.ca (gitignored)"
bash ../../infra/deploy/bootstrap-ca.sh "$SCRIPT_DIR/.ca"

export TURN_SHARED_SECRET
TURN_SHARED_SECRET="$(openssl rand -hex 32)"

# ---------------------------------------------------------------------------------------------
# 1. Bring up the stack under the requested discovery mode
# ---------------------------------------------------------------------------------------------
log "bringing up the stack ($MODE discovery mode) — this builds the demo image on first run"
"${COMPOSE[@]}" up -d --build

log "waiting for rendezvous-a / rendezvous-b to report healthy"
for svc in rendezvous-a rendezvous-b; do
  retry 60 container_healthy "$svc" || fail "$svc never became healthy — 'docker compose logs $svc' for detail"
done

# Air-gap sanity check (deployment.md §9.3): the demo network is `internal: true`, so egress must
# be structurally impossible, not merely unconfigured. A quick negative check from inside the
# client container — not a substitute for a real packet capture, but cheap and load-bearing.
log "confirming the demo network has no external egress (air-gap check)"
if "${COMPOSE[@]}" exec -T client curl -s -m 3 -o /dev/null https://1.1.1.1 2>/dev/null; then
  fail "client container reached the public internet — the 'internal: true' air-gap network is not actually air-gapped"
fi
echo "confirmed: no external egress from the demo network"

if [ "$MODE" = "srv" ]; then
  log "confirming DNS SRV discovery is genuinely exercised (not faked)"
  "${COMPOSE[@]}" exec -T client dig +short SRV _meridian-fed._tcp.org-b.test @172.28.0.53 \
    | grep -q "rendezvous-b" || fail "no real _meridian-fed._tcp.org-b.test SRV record resolved"
  echo "confirmed: _meridian-fed._tcp.org-b.test SRV → rendezvous-b:8444 (real DNS, not a fake)"
fi

# ---------------------------------------------------------------------------------------------
# 2. Create + register alice@org-a.test and bob@org-b.test
# ---------------------------------------------------------------------------------------------
ALICE_HOME=/tmp/alice-home
BOB_HOME=/tmp/bob-home

log "creating alice@org-a.test and bob@org-b.test"
exec_client "$ALICE_HOME" id new --store file --out /tmp/alice.key --hint org-a.test >/dev/null
exec_client "$BOB_HOME"   id new --store file --out /tmp/bob.key   --hint org-b.test >/dev/null

ALICE_ID="$(exec_client "$ALICE_HOME" id show | tr -d '\r')"
BOB_ID="$("${COMPOSE[@]}"   exec -T -e "MERIDIAN_HOME=$BOB_HOME" client meridian id show | tr -d '\r')"
[ -n "$ALICE_ID" ] && [ -n "$BOB_ID" ] || fail "could not read back alice/bob's mrd1: IDs"
echo "alice: $ALICE_ID"
echo "bob:   $BOB_ID"

log "registering both accounts with their own org's rendezvous (through the TLS-terminating edge)"
retry 30 exec_client "$ALICE_HOME" register --server wss://org-a.test:8443 \
  || fail "alice failed to register with org-a.test"
retry 30 exec_client "$BOB_HOME"   register --server wss://org-b.test:8443 \
  || fail "bob failed to register with org-b.test"
echo "both accounts registered (each published a prekey bundle)"

# Deterministic role assignment (mirrors chat.rs: the lexicographically-smaller identity key
# initiates), so the script knows which side must type the opening line versus which side only
# needs to be online and answer the message-request prompt.
ALICE_KEY="$(exec_client "$ALICE_HOME" id parse "$ALICE_ID" | awk '/^key:/ {print $2}')"
BOB_KEY="$("${COMPOSE[@]}"   exec -T -e "MERIDIAN_HOME=$BOB_HOME" client meridian id parse "$BOB_ID" | awk '/^key:/ {print $2}')"
if [ "$(LC_ALL=C printf '%s\n%s\n' "$ALICE_KEY" "$BOB_KEY" | sort | head -n1)" = "$ALICE_KEY" ]; then
  INITIATOR=alice; RESPONDER=bob
else
  INITIATOR=bob; RESPONDER=alice
fi
echo "role assignment (by key order, same rule chat.rs uses): $INITIATOR initiates, $RESPONDER responds"

# ---------------------------------------------------------------------------------------------
# 3. Cross-org chat: message-request gate, then delivery, once accepted
# ---------------------------------------------------------------------------------------------
declare -A HOMES=( [alice]="$ALICE_HOME" [bob]="$BOB_HOME" )
declare -A SERVER=( [alice]="wss://org-a.test:8443" [bob]="wss://org-b.test:8443" )
declare -A IDOF=( [alice]="$ALICE_ID" [bob]="$BOB_ID" )

RESP_FIFO="$SCRATCH/${RESPONDER}.fifo"; mkfifo "$RESP_FIFO"
exec {RESP_FD}<>"$RESP_FIFO"   # read+write on our own fd: keeps the fifo from EOFing, non-blocking

log "starting $RESPONDER's chat session (must be online before $INITIATOR sends the opening message)"
"${COMPOSE[@]}" exec -T -e "MERIDIAN_HOME=${HOMES[$RESPONDER]}" -e "MERIDIAN_PASSPHRASE=$PASS" client \
  meridian chat --json --server "${SERVER[$RESPONDER]}" "${IDOF[$INITIATOR]}" \
  <"$RESP_FIFO" >"$SCRATCH/${RESPONDER}_chat.log" 2>&1 &
RESP_PID=$!

# Give the responder a moment to connect + publish its (fresh) bundle before the initiator fetches it.
sleep 3

INIT_FIFO="$SCRATCH/${INITIATOR}.fifo"; mkfifo "$INIT_FIFO"
exec {INIT_FD}<>"$INIT_FIFO"

log "starting $INITIATOR's chat session"
"${COMPOSE[@]}" exec -T -e "MERIDIAN_HOME=${HOMES[$INITIATOR]}" -e "MERIDIAN_PASSPHRASE=$PASS" client \
  meridian chat --json --server "${SERVER[$INITIATOR]}" "${IDOF[$RESPONDER]}" \
  <"$INIT_FIFO" >"$SCRATCH/${INITIATOR}_chat.log" 2>&1 &
INIT_PID=$!
sleep 2

MSG="hello-across-orgs-$(date +%s)-$RANDOM"
log "sending from $INITIATOR to $RESPONDER: \"$MSG\""
echo "$MSG" >&"$INIT_FD"

log "waiting for $INITIATOR's send to be routed"
wait_for "$SCRATCH/${INITIATOR}_chat.log" '"event":"sent"' 20 \
  || fail "$INITIATOR's message was never routed"
grep -F '"event":"sent"' "$SCRATCH/${INITIATOR}_chat.log" | grep -q '"delivered":true' \
  || fail "$INITIATOR's message was routed but NOT delivered — $RESPONDER's rendezvous connection wasn't live (federation/delivery broken)"
echo "confirmed: $INITIATOR's message was routed cross-org and delivered while $RESPONDER was online"

log "waiting for $RESPONDER's message-request gate (task 2.10: first contact is queued, not auto-delivered)"
wait_for "$SCRATCH/${RESPONDER}_chat.log" '"event":"message_request"' 20 \
  || fail "$RESPONDER never saw a message_request event — the first-contact gate (2.10) did not fire"
echo "confirmed: the cross-org message landed in $RESPONDER's message-request queue, not auto-delivered"

log "accepting the request as $RESPONDER"
echo "y" >&"$RESP_FD"
wait_for "$SCRATCH/${RESPONDER}_chat.log" '"event":"request_accepted"' 10 \
  || fail "$RESPONDER's accept did not register"
wait_for "$SCRATCH/${RESPONDER}_chat.log" "\"body\":\"$MSG\"" 10 \
  || fail "$RESPONDER never received the plaintext body after accepting — delivery is broken"
echo "confirmed: after accepting, $RESPONDER received the message content end-to-end: \"$MSG\""

# Best-effort shutdown of both chat processes: close our write ends (delivers stdin EOF into the
# container process once its `docker compose exec` local process also observes it) so `meridian
# chat` has a chance to exit its loop and close its own client cleanly. NOT awaited: `docker
# compose exec`'s own local client process holds an independent read handle on the same fifo, so
# EOF delivery here is not guaranteed promptly (and isn't required for correctness — a still-open
# chat session does not conflict with the `session connect` signaling connections started below,
# which are independent per-connection sessions on the server side). The stack teardown in this
# script's exit trap is what actually reclaims these processes either way.
exec {INIT_FD}>&- {RESP_FD}>&- 2>/dev/null || true

# ---------------------------------------------------------------------------------------------
# 4. Real P2P: `session connect` over WebRTC, real DTLS, via the stack's own coturn TURN relays
# ---------------------------------------------------------------------------------------------
if [ "${SKIP_P2P:-0}" = "1" ]; then
  log "SKIP_P2P=1 — skipping the real WebRTC/DTLS leg (chat delivery above is the primary proof)"
else
  log "attempting a real cross-org P2P session (session connect, --transport webrtc, via coturn)"
  "${COMPOSE[@]}" exec -T -e "MERIDIAN_HOME=$ALICE_HOME" -e "MERIDIAN_PASSPHRASE=$PASS" client \
    meridian session connect --json --server wss://org-a.test:8443 "$BOB_ID" \
    >"$SCRATCH/alice_session.log" 2>&1 &
  A_PID=$!
  "${COMPOSE[@]}" exec -T -e "MERIDIAN_HOME=$BOB_HOME" -e "MERIDIAN_PASSPHRASE=$PASS" client \
    meridian session connect --json --server wss://org-b.test:8443 "$ALICE_ID" \
    >"$SCRATCH/bob_session.log" 2>&1 &
  B_PID=$!

  A_RC=0; B_RC=0
  wait "$A_PID" || A_RC=$?
  wait "$B_PID" || B_RC=$?

  if [ "$A_RC" -ne 0 ] || [ "$B_RC" -ne 0 ] \
     || ! grep -q '"established":true' "$SCRATCH/alice_session.log" \
     || ! grep -q '"established":true' "$SCRATCH/bob_session.log"; then
    echo "--- alice session log ---" >&2; cat "$SCRATCH/alice_session.log" >&2
    echo "--- bob session log ---" >&2; cat "$SCRATCH/bob_session.log" >&2
    fail "cross-org P2P session (session connect --transport webrtc) did not establish — see logs above; re-run with SKIP_P2P=1 to still get the primary chat-delivery proof"
  fi
  echo "confirmed: real cross-org P2P session established for both sides (DTLS fingerprint verified) —"
  grep -o '"path":"[^"]*"' "$SCRATCH/alice_session.log"
fi

# ---------------------------------------------------------------------------------------------
# 5. Prove no server ever saw the plaintext
# ---------------------------------------------------------------------------------------------
log "checking both rendezvous servers' own logs for the plaintext message body"
"${COMPOSE[@]}" logs --no-color rendezvous-a rendezvous-b edge-a edge-b coturn-a coturn-b \
  > "$SCRATCH/server_logs.txt" 2>&1

if grep -qF "$MSG" "$SCRATCH/server_logs.txt"; then
  fail "the plaintext chat body '$MSG' appears in a server's own logs — opacity is broken"
fi
echo "confirmed: 0 occurrences of the plaintext message body ('$MSG') in any server's logs"

# A literal `grep -c plaintext` (as the feature spec's demo script does) is its own trap here:
# meridian-rendezvous's OWN startup banner literally says "holds no plaintext by construction"
# (apps/rendezvous/src/main.rs) — a benign self-description, not a leak. So this check subtracts
# exactly that expected banner line (one per rendezvous instance) before asserting zero.
BANNER_COUNT="$(grep -c 'holds no plaintext by construction' "$SCRATCH/server_logs.txt" || true)"
PLAINTEXT_COUNT="$(grep -ci 'plaintext' "$SCRATCH/server_logs.txt" || true)"
if [ "${PLAINTEXT_COUNT:-0}" -gt "${BANNER_COUNT:-0}" ]; then
  echo "--- server_logs.txt ---" >&2
  cat "$SCRATCH/server_logs.txt" >&2
  fail "the word 'plaintext' appears in server logs more often than the expected startup banner — investigate"
fi
echo "confirmed: grep -c plaintext == $BANNER_COUNT (exactly the benign startup banner, 0 real leaks)"

log "PASS — $MODE-discovery-mode walkthrough complete: cross-org chat federated, message-request"
echo "        gate fired, delivery succeeded once accepted$( [ "${SKIP_P2P:-0}" = "1" ] || echo ", real P2P/DTLS established" ), and neither"
echo "        server's logs ever contained the plaintext."
