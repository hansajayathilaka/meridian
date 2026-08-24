#!/usr/bin/env bash
# demo/p2p-wire-proof/two-machine-chat.sh — run this on EACH of two real, separate machines to
# exchange a few real P2P sessions with each other over the real hosted rendezvous server. Both
# sides run the exact same script; the only difference is which peer ID you pass.
#
# Step 1 (each machine, once): learn your own ID.
#   bash two-machine-chat.sh
# Step 2: tell the other person your ID, get theirs.
# Step 3 (each machine, together): actually connect.
#   bash two-machine-chat.sh <their-mrd1-id> [rounds]
#
# What this does NOT do: run a long-lived interactive chat. `meridian session connect` (T04) is a
# one-shot command — it dials/answers, exchanges exactly one message each way over the real P2P
# data channel, and exits. "Chatting a couple of times" here means running that one-shot exchange
# several times in a row (default 3), each one a genuinely fresh ICE/DTLS handshake between your
# two machines. `meridian chat` (T03) is the OTHER command in this codebase and is intentionally
# not used here — it relays through the server by design, which is the opposite of what this is
# trying to prove.
#
# Requires: a `meridian` binary (this repo builds one with `cargo build --release -p meridian-cli
# --features meridian-cli/webrtc`, or use a prebuilt release —
# https://github.com/hansajayathilaka/meridian/releases/tag/cli-latest — no Rust toolchain needed
# either way). Point MERIDIAN_BIN at it if it's not on your PATH as `meridian`.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RENDEZVOUS_URL="${RENDEZVOUS_URL:-wss://rendezvous.hansajayathilaka.com}"
ROUNDS="${2:-3}"
PEER_ID="${1:-}"
BIN="${MERIDIAN_BIN:-meridian}"
HOME_DIR="$(pwd)/two-machine-home"
export MERIDIAN_PASSPHRASE="${MERIDIAN_PASSPHRASE:-two-machine-demo}"

log() { echo "[two-machine] $*"; }
fail() { echo "[two-machine] FAIL: $*" >&2; exit 1; }

command -v "$BIN" >/dev/null 2>&1 || [[ -x "$BIN" ]] || fail "meridian binary not found ('$BIN') — build it or download a release, then set MERIDIAN_BIN if it's not on PATH"

if [[ ! -f "$HOME_DIR/meridian.key" ]]; then
  mkdir -p "$HOME_DIR"
  log "no identity yet — creating one and registering with $RENDEZVOUS_URL…"
  (cd "$HOME_DIR" && MERIDIAN_HOME="$HOME_DIR" "$BIN" id new --store file --out meridian.key --hint rendezvous.hansajayathilaka.com >/dev/null)
  (cd "$HOME_DIR" && MERIDIAN_HOME="$HOME_DIR" timeout 20 "$BIN" register --server "$RENDEZVOUS_URL")
fi
MY_ID="$(cd "$HOME_DIR" && MERIDIAN_HOME="$HOME_DIR" "$BIN" id show)"
log "your ID: $MY_ID"

if [[ -z "$PEER_ID" ]]; then
  log "no peer ID given — share the ID above with the other person, get theirs, then run:"
  log "  bash two-machine-chat.sh <their-id> [rounds]"
  exit 0
fi

log "will run $ROUNDS round(s) of session connect against $PEER_ID via $RENDEZVOUS_URL"
log "(each round is a fresh handshake — some retrying is normal if the other side isn't running the same round at the exact same moment; this script retries automatically)"

for round in $(seq 1 "$ROUNDS"); do
  log "=== round $round/$ROUNDS ==="
  ok=0
  for attempt in 1 2 3 4 5 6 7 8; do
    set +e
    (cd "$HOME_DIR" && MERIDIAN_HOME="$HOME_DIR" timeout 40 "$BIN" session connect "$PEER_ID" --server "$RENDEZVOUS_URL" --transport webrtc --json)
    rc=$?
    set -e
    if [[ "$rc" == "0" ]]; then
      ok=1
      break
    fi
    log "round $round attempt $attempt/8 didn't complete (rc=$rc) — retrying in 3s (the other side may not have run this round yet)"
    sleep 3
  done
  [[ "$ok" == "1" ]] || fail "round $round never completed after 8 attempts — is the other side running the same round?"
done

log "all $ROUNDS round(s) complete."
