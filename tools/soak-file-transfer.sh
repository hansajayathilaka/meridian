#!/usr/bin/env bash
# Task 10.14 — soak test: 1 GiB / 10 GiB `meridian send` transfers + throughput report.
#
# Drives two real `meridian` CLI processes (built with `--features webrtc`, the same real
# WebRtcTransport backend the feature spec's own demo script uses) through a full identity ->
# rendezvous -> real P2P session -> `mrd.file/1` transfer, on either:
#   - plain loopback (127.0.0.1, no netns, no loss/RTT injection) — the `loopback` subcommand, or
#   - a netns rig under `tools/netns-netem.sh`'s named `file-transfer` profile (1% loss / 80ms RTT,
#     per docs/architecture/features/09-file-transfer.md) — the `netns` subcommand.
#
# Verifies byte-perfect delivery via sha256sum on both ends (the feature spec's own demo script's
# final line), and reports elapsed wall time / throughput (MB/s) for whatever size actually
# completed. See docs/testing/soak-file-transfer-throughput.md for the full report this harness
# feeds, including the pre-existing defect this task's own real run surfaced (see that doc's
# "Blocking finding" section) — this script deliberately does NOT paper over that defect: it
# detects the specific failure mode and reports it loudly (a real exit-1 finding, not a graceful
# skip), rather than hanging forever or fabricating a throughput number from a run that never
# actually moved the requested number of bytes.
#
# Requires two prebuilt binaries (not built automatically here, mirroring tools/netns-kill-resume.sh's
# same precedent — keeps this script fast/pure and the build step visible to whoever runs it):
#   cargo build -p meridian-cli --features webrtc --bin meridian
#   cargo build -p meridian-rendezvous --bin meridian-rendezvous
#
# Usage:
#   tools/soak-file-transfer.sh loopback [--size-mib N] [--timeout-secs N]
#   sudo tools/soak-file-transfer.sh netns [--size-mib N] [--profile file-transfer] [--timeout-secs N]
#   sudo tools/soak-file-transfer.sh netns down     # tear down a leftover topology
#
# `netns` requires root (NET_ADMIN) and (for the loss/RTT injection to actually apply) a kernel with
# CONFIG_NET_SCH_NETEM — gracefully skips (exit 0) on either being unavailable, sourcing
# tools/netns-netem.sh's own need_root()/need_netem() exactly as that script's own header comment
# invites a future rig to do. `loopback` needs neither root nor netns/netem and is the harness's
# other, always-available leg — the one honest data point this task can produce in any sandbox,
# clearly labeled as excluding loss/RTT injection.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

# shellcheck source=tools/netns-netem.sh
source "$REPO_ROOT/tools/netns-netem.sh"

MERIDIAN_BIN="${MERIDIAN_BIN:-$REPO_ROOT/target/debug/meridian}"
RENDEZVOUS_BIN="${MERIDIAN_RENDEZVOUS_BIN:-$REPO_ROOT/target/debug/meridian-rendezvous}"

SIZE_MIB=1024          # 1 GiB default, per the feature spec's own named soak size.
SIZE_BYTES_OVERRIDE=""  # set via --size-bytes; see parse_common_flags.
TIMEOUT_SECS=180        # bounds each side's wait — see the module doc on why this must never hang.
PROFILE="file-transfer"

NS_A="ns-soak-a"
NS_B="ns-soak-b"
IF_A="soak-a"
IF_B="soak-b"
IP_A="10.77.9.1"
IP_B="10.77.9.2"
PORT=8443

# bounded_wait <pid> <timeout_secs> -> the real exit status of <pid>, or 124 (mirroring GNU
# `timeout`'s own convention) if it's still running once <timeout_secs> elapses (force-killed in
# that case). NOT `timeout N wait "$pid"`: GNU coreutils' `timeout` execs its argument as a real
# program via execvp, and `wait` is a bash builtin with no standalone binary on the PATH of any
# distro this repo targets — that idiom silently fails with "timeout: failed to run command
# 'wait': No such file or directory" (exit 127) on EVERY call, regardless of whether the awaited
# process is healthy, hung, or already exited, discovered directly while building this harness
# (confirmed exit 127 in this sandbox). `tools/netns-kill-resume.sh` (task 10.15, landing
# concurrently with this task) already implements the correct `kill -0` polling loop under its own
# `wait_pid_with_timeout`, with its own comment explaining the same `timeout N wait` pitfall.
bounded_wait() {
  local pid="$1" timeout_secs="$2" waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= timeout_secs )); then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid"
}

check_bins() {
  local missing=0
  if [[ ! -x "$MERIDIAN_BIN" ]]; then
    echo "meridian binary not found/executable at $MERIDIAN_BIN — build it first:" >&2
    echo "  cargo build -p meridian-cli --features webrtc --bin meridian" >&2
    missing=1
  fi
  if [[ ! -x "$RENDEZVOUS_BIN" ]]; then
    echo "meridian-rendezvous binary not found/executable at $RENDEZVOUS_BIN — build it first:" >&2
    echo "  cargo build -p meridian-rendezvous --bin meridian-rendezvous" >&2
    missing=1
  fi
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
}

parse_common_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --size-mib) SIZE_MIB="$2"; shift 2 ;;
      --size-gib) SIZE_MIB=$((${2} * 1024)); shift 2 ;;
      # Sub-MiB sizes, in bytes — not part of the task's own named 1 GiB/10 GiB soak sizes, but
      # useful for exercising the single-chunk (<=~65400 byte) boundary this harness's own
      # development found load-bearing (see BLOCKING_DEFECT_MARKER's doc comment below). Sets
      # SIZE_MIB to 0 and SIZE_BYTES_OVERRIDE instead; gen_file prefers the override when set.
      --size-bytes) SIZE_BYTES_OVERRIDE="$2"; shift 2 ;;
      --timeout-secs) TIMEOUT_SECS="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
  done
}

rig_dir() {
  echo "${MERIDIAN_SOAK_RIG_DIR:-$(mktemp -d /tmp/meridian-soak.XXXXXX)}"
}

# gen_file <path> <size_mib> — real pseudorandom content (mirrors tools/netns-kill-resume.sh's own
# `head -c ... /dev/urandom` choice): content doesn't affect chunking/AEAD/merkle cost, but random
# bytes rule out any accidental sparse-file/compression shortcut making the measured throughput
# look better than a real payload would.
gen_file() {
  local path="$1" size_mib="$2"
  if [[ -n "${SIZE_BYTES_OVERRIDE:-}" ]]; then
    echo "[soak] generating a ${SIZE_BYTES_OVERRIDE}-byte test file at $path…"
    head -c "$SIZE_BYTES_OVERRIDE" /dev/urandom > "$path"
    return
  fi
  echo "[soak] generating a ${size_mib} MiB test file at $path…"
  head -c "$((size_mib * 1024 * 1024))" /dev/urandom > "$path"
}

# run_send_pair <netns-exec-a-prefix (may be empty)> <netns-exec-b-prefix> <server-url-for-a>
# <server-url-for-b> <workdir> <file> <out-dir> -> sets ALICE_ERR_FILE/BOB_ERR_FILE/ELAPSED/AEXIT/BEXIT
# globals for the caller to inspect. Fresh identities + a fresh rendezvous every call (never reused
# across runs) — reusing identities against a still-running rendezvous was found, during this task's
# own development, to leave a stale one-time-prekey in the server's pool from an earlier run whose
# process (and therefore whose OTK secret) no longer exists, producing a confusing
# "no matching prekey secret for incoming session" failure unrelated to anything this harness is
# actually trying to measure — always start clean instead of trying to detect/avoid that staleness.
run_send_pair() {
  local exec_a="$1" exec_b="$2" server_a="$3" server_b="$4" workdir="$5" file="$6" out_dir="$7"

  mkdir -p "$workdir/alice_home" "$workdir/bob_home" "$out_dir"

  export MERIDIAN_PASSPHRASE="soak-test-passphrase"
  # shellcheck disable=SC2086 # $exec_a/$exec_b are intentionally word-split (may be empty, or
  # "ip netns exec ns-soak-a") — quoting would pass a single empty-string argv[0] to env/exec.
  # Absolute `--out` paths: this script itself `cd`s to the repo root at the top, so a bare
  # relative "alice.key" here would land in the repo root, not `$workdir` — a real mistake this
  # harness's own early development made (confirmed: it left `alice.key`/`bob.key` age-encrypted
  # key files sitting in the repo root after a test run, discovered via `git status`).
  MERIDIAN_HOME="$workdir/alice_home" $exec_a "$MERIDIAN_BIN" id new --store file \
    --out "$workdir/alice.key" --hint localhost > "$workdir/alice_new.log" 2>&1
  MERIDIAN_HOME="$workdir/bob_home" $exec_b "$MERIDIAN_BIN" id new --store file \
    --out "$workdir/bob.key" --hint localhost > "$workdir/bob_new.log" 2>&1
  local alice_id bob_id
  alice_id="$(MERIDIAN_HOME="$workdir/alice_home" $exec_a "$MERIDIAN_BIN" id show)"
  bob_id="$(MERIDIAN_HOME="$workdir/bob_home" $exec_b "$MERIDIAN_BIN" id show)"
  echo "[soak] alice=$alice_id"
  echo "[soak] bob=$bob_id"

  local alice_log="$workdir/alice_send.log" alice_err="$workdir/alice_send.err"
  local bob_log="$workdir/bob_send.log" bob_err="$workdir/bob_send.err"
  ALICE_ERR_FILE="$alice_err"
  BOB_ERR_FILE="$bob_err"

  local start end
  start="$(date +%s.%N)"
  # `y\n` on stdin auto-accepts the (non-image) file prompt (`send.rs::prompt_accept`); `--out
  # $out_dir` on both invocations. Both are harmless no-ops for whichever side turns out to be the
  # INITIATOR: `send.rs`'s role (dial vs. answer) is decided by key order (the lexicographically
  # smaller identity key initiates, `apps/cli/src/send.rs`'s own module doc), which this harness
  # cannot predict from freshly generated identities — either alice or bob may end up the responder
  # (the one that actually reads stdin / writes into --out), discovered directly while building this
  # harness (a run where "alice" ended up the responder and "bob" the initiator, with the file
  # showing up needing alice's stdin, not bob's, and vice versa on the next run). Giving both
  # invocations identical treatment removes the need to guess.
  # NOT wrapped in a `( ... ) &` subshell: bash backgrounding a *pipeline* directly
  # (`cmd1 | cmd2 &`) sets `$!` to cmd2's own PID (here, the real `meridian` process) with no
  # intervening subshell — wrapping in parens instead makes `$!` the subshell wrapper's PID, whose
  # own children (the real, long-running `meridian` process) are NOT killed by `kill -9 "$pid"` on
  # that wrapper (SIGKILL is not forwarded to a killed process's own children) — discovered directly
  # while building this harness: an earlier, parenthesized version of this function left orphaned
  # `meridian send` processes running indefinitely in the background after `bounded_wait`'s own
  # timeout branch fired and reported the run as done, exactly the kind of silent resource leak this
  # harness's own bounded-timeout/cleanup logic exists to prevent.
  printf 'y\n' | MERIDIAN_HOME="$workdir/alice_home" $exec_a "$MERIDIAN_BIN" send "$bob_id" "$file" \
    --server "$server_a" --out "$out_dir" --json > "$alice_log" 2> "$alice_err" &
  local apid=$!
  printf 'y\n' | MERIDIAN_HOME="$workdir/bob_home" $exec_b "$MERIDIAN_BIN" send "$alice_id" "$file" \
    --server "$server_b" --out "$out_dir" --json > "$bob_log" 2> "$bob_err" &
  local bpid=$!

  AEXIT=0
  BEXIT=0
  bounded_wait "$apid" "$TIMEOUT_SECS"; AEXIT=$?
  bounded_wait "$bpid" "$TIMEOUT_SECS"; BEXIT=$?
  # Neither side self-terminates once the other has fatally errored on the real transport (see the
  # module doc's "Responder exit condition" caveat, `apps/cli/src/send.rs`) — belt-and-suspenders
  # kill so a failed run never leaves an orphaned process past this function returning.
  kill "$apid" "$bpid" 2>/dev/null || true

  end="$(date +%s.%N)"
  ELAPSED="$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')"

  echo "[soak] --- alice log ---"; cat "$alice_log" 2>/dev/null || true
  echo "[soak] --- alice err ---"; cat "$alice_err" 2>/dev/null || true
  echo "[soak] --- bob log ---"; cat "$bob_log" 2>/dev/null || true
  echo "[soak] --- bob err ---"; cat "$bob_err" 2>/dev/null || true
}

# The specific, previously-undiscovered defect this task's own real run surfaced (independently
# reproduced twice: once by this harness's loopback run, once by task 10.15's own
# kill_resume_netns_drive example, both against apps/transport/src/webrtc_backend.rs's real
# WebRtcTransport) — see docs/testing/soak-file-transfer-throughput.md for the full writeup. Detected
# by exact stderr substring rather than exit code alone, so this harness fails LOUDLY and
# specifically on this known cause rather than reporting a generic, less actionable failure.
BLOCKING_DEFECT_MARKER="outbound packet larger than maximum message size"

# check_result <label> <file> <out-dir> -> prints a RESULT line and returns 0/1. Never claims a
# throughput number for a run that didn't actually verify byte-perfect delivery of the full file.
check_result() {
  local label="$1" file="$2" out_dir="$3"
  local size_bytes
  size_bytes="$(stat -c%s "$file")"

  if grep -q "$BLOCKING_DEFECT_MARKER" "$ALICE_ERR_FILE" "$BOB_ERR_FILE" 2>/dev/null; then
    cat >&2 <<EOF
[soak] BLOCKED ($label): hit the known pre-existing defect — the real WebRtcTransport's default
SCTP max-message-size (65536 bytes) cannot carry a full 64 KiB mrd.file/1 chunk once ratchet/AEAD/
CBOR framing overhead is added, so ANY transfer needing more than one chunk fails deterministically
on the very first full chunk. This is not a throughput ceiling and not an environment limitation —
it is a functional defect in the existing wiring, independently reproduced by this harness and by
task 10.15's own kill_resume_netns_drive example. See docs/testing/soak-file-transfer-throughput.md
for the full writeup and the recommended fix (raise the negotiated SCTP max-message-size in
apps/transport/src/webrtc_backend.rs's SettingEngine). No throughput number can be produced for
$label until that lands — reporting this as a real, loud failure rather than a graceful skip or a
fabricated number.
EOF
    echo "RESULT $label ok=false blocked_by_defect=true size_bytes=$size_bytes"
    return 1
  fi

  if [[ "$AEXIT" -ne 0 || "$BEXIT" -ne 0 ]]; then
    echo "[soak] FAIL ($label): alice_exit=$AEXIT bob_exit=$BEXIT (see logs above)" >&2
    echo "RESULT $label ok=false blocked_by_defect=false size_bytes=$size_bytes"
    return 1
  fi

  local received
  received="$(find "$out_dir" -maxdepth 1 -type f | head -n1 || true)"
  if [[ -z "$received" ]]; then
    echo "[soak] FAIL ($label): no file was written to $out_dir" >&2
    echo "RESULT $label ok=false blocked_by_defect=false size_bytes=$size_bytes"
    return 1
  fi

  local src_sha out_sha
  src_sha="$(sha256sum "$file" | cut -d' ' -f1)"
  out_sha="$(sha256sum "$received" | cut -d' ' -f1)"
  if [[ "$src_sha" != "$out_sha" ]]; then
    echo "[soak] FAIL ($label): sha256 mismatch — source=$src_sha received=$out_sha" >&2
    echo "RESULT $label ok=false blocked_by_defect=false size_bytes=$size_bytes"
    return 1
  fi

  local mb_per_sec
  mb_per_sec="$(awk -v b="$size_bytes" -v s="$ELAPSED" 'BEGIN { if (s <= 0) s = 0.001; printf "%.2f", (b / 1000000.0) / s }')"
  echo "[soak] PASS ($label): sha256 matches on both ends ($src_sha), ${size_bytes} bytes in ${ELAPSED}s (${mb_per_sec} MB/s)"
  echo "RESULT $label ok=true blocked_by_defect=false size_bytes=$size_bytes elapsed_s=$ELAPSED mb_per_s=$mb_per_sec"
}

# --------------------------------------------------------------------------------------------
# loopback — real CLI-to-CLI transfer on 127.0.0.1. No netns, no netem: the "honest, real, no
# loss/RTT injection" data point the task calls for, always runnable (no root needed).
# --------------------------------------------------------------------------------------------
cmd_loopback() {
  parse_common_flags "$@"
  check_bins

  local d
  d="$(rig_dir)"
  echo "[soak] rundir: $d"

  local file="$d/input.bin"
  gen_file "$file" "$SIZE_MIB"

  nohup "$RENDEZVOUS_BIN" --bind "127.0.0.1:$PORT" > "$d/rendezvous.log" 2>&1 &
  local rvpid=$!
  sleep 1

  local out_dir="$d/bob_out"
  local ok=1
  run_send_pair "" "" "ws://127.0.0.1:$PORT" "ws://127.0.0.1:$PORT" "$d" "$file" "$out_dir" || true
  check_result "loopback" "$file" "$out_dir" || ok=0

  kill "$rvpid" 2>/dev/null || true
  wait "$rvpid" 2>/dev/null || true

  [[ "$ok" -eq 1 ]]
}

# --------------------------------------------------------------------------------------------
# netns — the real soak scenario: two network namespaces joined by a veth pair, the feature spec's
# named `file-transfer` (1% loss / 80ms RTT) profile applied via tools/netns-netem.sh, gracefully
# skipping (exit 0) if root/netem aren't available (need_root/need_netem, sourced above).
# --------------------------------------------------------------------------------------------
netns_topology_up() {
  ip netns add "$NS_A" 2>/dev/null || true
  ip netns add "$NS_B" 2>/dev/null || true
  ip link add "$IF_A" netns "$NS_A" type veth peer name "$IF_B" netns "$NS_B" 2>/dev/null || true
  ip netns exec "$NS_A" ip link set "$IF_A" up
  ip netns exec "$NS_B" ip link set "$IF_B" up
  ip netns exec "$NS_A" ip link set lo up
  ip netns exec "$NS_B" ip link set lo up
  ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$IF_A" 2>/dev/null || true
  ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$IF_B" 2>/dev/null || true
  echo "[soak] topology up: $NS_A($IP_A) <-veth-> $NS_B($IP_B)"
}

netns_topology_down() {
  clear_netem_pair "$NS_A" "$IF_A" "$NS_B" "$IF_B" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  echo "[soak] topology torn down"
}

cmd_netns() {
  if [[ "${1:-}" == "down" ]]; then
    netns_topology_down
    return 0
  fi
  parse_common_flags "$@"
  need_root
  need_netem
  check_bins

  local d
  d="$(rig_dir)"
  echo "[soak] rundir: $d"
  netns_topology_up
  trap netns_topology_down EXIT

  local loss rtt
  loss="$(profile_loss "$PROFILE")"
  rtt="$(profile_rtt "$PROFILE")"
  echo "[soak] applying profile '$PROFILE': loss=${loss}% rtt=${rtt}ms"
  apply_netem_pair "$NS_A" "$IF_A" "$NS_B" "$IF_B" "$loss" "$rtt"

  local file="$d/input.bin"
  gen_file "$file" "$SIZE_MIB"

  # Rendezvous runs inside ns-soak-a, bound to 0.0.0.0 — reachable both from ns-soak-a itself
  # (127.0.0.1, same netns) and from ns-soak-b across the veth link ($IP_A).
  ip netns exec "$NS_A" "$RENDEZVOUS_BIN" --bind "0.0.0.0:$PORT" > "$d/rendezvous.log" 2>&1 &
  local rvpid=$!
  sleep 1

  local out_dir="$d/bob_out"
  local ok=1
  run_send_pair "ip netns exec $NS_A" "ip netns exec $NS_B" \
    "ws://127.0.0.1:$PORT" "ws://$IP_A:$PORT" "$d" "$file" "$out_dir" || true
  check_result "netns-${PROFILE}" "$file" "$out_dir" || ok=0

  kill "$rvpid" 2>/dev/null || true
  wait "$rvpid" 2>/dev/null || true
  clear_netem_pair "$NS_A" "$IF_A" "$NS_B" "$IF_B"
  trap - EXIT
  netns_topology_down

  [[ "$ok" -eq 1 ]]
}

case "${1:-}" in
  loopback) shift; cmd_loopback "$@" ;;
  netns) shift; cmd_netns "$@" ;;
  *)
    echo "usage: $0 {loopback|netns} [--size-mib N | --size-gib N] [--timeout-secs N] [--profile NAME]" >&2
    echo "       $0 netns down     # tear down a leftover topology" >&2
    exit 2
    ;;
esac
