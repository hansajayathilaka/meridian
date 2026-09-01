#!/usr/bin/env bash
# Task 10.15 — kill/resume test automation on the netns rig.
#
# Automates the feature spec's demo script (docs/architecture/features/09-file-transfer.md):
#
#     $ meridian send mrd1:<bob>@org-b.test ./video-1GiB.bin
#       [file] merkle root b3:9af2… | 16384 chunks | direct path
#       38% ▓▓▓▓▓░░░░ 41 MB/s
#     $ # yank the network mid-transfer (testrig cuts the veth), then restore
#       [session] ICE restart… reconnected
#       [file] peer reports 6211 missing ranges — resuming at 38%
#       done ✔ verified b3:9af2… matches
#     $ sha256sum on both ends → identical
#
# SCOPE RESOLUTION (this task's own explicit "TODO: confirm" risk note): the demo script above shows
# a network CUT + ICE restart — the `meridian send` PROCESS stays alive throughout (it is the same
# shell prompt printing progressively more output). It is NOT a full CLI-process kill and restart
# from cold; that harder interpretation would need on-disk-persisted partial-transfer state, which no
# task in this phase builds (task 10.9's resume protocol is entirely in-memory, keyed by a live
# `StreamId`/session — see `apps/streams/src/resume.rs` / `apps/streams/src/receiver.rs`). This rig
# implements the network-cut interpretation only.
#
# DRIVER CHOICE: `meridian send` itself (`apps/cli/src/send.rs`) has NO automatic drop-detection or
# reconnect/resume wiring — task 10.9's own module doc (`apps/streams/src/resume.rs`) already flags
# this as a tracked, separate gap: no `SessionEvent`/`StreamType` hook exists to learn "the network
# changed" without a `meridian-core` change, which is out of THIS task's scope (a "no core-crate
# edits" additive-stream-type invariant, root CLAUDE.md). Rather than inventing that hook here, this
# rig drives the real `meridian-core`/`meridian-streams` primitives directly via a small, dedicated
# driver binary (`apps/cli/examples/kill_resume_netns_drive.rs`) that plays the "session-lifecycle
# layer" `resume.rs`'s own doc says must exist outside the crate — calling `P2pSession::ice_restart()`
# + `send_missing_chunks`/the resume-bitmap wire shape at the exact moment THIS SCRIPT tells it to
# (via marker files), since the script is the one performing the cut and already knows when. See the
# driver's own module doc and this task's report for the full reasoning.
#
# TWO PRE-EXISTING, INDEPENDENT GAPS THIS RIG WILL LIKELY SURFACE (neither is a defect in this
# task's own deliverable — both were found WHILE building it, confirmed live on this very sandbox,
# and are flagged here for follow-up rather than silently worked around):
#
# 1. `apps/transport/src/webrtc_backend.rs`'s own module doc states that `Transport::ice_restart` on
#    the real `WebRtcTransport` backend is CURRENTLY A NO-OP on the wire — it resets only local
#    candidate-gathering bookkeeping and does not renegotiate ICE with the peer. CONFIRMED LIVE by
#    this task via the `probe` subcommand below: after a genuine 15s veth cut (past the backend's own
#    9s ICE_FAILED_TIMEOUT) + restore + `ice_restart()` on both sides, the sender's own `send_chat()`
#    call returns `Ok(())` with no error, but the message never reaches the peer even after a further
#    25s wait — see `apps/cli/examples/netns_ice_restart_probe.rs`'s own module doc for the full
#    write-up. This means `run`'s file-transfer scenario below is EXPECTED to fail the same way once
#    it gets past gap 2.
# 2. The `mrd.file/1` wire chunk size (`meridian_streams::merkle::CHUNK_SIZE`, 65536 bytes) is exactly
#    equal to `webrtc-sctp`'s own default `max_message_size` (also 65536) — so ANY full-size chunk,
#    once wrapped in its AEAD tag + CBOR framing + the outer ratchet envelope, exceeds the real
#    transport's outbound message-size limit. CONFIRMED LIVE: `run`'s very first `send_chunk_frame`
#    call fails immediately with "outbound packet larger than maximum message size", before the veth
#    is even cut. This means real multi-chunk `mrd.file/1` transfers cannot complete over the real
#    `WebRtcTransport` backend TODAY, independent of kill/resume — a separate, likely higher-priority
#    finding than gap 1.
#
# This rig cuts the veth long enough (past the 9s ICE_FAILED_TIMEOUT) to observe gap 1 for real
# rather than take it on faith. If either driver reports the errors above, that is this rig correctly
# doing its job, not a bug in the rig — do not "fix" this script to hide either failure.
#
# UPDATE (task 10.23): both gaps above are now fixed and no longer expected on a live run.
#   - Gap 2 (SCTP max-message-size) was fixed by task 10.18
#     (`apps/transport/src/webrtc_backend.rs`'s `SCTP_MAX_MESSAGE_SIZE`/`with_max_message_size_attr`).
#   - Gap 1 (`ice_restart` real signaling) was fixed by tasks 10.19–10.22 per
#     [ADR 0025](../docs/adr/0025-ice-restart-renegotiation.md); the driver/probe examples were
#     updated in task 10.23 to call the new signature the way ADR 0025 requires (a fresh,
#     transiently-reconnected `SignalRelay` for the restart round trip, not the dial-time relay held
#     open). `run`/`probe` are now both expected to PASS end-to-end on this rig — see
#     `docs/tasks/phase-10/10.23-demo-transcript.md` for a real, live re-run. A FAIL at this point is
#     a genuine new regression, not a reproduction of either historical gap above — report it, don't
#     assume it's "the same known issue."
#
# Usage:
#   cargo build -p meridian-cli --example kill_resume_netns_drive --features webrtc
#   cargo build -p meridian-cli --example netns_ice_restart_probe --features webrtc
#   sudo tools/netns-kill-resume.sh run     # the full mrd.file/1 scenario — see gap 2 above
#   sudo tools/netns-kill-resume.sh probe   # the smaller chat-only substrate check — see gap 1 above
#   sudo tools/netns-kill-resume.sh down    # tear down
#
# Requires root (NET_ADMIN) and a `--features webrtc` build of the driver example. On CI/sandboxes
# without root, or without basic netns/veth link-state support, this SKIPS (exit 0) with a clear
# message — mirroring `tools/netns-nat-matrix.sh`/`tools/netns-netem.sh`'s existing convention
# (task 3.12's precedent). The orchestration/assertion logic itself (marker sequencing, resend-ratio
# math, dual BLAKE3/sha256 verification) is independently exercised without any real network at all by
# `apps/streams/tests/kill_resume_simulated.rs` — see that file's own module doc.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

DRIVER_BIN="${MERIDIAN_KILL_RESUME_DRIVER:-./target/debug/examples/kill_resume_netns_drive}"
PROBE_BIN="${MERIDIAN_KILL_RESUME_PROBE:-./target/debug/examples/netns_ice_restart_probe}"
NS_A="ns-kr-a"
NS_B="ns-kr-b"
IF_A="kr-a"
IF_B="kr-b"
IP_A="10.66.9.1"
IP_B="10.66.9.2"

# File size / chunking: 24 chunks of 64 KiB = 1.5 MiB — small enough to run fast, large enough for a
# meaningful pre-cut/post-cut split (send 15/24 = 62.5% before the cut, matching the demo script's own
# "38%...resuming" shape in spirit: a real prefix delivered, a real suffix missing).
TOTAL_CHUNKS=24
SPLIT_CHUNKS=15
FILE_SIZE_BYTES=$((TOTAL_CHUNKS * 65536 - 12345)) # not an exact multiple, exercises a short final chunk
CUT_SECS=15 # comfortably past webrtc_backend.rs's own ICE_FAILED_TIMEOUT (9s) — a genuine outage.

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    cat >&2 <<'EOF'
netns kill/resume rig needs root (NET_ADMIN). Skipping the wire-level run.
The resume protocol's own orchestration/assertion logic is covered without a network by:
  cargo test -p meridian-streams --test kill_resume_simulated
  cargo test -p meridian-streams --test resume_protocol   # task 10.9's own in-process coverage
EOF
    exit 0
  fi
  if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 ('ip') not found — cannot build the netns topology. Skipping." >&2
    exit 0
  fi
}

# Basic netns/veth link-state support (down/up) is a DIFFERENT kernel capability than netem
# (tools/netns-netem.sh's own gate) — probe it directly rather than assuming, per this task's own
# instruction.
need_veth_linkstate() {
  # (task 10.23 fix) Interface names are capped at IFNAMSIZ (15 usable bytes) — the previous
  # "kr-probe-a-$$"/"kr-probe-b-$$" prefixes are 11 chars on their own, so any 5-digit (or wider)
  # shell PID pushed the full name past 15 and made `ip link add ... peer name ...` fail outright
  # (confirmed live on this sandbox: `ip link add kr-probe-a-16738 ... peer name kr-probe-b-16738`
  # → "wrong: not a valid ifname"). That failure was silently swallowed by this function's own `||
  # true`/`ok=0` handling and reported as "netns/veth link up/down is not usable in this
  # environment — skipping", which is wrong: the capability genuinely works, only the self-check's
  # own probe names didn't fit. Task 10.17 first found this and worked around it out-of-line; fixed
  # here for real by zero-padding the PID to 6 digits (NOT truncating via bash's `${pid: -6}` — that
  # returns an *empty string*, not the whole value, for any PID under 6 digits, i.e. effectively
  # every real invocation given Linux's default `pid_max` of 32768; a truncate-based first attempt
  # at this fix silently collapsed every probe pair to the same constant name and was caught live,
  # by 10.23's own review, reproducing an actual `/run/netns/kr-lsa-` collision between two
  # concurrently-running instances — exactly the collision-safety property this fix exists to keep).
  # Zero-padding preserves genuine per-PID differentiation for short PIDs ("kr-a-016738") without any
  # truncation risk for long ones (Linux PIDs cap at 7 digits under `pid_max`, so "kr-a-4194304" is
  # still only 12 bytes, safely under the 15-byte cap). Namespace names (`ns_a`/`ns_b`) are
  # unaffected by `IFNAMSIZ` itself — `ip netns add` has no such constraint, only `ip link add` does
  # — but share the same suffix for readability/pairing.
  local pid="$$"
  local pid_suffix
  printf -v pid_suffix '%06d' "$pid"
  local probe_a="kr-a-${pid_suffix}" probe_b="kr-b-${pid_suffix}"
  local ns_a="kr-lsa-${pid_suffix}" ns_b="kr-lsb-${pid_suffix}"
  local ok=1
  trap 'ip netns del "'"$ns_a"'" 2>/dev/null || true; ip netns del "'"$ns_b"'" 2>/dev/null || true' RETURN
  if ip netns add "$ns_a" 2>/dev/null && ip netns add "$ns_b" 2>/dev/null \
     && ip link add "$probe_a" netns "$ns_a" type veth peer name "$probe_b" netns "$ns_b" 2>/dev/null; then
    ip netns exec "$ns_a" ip link set "$probe_a" up 2>/dev/null || ok=0
    ip netns exec "$ns_b" ip link set "$probe_b" up 2>/dev/null || ok=0
    ip netns exec "$ns_a" ip link set "$probe_a" down 2>/dev/null || ok=0
    ip netns exec "$ns_a" ip link set "$probe_a" up 2>/dev/null || ok=0
  else
    ok=0
  fi
  if [[ "$ok" -ne 1 ]]; then
    echo "basic netns/veth link up/down is not usable in this environment — skipping." >&2
    exit 0
  fi
}


# `timeout <n> wait <pid>` doesn't work — `wait` is a shell builtin, not an executable `timeout` can
# exec — so poll `kill -0` instead. Returns the waited process's own exit status via `wait` once it's
# confirmed gone; returns 124 (matching `timeout`'s own convention) if `secs` elapses first, killing
# the still-running process so it doesn't linger past this script's own exit.
wait_pid_with_timeout() {
  local pid="$1" secs="$2" waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= secs )); then
      kill -9 "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid"
}

rig_dir() {
  echo "${MERIDIAN_KILL_RESUME_RIG_DIR:-$(mktemp -d /tmp/meridian-kill-resume.XXXXXX)}"
}

topology_up() {
  ip netns add "$NS_A" 2>/dev/null || true
  ip netns add "$NS_B" 2>/dev/null || true
  ip link add "$IF_A" netns "$NS_A" type veth peer name "$IF_B" netns "$NS_B" 2>/dev/null || true
  ip netns exec "$NS_A" ip link set "$IF_A" up
  ip netns exec "$NS_B" ip link set "$IF_B" up
  ip netns exec "$NS_A" ip link set lo up
  ip netns exec "$NS_B" ip link set lo up
  ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$IF_A" 2>/dev/null || true
  ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$IF_B" 2>/dev/null || true
  echo "[kill-resume] topology up: $NS_A($IP_A) <-veth-> $NS_B($IP_B)"
}

down() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  echo "[kill-resume] topology torn down"
}

run() {
  need_root
  need_veth_linkstate
  if [[ ! -x "$DRIVER_BIN" ]]; then
    echo "driver example not found at $DRIVER_BIN — run:" >&2
    echo "  cargo build -p meridian-cli --example kill_resume_netns_drive --features webrtc" >&2
    exit 1
  fi

  local d
  d="$(rig_dir)"
  echo "[kill-resume] rundir: $d"
  topology_up

  head -c "$FILE_SIZE_BYTES" /dev/urandom > "$d/input.bin"
  echo "[kill-resume] generated a $FILE_SIZE_BYTES-byte input file ($TOTAL_CHUNKS chunks, splitting" \
       "at $SPLIT_CHUNKS before the cut)"

  local alice_log="$d/alice.log" bob_log="$d/bob.log"
  echo "[kill-resume] starting sender (ns=$NS_A) and receiver (ns=$NS_B)…"
  ip netns exec "$NS_A" "$REPO_ROOT/$DRIVER_BIN" sender "$d" "$d/input.bin" "$SPLIT_CHUNKS" \
    > "$alice_log" 2>&1 &
  local alice_pid=$!
  ip netns exec "$NS_B" "$REPO_ROOT/$DRIVER_BIN" receiver "$d" "$d/output.bin" "$SPLIT_CHUNKS" \
    > "$bob_log" 2>&1 &
  local bob_pid=$!

  echo "[kill-resume] waiting for both sides to finish the pre-cut burst…"
  local waited=0
  while [[ ! -f "$d/alice_ready_for_cut" || ! -f "$d/bob_ready_for_cut" ]]; do
    if ! kill -0 "$alice_pid" 2>/dev/null || ! kill -0 "$bob_pid" 2>/dev/null; then
      echo "[kill-resume] FAIL: a driver process exited before the pre-cut burst completed —" >&2
      echo "             alice log:" >&2; cat "$alice_log" >&2 || true
      echo "             bob log:" >&2; cat "$bob_log" >&2 || true
      exit 1
    fi
    if (( waited > 90 )); then
      echo "[kill-resume] FAIL: timed out waiting for the pre-cut burst markers" >&2
      exit 1
    fi
    sleep 0.5
    waited=$((waited + 1))
  done
  echo "[kill-resume] pre-cut burst delivered on both sides — cutting the veth for ${CUT_SECS}s…"

  ip netns exec "$NS_A" ip link set "$IF_A" down
  sleep "$CUT_SECS"
  ip netns exec "$NS_A" ip link set "$IF_A" up
  # A fresh interface-up needs a moment before it's genuinely usable again in some kernels; harmless
  # to wait briefly even if it's already fine.
  sleep 0.5
  echo "[kill-resume] veth restored — signaling both drivers to attempt ice_restart()+resume…"
  : > "$d/cut_restored"

  echo "[kill-resume] waiting for both drivers to finish (timeout: 180s)…"
  local ok=1
  if ! wait_pid_with_timeout "$alice_pid" 180; then
    echo "[kill-resume] sender exited nonzero or timed out" >&2
    ok=0
  fi
  if ! wait_pid_with_timeout "$bob_pid" 30; then
    echo "[kill-resume] receiver exited nonzero or timed out" >&2
    ok=0
  fi

  echo "[kill-resume] --- alice log ---"; cat "$alice_log"
  echo "[kill-resume] --- bob log ---"; cat "$bob_log"

  if [[ "$ok" -ne 1 ]]; then
    echo "[kill-resume] FAIL: at least one driver process did not complete successfully — see logs" \
         "above. As of task 10.23 this scenario is expected to PASS (both the SCTP-max-message-size" \
         "gap [task 10.18] and the ice_restart no-op gap [tasks 10.19-10.22, ADR 0025] are fixed);" \
         "a failure here is a genuine, newly-observed defect, not a reproduction of either historical" \
         "gap this script's own header comment records — report it, don't assume it away." >&2
    exit 1
  fi

  if [[ ! -f "$d/output.bin" ]]; then
    echo "[kill-resume] FAIL: no output file was written" >&2
    exit 1
  fi

  local in_sha out_sha
  in_sha="$(sha256sum "$d/input.bin" | cut -d' ' -f1)"
  out_sha="$(sha256sum "$d/output.bin" | cut -d' ' -f1)"
  if [[ "$in_sha" != "$out_sha" ]]; then
    echo "[kill-resume] FAIL: sha256 mismatch — input=$in_sha output=$out_sha" >&2
    exit 1
  fi
  echo "[kill-resume] PASS: sha256 matches on both ends ($in_sha)"

  local resend_ratio
  resend_ratio="$(grep -o '"resend_ratio":[0-9.]*' "$alice_log" | cut -d: -f2 || true)"
  if [[ -z "$resend_ratio" ]]; then
    echo "[kill-resume] FAIL: could not find the sender's resend_ratio summary line" >&2
    exit 1
  fi
  # Bash has no floating-point comparison; delegate to awk.
  if ! awk -v r="$resend_ratio" 'BEGIN { exit !(r <= 0.02) }'; then
    echo "[kill-resume] FAIL: resend_ratio=$resend_ratio exceeds the 2% acceptance bound" >&2
    exit 1
  fi
  echo "[kill-resume] PASS: resend_ratio=$resend_ratio (<= 0.02, the acceptance-criteria bound)"

  echo "[kill-resume] ALL CHECKS PASSED: session reconnected across a real veth cut, resume" \
       "delivered exactly the missing suffix, and the final file matches byte-for-byte."
}


# A smaller, chat-only companion to `run` (see `apps/cli/examples/netns_ice_restart_probe.rs`'s own
# module doc): sidesteps the CHUNK_SIZE/SCTP-max-message-size collision entirely (a chat message is a
# few dozen bytes) to directly answer whether the P2P **substrate** itself — not file-transfer
# chunking — recovers from a genuine veth cut once `ice_restart()` is called on both sides.
# Historically (task 10.15) this reproducibly FAILED (timed out post-restore) — a real, pre-existing
# gap in `meridian-transport`'s then-current `ice_restart` no-op (see that example's own module doc
# for the full finding). UPDATE (task 10.23): that gap is now fixed (tasks 10.19-10.22, ADR 0025) and
# this is expected to PASS — see this script's own top-of-file "UPDATE (task 10.23)" note.
probe() {
  need_root
  need_veth_linkstate
  if [[ ! -x "$PROBE_BIN" ]]; then
    echo "probe example not found at $PROBE_BIN — run:" >&2
    echo "  cargo build -p meridian-cli --example netns_ice_restart_probe --features webrtc" >&2
    exit 1
  fi

  local d
  d="$(rig_dir)"
  echo "[kill-resume:probe] rundir: $d"
  topology_up

  local a_log="$d/probe-a.log" b_log="$d/probe-b.log"
  ip netns exec "$NS_A" "$REPO_ROOT/$PROBE_BIN" a "$d" > "$a_log" 2>&1 &
  local a_pid=$!
  ip netns exec "$NS_B" "$REPO_ROOT/$PROBE_BIN" b "$d" > "$b_log" 2>&1 &
  local b_pid=$!

  local waited=0
  while [[ ! -f "$d/a_ready_for_cut" || ! -f "$d/b_ready_for_cut" ]]; do
    if ! kill -0 "$a_pid" 2>/dev/null || ! kill -0 "$b_pid" 2>/dev/null; then
      echo "[kill-resume:probe] FAIL: a probe process exited before the pre-cut handshake completed" >&2
      cat "$a_log" "$b_log" >&2 || true
      exit 1
    fi
    if (( waited > 60 )); then
      echo "[kill-resume:probe] FAIL: timed out waiting for the pre-cut markers" >&2
      exit 1
    fi
    sleep 0.5
    waited=$((waited + 1))
  done
  echo "[kill-resume:probe] both sides connected and exchanged a pre-cut chat message — cutting" \
       "the veth for ${CUT_SECS}s…"

  ip netns exec "$NS_A" ip link set "$IF_A" down
  sleep "$CUT_SECS"
  ip netns exec "$NS_A" ip link set "$IF_A" up
  sleep 0.5
  echo "[kill-resume:probe] veth restored — signaling both sides to call ice_restart()…"
  : > "$d/cut_restored"

  local ok=1
  wait_pid_with_timeout "$a_pid" 60 || ok=0
  wait_pid_with_timeout "$b_pid" 60 || ok=0

  echo "[kill-resume:probe] --- a ---"; cat "$a_log"
  echo "[kill-resume:probe] --- b ---"; cat "$b_log"

  if [[ "$ok" -ne 1 ]]; then
    echo "[kill-resume:probe] FAIL: the session did not survive the real network cut. As of task" \
         "10.23 this is expected to PASS (the ice_restart no-op gap is fixed, tasks 10.19-10.22," \
         "ADR 0025) — a failure here is a genuine, newly-observed defect, not a reproduction of the" \
         "historical gap apps/cli/examples/netns_ice_restart_probe.rs's module doc records. Report" \
         "it, do not paper over it." >&2
    exit 1
  fi
  echo "[kill-resume:probe] PASS: the session survived a real veth cut + ice_restart()."
}

case "${1:-run}" in
  run) run ;;
  probe) probe ;;
  down) down ;;
  *) echo "usage: $0 {run|probe|down}" >&2; exit 2 ;;
esac
