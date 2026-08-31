#!/usr/bin/env bash
# T09 / task 10.13 — tc netem loss/RTT injection for the netns test rigs. Pure test infrastructure,
# file-transfer-agnostic: parameterized by loss % and RTT, reusable by any future test against any
# existing veth pair (e.g. tools/netns-nat-matrix.sh's ns-alice/a-eth <-> ns-natA/nA-lan LAN leg, or
# tools/netns-two-lans.sh's equivalent link). 10.14 (soak throughput) and 10.15 (kill/resume
# automation) are the intended first real consumers of `apply-pair`/`clear-pair` below; this task
# implements the knob only, not any file-transfer test logic.
#
# Model: tc netem is an EGRESS-only qdisc — it shapes packets leaving the interface it's attached to,
# not packets arriving on it. To emulate a symmetric link with a target round-trip RTT R and a target
# round-trip loss probability L between the two ends of one veth pair, `apply-pair` applies HALF of
# each to the egress of BOTH ends (delay R/2 + loss L/2 on each side):
#   - A round trip crosses the link twice — once in each direction, each through a different egress
#     point — so two independent (R/2)-delay hops compose additively into a total measured RTT of ~R.
#   - Two independent (L/2)-loss draws compose into an overall per-round-trip loss probability of
#     2*(L/2) - (L/2)^2 (a packet is lost if EITHER leg drops it), which for the loss percentages this
#     task cares about (single digits or below) rounds to L to well within any ping sample's
#     statistical noise — e.g. the feature spec's 1% total becomes two independent 0.5% draws,
#     combining to 0.9975% observed round-trip loss, indistinguishable from 1% at realistic sample
#     sizes. `apply` (singular) is the lower-level per-side primitive `apply-pair` is built from, for
#     callers that want to manage each side independently (e.g. an asymmetric profile later).
#
# Usage — generic, against any two already-up netns/iface endpoints of an existing veth pair:
#   sudo tools/netns-netem.sh apply-pair <ns1> <if1> <ns2> <if2> --loss <pct> --rtt <ms>
#   sudo tools/netns-netem.sh apply-pair <ns1> <if1> <ns2> <if2> --profile file-transfer
#   sudo tools/netns-netem.sh clear-pair <ns1> <if1> <ns2> <if2>
#   sudo tools/netns-netem.sh apply <ns> <if> --loss <pct> --rtt <ms>    # single side, HALF-shares only
#   sudo tools/netns-netem.sh clear <ns> <if>
#   sudo tools/netns-netem.sh profile <name>                             # prints "loss=<pct> rtt=<ms>"
#
# Self-contained smoke test (builds its own throwaway two-namespace veth pair, proves the injected
# loss/RTT is actually observed via ping, tears itself down on exit via `trap ... EXIT` — no
# dependency on netns-nat-matrix.sh or any other rig being up):
#   sudo tools/netns-netem.sh smoke                        # feature-spec named profile: 1% loss / 80ms RTT
#   sudo tools/netns-netem.sh smoke --loss 20 --rtt 200    # higher-loss case, tighter statistical bound
#   sudo tools/netns-netem.sh smoke-all                    # both of the above
#
# This script is both directly executable and (via the `BASH_SOURCE` guard at the bottom) sourceable,
# so a future rig/harness (10.14/10.15) can `source tools/netns-netem.sh` and call `apply_netem_pair`/
# `clear_netem_pair` directly against its own already-up topology instead of shelling out.
#
# Requires root (NET_ADMIN) and a kernel built with CONFIG_NET_SCH_NETEM. Gracefully skips (exit 0) on
# either being unavailable — same convention as tools/netns-nat-matrix.sh's need_root(). A kernel
# without CONFIG_NET_SCH_NETEM is a real thing this was validated against (some sandboxed/minimal
# container kernels omit it); GitHub-hosted ubuntu-latest runners' stock kernel has it.
set -euo pipefail
cd "$(dirname "$0")/.."

LOSS_PCT=""
RTT_MS=""
PROFILE=""

# ---------------------------------------------------------------------------------------------
# Named profiles (loss%, rtt-ms) — from docs/architecture/features/09-file-transfer.md's soak-test
# line: "1 GiB and 10 GiB transfers on the netns rig with 1% loss / 80 ms RTT profiles". Add future
# named profiles here only; nothing else in this script or its callers needs to change.
# ---------------------------------------------------------------------------------------------

profile_loss() {
  case "$1" in
    file-transfer) echo 1 ;;
    *) echo "profile_loss: unknown profile '$1' (known: file-transfer)" >&2; exit 2 ;;
  esac
}

profile_rtt() {
  case "$1" in
    file-transfer) echo 80 ;;
    *) echo "profile_rtt: unknown profile '$1' (known: file-transfer)" >&2; exit 2 ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Preflight — same graceful-skip shape as netns-nat-matrix.sh's need_root().
# ---------------------------------------------------------------------------------------------

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "netns netem rig needs root (NET_ADMIN). Skipping." >&2
    exit 0
  fi
  if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 ('ip') not found — cannot manage the netns topology. Skipping." >&2
    exit 0
  fi
  if ! command -v tc >/dev/null 2>&1; then
    echo "iproute2 ('tc') not found — cannot apply netem qdiscs. Skipping." >&2
    exit 0
  fi
}

# Probes for CONFIG_NET_SCH_NETEM by actually trying to attach a netem qdisc to a throwaway veth
# pair in the root netns, rather than trusting `ip link add ... type veth` alone (that only proves
# veth support, not netem — the two are independent kernel config options, and a kernel can easily
# have one without the other, as found live in this task's own dev sandbox). Cleans up the throwaway
# pair itself either way; a single `ip link del` on either end removes both.
need_netem() {
  # "nemp<pid>" (+ "p" for the peer) stays well under IFNAMSIZ's 15 usable chars even for a large
  # PID, while keeping $$ intact for uniqueness (a plain fixed name, truncated or not, would collide
  # if two invocations of this script ever probed concurrently on the same host).
  local probe="nemp$$"
  local peer="${probe}p"
  ip link add "$probe" type veth peer name "$peer" >/dev/null 2>&1 || {
    echo "could not create a throwaway veth pair to probe for netem support — skipping." >&2
    exit 0
  }
  # Guard against a signal (SIGINT/SIGTERM) landing between the `ip link add` above succeeding and
  # the matching `ip link del` below, which would otherwise leak this throwaway probe pair in the
  # root namespace. Scoped to just this probe window and cleared again before returning (both exit
  # paths below) so it never lingers past this function or clashes with a caller's own EXIT trap
  # (e.g. smoke_topology_up's `trap smoke_cleanup EXIT`, installed later in the same process for
  # `smoke`/`smoke-all`) — bash only honors one EXIT trap at a time, so this must not still be
  # armed when that one is installed.
  #
  # Deliberate immediate (double-quoted) expansion of $probe here, not shellcheck's usual SC2064
  # single-quoted/deferred-expansion suggestion: $probe is a local that must be captured NOW, at
  # trap-install time, since this trap is torn down (`trap - EXIT`) before the function returns —
  # deferred expansion would just re-read the same still-in-scope value anyway, so there's no
  # staleness risk this particular warning exists to catch.
  # shellcheck disable=SC2064
  trap "ip link del '${probe}' >/dev/null 2>&1 || true" EXIT
  if ! tc qdisc add dev "$probe" root netem delay 1ms >/dev/null 2>&1; then
    ip link del "$probe" >/dev/null 2>&1 || true
    trap - EXIT
    cat >&2 <<'EOF'
tc netem is unavailable on this kernel (no CONFIG_NET_SCH_NETEM — 'tc qdisc add ... netem' reports
"Specified qdisc kind is unknown"). This is a genuine kernel-capability gap, not a script bug: some
minimal/sandboxed container kernels omit this scheduler even with full NET_ADMIN and working
netns/veth. Skipping. GitHub-hosted CI runners' stock kernel has this module; run there, or on a
kernel with CONFIG_NET_SCH_NETEM=y/m, to exercise this rig for real.
EOF
    exit 0
  fi
  ip link del "$probe" >/dev/null 2>&1 || true
  trap - EXIT
}

# ---------------------------------------------------------------------------------------------
# Core primitives — reusable by any rig, sourced or shelled out to.
# ---------------------------------------------------------------------------------------------

# apply_netem <ns> <iface> <delay_ms> <loss_pct> — idempotent (qdisc replace, not add): safe to call
# again on an interface that already has a netem qdisc attached (e.g. re-tuning a profile mid-run)
# without first requiring an explicit clear.
apply_netem() {
  local ns="$1" iface="$2" delay_ms="$3" loss_pct="$4"
  ip netns exec "$ns" tc qdisc replace dev "$iface" root netem delay "${delay_ms}ms" loss "${loss_pct}%"
}

# clear_netem <ns> <iface> — removes whatever root qdisc is present (netem or otherwise); a no-op,
# not a failure, if none was ever attached (mirrors netns-nat-matrix.sh's idempotent-teardown style:
# `ip netns del "$n" 2>/dev/null || true`).
clear_netem() {
  local ns="$1" iface="$2"
  ip netns exec "$ns" tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

# apply_netem_pair <ns1> <if1> <ns2> <if2> <loss_pct_total> <rtt_ms_total> — see the header comment
# for why each side gets HALF of the configured total (delay and loss both split two ways so the
# round-trip through both egress points sums back to the configured total).
apply_netem_pair() {
  local ns1="$1" if1="$2" ns2="$3" if2="$4" loss_total="$5" rtt_total="$6"
  local half_loss half_rtt
  half_loss="$(awk -v v="$loss_total" 'BEGIN { printf "%.4f", v / 2 }')"
  half_rtt="$(awk -v v="$rtt_total" 'BEGIN { printf "%.4f", v / 2 }')"
  apply_netem "$ns1" "$if1" "$half_rtt" "$half_loss"
  apply_netem "$ns2" "$if2" "$half_rtt" "$half_loss"
}

clear_netem_pair() {
  local ns1="$1" if1="$2" ns2="$3" if2="$4"
  clear_netem "$ns1" "$if1"
  clear_netem "$ns2" "$if2"
}

# ---------------------------------------------------------------------------------------------
# Self-contained smoke test: its own throwaway two-namespace veth pair (ns-netem-a <-> ns-netem-b),
# independent of any other rig. `trap ... EXIT` teardown (unlike netns-nat-matrix.sh's persistent
# topology + explicit `down`, this is a one-shot proof matching demo/p2p-wire-proof/run-wire-proof.sh's
# convention: always tear down on exit, success or failure) so a failed assertion never leaks
# namespaces/veths.
# ---------------------------------------------------------------------------------------------

# PID-suffixed (same treatment as need_netem()'s "nemp$$" probe pair) so two concurrent invocations
# of this script — e.g. an overlapping scheduled + manual `workflow_dispatch` run, or two developers
# running `smoke` locally at once — get distinct namespaces/interfaces instead of colliding.
# "nema$$"/"nemb$$" stay well under IFNAMSIZ's 15 usable chars even for a large PID.
SMOKE_NS_A="ns-netem-a-$$"
SMOKE_NS_B="ns-netem-b-$$"
SMOKE_IF_A="nema$$"
SMOKE_IF_B="nemb$$"
SMOKE_IP_A="10.250.0.1"
SMOKE_IP_B="10.250.0.2"

smoke_cleanup() {
  ip netns del "$SMOKE_NS_A" >/dev/null 2>&1 || true
  ip netns del "$SMOKE_NS_B" >/dev/null 2>&1 || true
}

smoke_topology_up() {
  trap smoke_cleanup EXIT
  smoke_cleanup # in case a prior run was interrupted before its own trap ran
  ip netns add "$SMOKE_NS_A"
  ip netns add "$SMOKE_NS_B"
  ip link add "$SMOKE_IF_A" netns "$SMOKE_NS_A" type veth peer name "$SMOKE_IF_B" netns "$SMOKE_NS_B"
  ip netns exec "$SMOKE_NS_A" ip link set "$SMOKE_IF_A" up
  ip netns exec "$SMOKE_NS_B" ip link set "$SMOKE_IF_B" up
  ip netns exec "$SMOKE_NS_A" ip link set lo up
  ip netns exec "$SMOKE_NS_B" ip link set lo up
  ip netns exec "$SMOKE_NS_A" ip addr add "$SMOKE_IP_A/24" dev "$SMOKE_IF_A"
  ip netns exec "$SMOKE_NS_B" ip addr add "$SMOKE_IP_B/24" dev "$SMOKE_IF_B"
}

# ping_stats <count> <interval_s> -> prints "loss_pct avg_rtt_ms" on stdout. `-i` below 0.2s needs
# root, which this whole script already requires; count*interval bounds smoke-test wall time.
ping_stats() {
  local count="$1" interval="$2"
  local out
  out="$(ip netns exec "$SMOKE_NS_A" ping -q -c "$count" -i "$interval" -W 2 "$SMOKE_IP_B" 2>&1)"
  local loss avg
  loss="$(echo "$out" | sed -n 's/.*, \([0-9.]*\)% packet loss.*/\1/p')"
  avg="$(echo "$out" | sed -n 's#.*rtt [a-z/]* = [0-9.]*/\([0-9.]*\)/.*#\1#p')"
  if [[ -z "$loss" ]]; then
    echo "[netns-netem] FAIL: could not parse ping packet-loss statistics from:" >&2
    echo "$out" >&2
    exit 1
  fi
  if [[ -z "$avg" ]]; then
    # 100% loss has no rtt line at all — expected shape, not a parse failure.
    avg="0"
  fi
  echo "$loss $avg"
}

# assert_in_range <label> <observed> <low> <high> — plain bash/awk numeric comparison (no bc
# dependency), fails loudly (never a warning) outside the tolerance band.
assert_in_range() {
  local label="$1" observed="$2" low="$3" high="$4"
  if awk -v o="$observed" -v l="$low" -v h="$high" 'BEGIN { exit !(o >= l && o <= h) }'; then
    echo "[netns-netem] PASS: $label observed=$observed within [$low, $high]"
  else
    echo "[netns-netem] FAIL: $label observed=$observed outside expected [$low, $high]" >&2
    exit 1
  fi
}

# parse_netem_loss_pct <tc-qdisc-show-output> -> prints the CONFIGURED netem loss percentage
# (numeric, no '%') parsed from `tc -s qdisc show`'s echoed qdisc line, e.g. a line of the shape:
#   qdisc netem 8001: root refcnt 2 limit 1000 delay 40ms loss 0.5%
# or empty if no such line/field is present. Factored out from assert_netem_loss below purely so it
# can be unit-tested against synthetic tc output (this repo's sandbox has no CONFIG_NET_SCH_NETEM to
# exercise the real thing against) without needing a real tc/netem-capable kernel.
parse_netem_loss_pct() {
  echo "$1" | sed -n 's/.*loss \([0-9.]*\)%.*/\1/p' | head -n1
}

# assert_netem_loss <label> <ns> <iface> <expected_pct> — deterministic (not statistical) check that
# the netem qdisc actually attached to this side reports the expected CONFIGURED loss percentage,
# read straight back from `tc -s qdisc show`. This closes a blind spot the ping-based statistical
# loss check in smoke_one below cannot cover on its own: if apply_netem_pair ever regressed to
# forgetting to halve the configured loss% between the two veth ends (composing to 2L-L^2 via two
# independent per-packet draws instead of the intended L), the resulting round-trip loss still falls
# inside that check's generous [0.2x, 3x] statistical tolerance band for the profiles this script
# cares about — e.g. 1.99% observed vs a 1% target's [0.2%, 3%] band, or 36% vs a 20% target's
# [4%, 60%] band — so a real halving-logic regression would silently pass there. Reading the actual
# configured qdisc parameter back is exact and immune to that blind spot; no larger ping sample would
# help, so this doesn't try to be one.
assert_netem_loss() {
  local label="$1" ns="$2" iface="$3" expected="$4"
  local out reported
  out="$(ip netns exec "$ns" tc -s qdisc show dev "$iface")"
  reported="$(parse_netem_loss_pct "$out")"
  if [[ -z "$reported" ]]; then
    echo "[netns-netem] FAIL: could not parse configured netem loss% for $label ($ns/$iface) from:" >&2
    echo "$out" >&2
    exit 1
  fi
  # Small absolute/relative tolerance for netem's internal fixed-point representation (loss is
  # stored kernel-side as a fraction of UINT32_MAX and may round slightly on display) — this is a
  # deterministic check against the CONFIGURED qdisc parameter, not a statistical sample, so the
  # tolerance only needs to absorb display rounding, not sampling variance.
  local tol tol_low tol_high
  tol="$(awk -v e="$expected" 'BEGIN { t = e * 0.02; if (t < 0.01) t = 0.01; printf "%.4f", t }')"
  tol_low="$(awk -v e="$expected" -v t="$tol" 'BEGIN { printf "%.4f", e - t }')"
  tol_high="$(awk -v e="$expected" -v t="$tol" 'BEGIN { printf "%.4f", e + t }')"
  assert_in_range "$label configured loss% (deterministic; expected per-side half-share)" \
    "$reported" "$tol_low" "$tol_high"
}

# One profile's worth of smoke-check: baseline (no netem — proves the veth pair itself is clean, so
# any loss/delay seen afterward is genuinely injected, not ambient noise) then under the profile.
#
# Sample sizes/tolerances are a deliberate statistical trade-off, not arbitrary:
#   - RTT: netem's `delay` (no jitter configured) is essentially deterministic, so a small sample
#     (20 pings) and a generous +/-25% band comfortably separates "netem applied" (tens of ms) from
#     "netem not applied" (sub-millisecond on a bare veth) with no realistic flake risk.
#   - Loss: a random per-packet draw, so the observed fraction has real sample variance. At the
#     configured TOTAL loss L (recall: L/2 applied to each of two independent hops per round trip),
#     using count=1500 keeps the true positive rate's binomial 3-sigma band comfortably inside a
#     [0.2x, 3x] multiplicative tolerance of the target for both this task's 1%-profile case and the
#     higher-loss case `smoke-all` also runs (which additionally exercises the loss knob with tighter
#     statistical confidence, since 1% alone — expected ~15 losses in 1500 draws — is a fairly thin
#     margin on its own for a single run).
smoke_one() {
  local loss="$1" rtt="$2" label="$3"
  echo "[netns-netem] smoke '$label': profile loss=${loss}% rtt=${rtt}ms"

  echo "[netns-netem] baseline (no netem) — proving the bare veth pair is clean first…"
  local baseline base_loss base_avg
  baseline="$(ping_stats 10 0.05)"
  base_loss="$(echo "$baseline" | cut -d' ' -f1)"
  base_avg="$(echo "$baseline" | cut -d' ' -f2)"
  echo "[netns-netem] baseline: loss=${base_loss}% avg_rtt=${base_avg}ms"
  assert_in_range "baseline loss%" "$base_loss" 0 5
  assert_in_range "baseline avg RTT (ms, bare veth should be sub-ms)" "$base_avg" 0 5

  echo "[netns-netem] applying netem: loss=${loss}% rtt=${rtt}ms (split in half on each side)…"
  apply_netem_pair "$SMOKE_NS_A" "$SMOKE_IF_A" "$SMOKE_NS_B" "$SMOKE_IF_B" "$loss" "$rtt"

  echo "[netns-netem] deterministic check: confirming each side's qdisc actually got the halved" \
       "loss share (catches a halving-logic regression the statistical ping check below can't)…"
  local expected_half_loss
  expected_half_loss="$(awk -v v="$loss" 'BEGIN { printf "%.4f", v / 2 }')"
  assert_netem_loss "side A ($SMOKE_NS_A/$SMOKE_IF_A)" "$SMOKE_NS_A" "$SMOKE_IF_A" "$expected_half_loss"
  assert_netem_loss "side B ($SMOKE_NS_B/$SMOKE_IF_B)" "$SMOKE_NS_B" "$SMOKE_IF_B" "$expected_half_loss"

  echo "[netns-netem] measuring RTT (20 pings)…"
  local rtt_sample rtt_avg
  rtt_sample="$(ping_stats 20 0.1)"
  rtt_avg="$(echo "$rtt_sample" | cut -d' ' -f2)"
  echo "[netns-netem] observed avg RTT=${rtt_avg}ms (configured ${rtt}ms)"
  local rtt_low rtt_high
  rtt_low="$(awk -v v="$rtt" 'BEGIN { printf "%.2f", v * 0.75 }')"
  rtt_high="$(awk -v v="$rtt" 'BEGIN { printf "%.2f", v * 1.25 }')"
  assert_in_range "avg RTT (ms)" "$rtt_avg" "$rtt_low" "$rtt_high"

  echo "[netns-netem] measuring packet loss (1500 pings, this takes ~1-2 minutes)…"
  local loss_sample loss_pct
  loss_sample="$(ping_stats 1500 0.05)"
  loss_pct="$(echo "$loss_sample" | cut -d' ' -f1)"
  echo "[netns-netem] observed loss=${loss_pct}% (configured ${loss}%)"
  local loss_low loss_high
  loss_low="$(awk -v v="$loss" 'BEGIN { printf "%.4f", v * 0.2 }')"
  loss_high="$(awk -v v="$loss" 'BEGIN { printf "%.4f", v * 3.0 }')"
  assert_in_range "loss %" "$loss_pct" "$loss_low" "$loss_high"

  clear_netem_pair "$SMOKE_NS_A" "$SMOKE_IF_A" "$SMOKE_NS_B" "$SMOKE_IF_B"
  echo "[netns-netem] smoke '$label': PASS"
}

smoke() {
  need_root
  need_netem
  smoke_topology_up
  local loss rtt
  if [[ -n "$PROFILE" ]]; then
    loss="$(profile_loss "$PROFILE")"
    rtt="$(profile_rtt "$PROFILE")"
  else
    loss="${LOSS_PCT:-1}"
    rtt="${RTT_MS:-80}"
  fi
  smoke_one "$loss" "$rtt" "${PROFILE:-custom loss=${loss}%/rtt=${rtt}ms}"
}

smoke_all() {
  need_root
  need_netem
  smoke_topology_up
  smoke_one "$(profile_loss file-transfer)" "$(profile_rtt file-transfer)" "file-transfer (feature spec 09)"
  smoke_one 20 200 "high-loss statistical-confidence check"
}

# ---------------------------------------------------------------------------------------------
# CLI arg parsing shared by apply/apply-pair
# ---------------------------------------------------------------------------------------------

parse_loss_rtt_flags() {
  LOSS_PCT=""
  RTT_MS=""
  PROFILE=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --loss) LOSS_PCT="$2"; shift 2 ;;
      --rtt) RTT_MS="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
  done
  if [[ -n "$PROFILE" ]]; then
    LOSS_PCT="$(profile_loss "$PROFILE")"
    RTT_MS="$(profile_rtt "$PROFILE")"
  fi
  if [[ -z "$LOSS_PCT" || -z "$RTT_MS" ]]; then
    echo "usage: --loss <pct> --rtt <ms>  OR  --profile <name>" >&2
    exit 2
  fi
}

# ---------------------------------------------------------------------------------------------
# CLI dispatch — guarded so this file can also be `source`d by a future rig/harness to call
# apply_netem_pair/clear_netem_pair directly without spawning a subshell per call.
# ---------------------------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    apply)
      shift
      ns="${1:?usage: apply <ns> <iface> --loss <pct> --rtt <ms>}"; shift
      iface="${1:?usage: apply <ns> <iface> --loss <pct> --rtt <ms>}"; shift
      need_root
      need_netem
      parse_loss_rtt_flags "$@"
      apply_netem "$ns" "$iface" "$RTT_MS" "$LOSS_PCT"
      echo "[netns-netem] applied to $ns/$iface: delay=${RTT_MS}ms loss=${LOSS_PCT}% (this side's" \
           "share only — see apply-pair for the round-trip-total convenience wrapper)"
      ;;
    clear)
      shift
      ns="${1:?usage: clear <ns> <iface>}"; shift
      iface="${1:?usage: clear <ns> <iface>}"; shift
      need_root
      clear_netem "$ns" "$iface"
      echo "[netns-netem] cleared netem on $ns/$iface"
      ;;
    apply-pair)
      shift
      ns1="${1:?usage: apply-pair <ns1> <if1> <ns2> <if2> --loss <pct> --rtt <ms>}"; shift
      if1="${1:?}"; shift
      ns2="${1:?}"; shift
      if2="${1:?}"; shift
      need_root
      need_netem
      parse_loss_rtt_flags "$@"
      apply_netem_pair "$ns1" "$if1" "$ns2" "$if2" "$LOSS_PCT" "$RTT_MS"
      echo "[netns-netem] applied round-trip totals loss=${LOSS_PCT}% rtt=${RTT_MS}ms across" \
           "$ns1/$if1 <-> $ns2/$if2 (split in half on each side)"
      ;;
    clear-pair)
      shift
      ns1="${1:?usage: clear-pair <ns1> <if1> <ns2> <if2>}"; shift
      if1="${1:?}"; shift
      ns2="${1:?}"; shift
      if2="${1:?}"; shift
      need_root
      clear_netem_pair "$ns1" "$if1" "$ns2" "$if2"
      echo "[netns-netem] cleared netem on $ns1/$if1 and $ns2/$if2"
      ;;
    profile)
      shift
      name="${1:?usage: profile <name>}"
      # Bare assignments (unlike command substitution embedded in an echo argument) DO trip
      # `errexit` on failure, so an unknown profile name's `exit 2` inside profile_loss/profile_rtt
      # correctly aborts here rather than silently printing an empty "loss=% rtt=ms".
      loss="$(profile_loss "$name")"
      rtt="$(profile_rtt "$name")"
      echo "loss=${loss}% rtt=${rtt}ms"
      ;;
    smoke)
      shift
      # Unlike apply/apply-pair, all of --profile/--loss/--rtt are OPTIONAL here (smoke() defaults
      # to the file-transfer profile) — so this uses its own lenient inline parser rather than
      # parse_loss_rtt_flags, which hard-errors when neither a profile nor both --loss/--rtt are given.
      PROFILE=""
      LOSS_PCT=""
      RTT_MS=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --profile) PROFILE="$2"; shift 2 ;;
          --loss) LOSS_PCT="$2"; shift 2 ;;
          --rtt) RTT_MS="$2"; shift 2 ;;
          *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
      done
      smoke
      ;;
    smoke-all)
      smoke_all
      ;;
    *)
      echo "usage: $0 {apply|clear|apply-pair|clear-pair|profile|smoke|smoke-all} ..." >&2
      echo "  see this script's header comment for full usage and the loss/RTT split model." >&2
      exit 2
      ;;
  esac
fi
