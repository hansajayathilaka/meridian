#!/usr/bin/env bash
# Invariant: meridian-tui must depend on `meridian-core` and NOTHING else from this workspace —
# in particular, never `meridian-cli`, at any depth. ADR 0020 condition 3 (docs/adr/0020-tui-packaging.md):
# the dependency direction is meridian-cli -> meridian-tui -> meridian-core, never the reverse, so
# the TUI can never accidentally reach into the CLI's private module tree (or vice versa create a
# cycle once meridian-cli depends on meridian-tui for the `meridian tui` subcommand, task 4.12).
#
# Structural (`cargo tree`), mirroring tools/lint-server-no-core.sh's allowlist approach exactly —
# see that script's header for the ALLOWLIST-not-denylist and dev-dependency-exclusion rationale,
# both of which apply identically here.
set -euo pipefail

CRATE="meridian-tui"
ALLOWED='^meridian-(tui|core|proto|envelope|identity|store|crypto|transport|signaling)$'

# Read a `cargo tree --prefix none` rendering on stdin and report any workspace crate in it that is
# not allowlisted. Returns non-zero if a violation is found. Kept as a pure text function so
# --selftest can prove it actually trips without mutating the real manifest.
check_tree() {
  local label="$1" offenders
  offenders=$(sed 's/ .*//' | grep '^meridian-' | sort -u | grep -Ev "$ALLOWED" || true)
  if [ -n "$offenders" ]; then
    echo "FAIL ($label): $CRATE's dependency graph contains workspace crate(s) it must not depend on:"
    echo "$offenders" | sed 's/^/  - /'
    echo "  meridian-tui must depend only on meridian-core (and meridian-core's own dependencies) —"
    echo "  never meridian-cli (ADR 0020 condition 3)."
    echo "  Trace the route with: cargo tree -p $CRATE -e normal,build -i <crate>"
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selftest" ]; then
  # Guards the guard: prove the check trips on a transitive meridian-cli route and passes on a
  # clean graph, the same shape as lint-server-no-core.sh's selftest.
  echo "-- selftest: expect PASS on a clean graph --"
  if ! printf '%s\n' \
    "$CRATE v0.0.0 (/repo/apps/tui)" \
    "meridian-core v0.0.0 (/repo/apps/core)" \
    "ratatui v0.30.2" \
    "crossterm v0.29.0" | check_tree selftest-clean >/dev/null; then
    echo "SELFTEST FAILED: clean graph was reported as a violation."
    exit 1
  fi
  echo "-- selftest: expect FAIL on a TRANSITIVE meridian-cli route --"
  if printf '%s\n' \
    "$CRATE v0.0.0 (/repo/apps/tui)" \
    "meridian-core v0.0.0 (/repo/apps/core)" \
    "some-helper v1.0.0" \
    "meridian-cli v0.0.0 (/repo/apps/cli)" | check_tree selftest-transitive >/dev/null; then
    echo "SELFTEST FAILED: a transitive meridian-cli dependency was not caught."
    exit 1
  fi
  echo "-- selftest: expect FAIL on a direct meridian-cli dependency --"
  if printf '%s\n' \
    "$CRATE v0.0.0 (/repo/apps/tui)" \
    "meridian-cli v0.0.0 (/repo/apps/cli)" | check_tree selftest-direct >/dev/null; then
    echo "SELFTEST FAILED: a direct meridian-cli dependency was not caught."
    exit 1
  fi
  echo "OK: lint-tui-no-cli selftest passed (clean graph passes; transitive + direct meridian-cli violations trip)."
  exit 0
fi

status=0
for variant in "default features::" "all features::--all-features"; do
  label="${variant%%::*}"
  flag="${variant##*::}"
  # shellcheck disable=SC2086 # $flag is intentionally word-split (empty or --all-features).
  if ! tree=$(cargo tree -p "$CRATE" -e normal,build --prefix none $flag 2>&1); then
    echo "FAIL: 'cargo tree -p $CRATE' failed ($label) — cannot verify the invariant, refusing to pass."
    echo "$tree" | sed 's/^/  /'
    exit 1
  fi
  printf '%s\n' "$tree" | check_tree "$label" || status=1
done

if [ "$status" -ne 0 ]; then
  exit 1
fi
echo "OK: $CRATE depends only on meridian-core (transitively; never meridian-cli), checked with default + all features."
