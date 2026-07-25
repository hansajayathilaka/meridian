#!/usr/bin/env bash
# Invariant: meridian-rendezvous must depend on `meridian-proto` and NOTHING else from this
# workspace — no meridian-core, -identity, -store, -crypto, -envelope, -transport, -signaling, at
# any depth. This keeps session/ratchet/identity code out of the server by construction.
# docs/adr/0008-infra-topology.md, apps/CLAUDE.md, apps/rendezvous/CLAUDE.md.
#
# This is a STRUCTURAL check (`cargo tree`), not a grep (task 1.20 / review finding F21). The
# previous version grepped `apps/rendezvous/Cargo.toml` for a literal `meridian-core =` line, which
# only ever saw *direct* dependencies spelled exactly that way: a transitive route (rendezvous ->
# some crate -> meridian-core), a path/rename form, or a dependency on meridian-identity/-store/
# -crypto all passed it silently. Resolving the real dependency graph closes all of those.
#
# Design notes:
#   * ALLOWLIST, not denylist. Anything matching `meridian-*` that is not meridian-proto (or the
#     server itself) fails. A denylist of today's crate names would silently miss a crate added
#     tomorrow — this is the fail-closed direction.
#   * `-e normal,build` excludes DEV-dependencies deliberately: the invariant is about what ships
#     in the server binary. A dev-dependency on a core crate would be regrettable but is not a
#     violation of "the server never depends on meridian-core", and treating it as one would make
#     the lint unusable for integration tests that legitimately drive a real client.
#   * Checked twice: default features, and `--all-features`. The crate has a `test-tamper-hook`
#     feature, and a feature is exactly the sort of thing that could quietly pull in a core crate.
#   * Fail-closed: if `cargo tree` itself errors (bad manifest, resolver failure), that is a FAIL,
#     never a silent pass.
set -euo pipefail

SERVER="meridian-rendezvous"
ALLOWED='^meridian-(proto|rendezvous)$'

# Read a `cargo tree --prefix none` rendering on stdin and report any workspace crate in it that is
# not allowlisted. Returns non-zero if a violation is found. Kept as a pure text function so
# --selftest can prove it actually trips without mutating the real manifest.
check_tree() {
  local label="$1" offenders
  offenders=$(sed 's/ .*//' | grep '^meridian-' | sort -u | grep -Ev "$ALLOWED" || true)
  if [ -n "$offenders" ]; then
    echo "FAIL ($label): $SERVER's dependency graph contains workspace crate(s) it must not depend on:"
    echo "$offenders" | sed 's/^/  - /'
    echo "  The server must depend only on meridian-proto (shared wire types)."
    echo "  Trace the route with: cargo tree -p $SERVER -e normal,build -i <crate>"
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selftest" ]; then
  # Guards the guard: prove the check trips on a transitive violation and passes on a clean graph.
  # Synthetic input, so nothing in the tree is mutated (the old grep-based lint could only have
  # been proven by editing Cargo.toml, which risks leaving the repo dirty on failure).
  echo "-- selftest: expect PASS on a clean graph --"
  if ! printf '%s\n' \
    "$SERVER v0.0.0 (/repo/apps/rendezvous)" \
    "meridian-proto v0.0.0 (/repo/apps/proto)" \
    "axum v0.7.9" | check_tree selftest-clean >/dev/null; then
    echo "SELFTEST FAILED: clean graph was reported as a violation."
    exit 1
  fi
  echo "-- selftest: expect FAIL on a TRANSITIVE meridian-core route (what the old grep missed) --"
  if printf '%s\n' \
    "$SERVER v0.0.0 (/repo/apps/rendezvous)" \
    "meridian-proto v0.0.0 (/repo/apps/proto)" \
    "some-helper v1.0.0" \
    "meridian-core v0.0.0 (/repo/apps/core)" | check_tree selftest-transitive >/dev/null; then
    echo "SELFTEST FAILED: a transitive meridian-core dependency was not caught."
    exit 1
  fi
  echo "-- selftest: expect FAIL on meridian-identity/-store/-crypto/-envelope (not just -core) --"
  for crate in meridian-identity meridian-store meridian-crypto meridian-envelope; do
    if printf '%s\n' "$SERVER v0.0.0 (/repo/apps/rendezvous)" "$crate v0.0.0 (/repo/apps/x)" \
      | check_tree "selftest-$crate" >/dev/null; then
      echo "SELFTEST FAILED: $crate was not caught."
      exit 1
    fi
  done
  echo "OK: lint-server-no-core selftest passed (clean graph passes; transitive + sibling-crate violations trip)."
  exit 0
fi

status=0
for variant in "default features::" "all features::--all-features"; do
  label="${variant%%::*}"
  flag="${variant##*::}"
  # shellcheck disable=SC2086 # $flag is intentionally word-split (empty or --all-features).
  if ! tree=$(cargo tree -p "$SERVER" -e normal,build --prefix none $flag 2>&1); then
    echo "FAIL: 'cargo tree -p $SERVER' failed ($label) — cannot verify the invariant, refusing to pass."
    echo "$tree" | sed 's/^/  /'
    exit 1
  fi
  printf '%s\n' "$tree" | check_tree "$label" || status=1
done

if [ "$status" -ne 0 ]; then
  exit 1
fi
echo "OK: $SERVER depends only on meridian-proto (checked transitively, default + all features)."
