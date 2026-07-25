#!/usr/bin/env bash
# Invariant: meridian-rendezvous logs NO raw identifiers — account public keys, IPs, nonces, or
# opaque blob bytes. docs/security/anonymity-and-retention.md "must never" #4;
# .claude/skills/anonymity-model/SKILL.md. Identifiers reach a log line only via
# `apps/rendezvous/src/logid.rs`'s salted `LogId`.
#
# WHY THIS EXISTS NOW (task 1.20 / review finding F21): invariant #4 currently holds only
# *vacuously* — the server logs nothing at all. The first person to add observability will reach for
# `tracing::info!(account = ?account_pub, ...)` and break it silently. This lint plus `LogId` are the
# guard rail, landed ahead of the logging they guard.
#
# ── HONEST LIMITS OF THIS LINT ────────────────────────────────────────────────────────────────────
# This is a grep-based heuristic, not a type system. It catches the shape people actually write and
# nothing more. It DOES catch:
#   * a sensitive identifier name appearing inside a `tracing::`/bare `info!(...)`-style macro call,
#     on one line or spread over several, unless wrapped in `LogId`;
#   * the same for `println!`/`eprintln!`/`print!`/`eprint!`/`panic!`/`dbg!` in server src, which are
#     de facto logging on a server process.
# It does NOT catch:
#   * an identifier laundered through an intermediate binding first
#     (`let a = account_pub; info!(?a)`) — no dataflow analysis here;
#   * a struct that derives `Debug` and happens to contain a key, logged whole (`?state`);
#   * `format!`/`to_string()` built elsewhere and then logged;
#   * anything reaching stdout/stderr from a dependency.
# The real defence remains code review plus `LogId` being the only ergonomic path. Treat a PASS here
# as "the obvious mistake was not made", never as "the invariant is proven".
# ──────────────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Identifier-bearing names that actually exist in this crate (checked against the real source, not
# imagined): account keys, routing targets, challenge nonces, opaque payloads, peer addresses.
SENSITIVE='account_pub|target|peer_addr|remote_addr|nonce|blob|spk|otk|credential|invite|challenge'

# Macros whose output lands in a log or on a console.
LOGGING='(trace|debug|info|warn|error)!|tracing::[a-z_]+!|(e)?print(ln)?!|panic!|dbg!'

# Scan the *.rs files under the given roots and emit `file:line: offending text` for each logging
# macro invocation that mentions a sensitive name without a `LogId` wrapper. Multi-line aware: a
# perl slurp collects each macro call up to its closing paren. Kept as a function so --selftest can
# run it against a planted fixture (mirrors tools/lint-no-serde-on-blob.sh's approach — no bad
# fixture is checked into the tree, since grep lints love matching their own fixtures).
lint_paths() {
  local found=0 root
  for root in "$@"; do
    [ -d "$root" ] || continue
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      echo "  $hit"
      found=1
    done < <(
      find "$root" -name '*.rs' -type f -print0 \
        | xargs -0 -r perl -0777 -ne '
            my $file = $ARGV;
            # Blank out comment bodies FIRST, keeping the newlines so line numbers stay accurate.
            # Without this the lint trips on its own documentation: doc comments legitimately show
            # the forbidden shape as a counter-example (logid.rs does exactly that), and a lint that
            # flags prose is a lint someone deletes. Only whole-line comments are stripped — that is
            # where doc examples live, and it avoids mangling a `//` inside a string literal.
            s{^(\s*)//.*$}{$1}mg;
            # Match a logging macro call and its argument list (non-greedy to the first `);`).
            while (/((?:'"$LOGGING"')\s*\((?:[^()]|\([^()]*\))*?\))/gs) {
              my $call = $1;
              next unless $call =~ /\b(?:'"$SENSITIVE"')\b/;
              next if $call =~ /LogId/;
              # Line number of the match start.
              my $pre = substr($_, 0, pos($_) - length($call));
              my $line = 1 + ($pre =~ tr/\n//);
              my $flat = $call; $flat =~ s/\s+/ /g;
              $flat = substr($flat, 0, 140);
              print "$file:$line: $flat\n";
            }
          '
    )
  done
  return $found
}

if [ "${1:-}" = "--selftest" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/src"

  # Fixture 1: the exact mistake this lint exists to prevent.
  cat > "$tmp/src/bad_single_line.rs" <<'RS'
fn log_it(account_pub: &[u8; 32]) {
    tracing::info!(account = ?account_pub, "client authenticated");
}
RS
  # Fixture 2: bare macro form (the common style once `use tracing::info;` is in scope).
  cat > "$tmp/src/bad_bare_macro.rs" <<'RS'
fn log_it(target: &[u8; 32]) {
    info!(?target, "routing envelope");
}
RS
  # Fixture 3: multi-line call — the shape a rustfmt'd real log line actually takes.
  cat > "$tmp/src/bad_multiline.rs" <<'RS'
fn log_it(account_pub: &[u8; 32], blob: &[u8]) {
    tracing::warn!(
        account = ?account_pub,
        len = blob.len(),
        "oversized payload",
    );
}
RS
  # Fixture 4: println! on a server process is de facto logging.
  cat > "$tmp/src/bad_println.rs" <<'RS'
fn log_it(nonce: &[u8; 32]) {
    println!("challenge nonce: {nonce:?}");
}
RS
  echo "-- selftest: expect FAIL on each raw-identifier fixture --"
  for f in bad_single_line bad_bare_macro bad_multiline bad_println; do
    d=$(mktemp -d)
    cp "$tmp/src/$f.rs" "$d/"
    if lint_paths "$d" >/dev/null; then
      echo "SELFTEST FAILED: $f was not caught."
      rm -rf "$d"
      exit 1
    fi
    rm -rf "$d"
    echo "   caught: $f"
  done

  # Fixture 5: the sanctioned form must NOT trip (a lint that flags correct code gets disabled).
  good=$(mktemp -d)
  cat > "$good/good_logid.rs" <<'RS'
use crate::logid::LogId;
fn log_it(account_pub: &[u8; 32], target: &[u8; 32]) {
    tracing::info!(account = %LogId::new(account_pub), "client authenticated");
    tracing::debug!(
        to = %LogId::new(target),
        "routed envelope",
    );
}
RS
  # Fixture 6: a doc comment showing the forbidden shape as a counter-example must NOT trip. This
  # is a real false positive that was hit and fixed while writing this lint (logid.rs's own module
  # doc documents the mistake it prevents); pinned so comment-stripping cannot silently regress.
  cat > "$good/good_doc_comment.rs" <<'RS'
//! Do NOT write `tracing::info!(account = ?account_pub, "authed")` — use LogId.
/// Counter-example: `info!(?target, "routing")` leaks a routing target.
// Also plain: println!("challenge nonce: {nonce:?}");
fn nothing() {}
RS
  echo "-- selftest: expect PASS on the sanctioned LogId form + doc-comment counter-examples --"
  if ! lint_paths "$good" >/dev/null; then
    echo "SELFTEST FAILED: the sanctioned LogId form or a doc-comment counter-example was flagged."
    rm -rf "$good"
    exit 1
  fi
  rm -rf "$good"
  echo "OK: lint-no-raw-id-logging selftest passed (all four bad shapes trip; LogId form passes)."
  exit 0
fi

echo "▶ Checking meridian-rendezvous logs no raw identifiers…"
if ! lint_paths apps/rendezvous/src; then
  echo "FAIL: a logging macro in apps/rendezvous/src references a raw identifier."
  echo "  The server must not log account keys, routing targets, IPs, nonces, or blob bytes"
  echo "  (docs/security/anonymity-and-retention.md \"must never\" #4)."
  echo "  Wrap it: tracing::info!(account = %LogId::new(account_pub), …)  — see src/logid.rs."
  exit 1
fi
echo "OK: no raw identifiers in server logging macros."
