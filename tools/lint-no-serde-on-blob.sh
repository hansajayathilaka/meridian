#!/usr/bin/env bash
# Invariant: envelope payloads stay OPAQUE server-side — no structured (de)serialization of blob
# contents in proto/server routing paths. docs/security/anonymity-and-retention.md "must never" #1.
#
# This is now DEFENSE IN DEPTH, not the primary control: the F15 fix moved every content-shaped
# type (MessageEnvelope, ChatContent, SignalContent, CtrlFrame, ...) into a separate crate
# (`meridian-envelope`, apps/envelope) that `apps/rendezvous/Cargo.toml` never lists as a
# dependency — direct or dev — so the compiler itself rejects any import of those types from
# server code under every build command, including `cargo build --workspace`. A Cargo-feature
# split was tried first and rejected: Cargo unifies feature flags across a workspace build, so it
# does not hold under `cargo build --workspace` / `cargo test --workspace`. The dependency-graph
# split does hold under those commands (see apps/envelope/src/lib.rs for the full rationale and
# apps/proto/src/lib.rs). This script stays as a second, independent line of defense: it also
# scans for the (older, weaker) pattern of a content-shaped type merely being *named* structurally
# in server-adjacent code, which would be a smell even without a successful import.
#
# Three checks:
#   1) `payload:` fields must stay OpaqueBlob/Vec<u8>/Bytes, never String/serde_json::Value.
#   2) turbofish-style structured decode of envelope/content-shaped types
#      (`from_slice::<Chat...>`, `decode::<Envelope...>`, etc).
#   3) type-inferred decode — the server's REAL style, `let x: T = ...frame.decode()` — where `T`
#      is anything other than an allowlisted control-plane wire type. This is what F15 found the
#      old lint missed: apps/rendezvous/src/ws.rs never writes `from_slice::<T>`, it writes
#      `let auth: Auth = frame.decode()` with `T` inferred from the binding's type annotation.
#      This check is multi-line-aware (a perl slurp pass, not per-line grep) and resolves
#      module-qualified type paths (`content::ChatContent`) to their last path segment before
#      checking the allowlist, closing two independently-reproduced bypasses:
#        - `let content: content::ChatContent = frame.decode().unwrap();` (module-qualified path)
#        - `let content: ChatContent =\n    match frame.decode() { ... };` (multi-line statement)
set -euo pipefail
FAIL=0

# Control-plane types meridian-rendezvous is legitimately allowed to `frame.decode()` — client<->
# server protocol requests/replies, never envelope/message *content*. Keep in sync with
# apps/proto/src/msg.rs's exports. Anything not on this list trips check 3 below.
ALLOWLIST='^(Auth|AuthOk|Publish|PublishOk|Fetch|Bundle|RouteBody|RouteOk|Deliver|TurnReq|TurnGrant|ErrBody|Challenge)$'

# Multi-line-aware scan for `let NAME: TYPE = ....decode()` across every *.rs file under the given
# roots, emitting `file:line:leaf_type_name` — one per match, with TYPE already resolved to its
# last `::`-path segment and stripped of a single Result<>/Option<> wrapper and any generic args.
# Implemented in perl (slurp mode: the whole file is one string, so `.` can cross newlines) rather
# than line-based grep/sed, specifically so a `let x: T =` and its `.decode()` need not share a
# line — closing the multi-line bypass — and so `mod::Type` paths are resolved rather than simply
# failing to match — closing the module-qualified-path bypass.
find_type_inferred_decodes() {
  local roots=("$@")
  local f
  while IFS= read -r -d '' f; do
    perl -0777 -ne '
      while (/let\s+[A-Za-z_]\w*\s*:\s*([A-Za-z_][A-Za-z0-9_:<>,\s]*?)\s*=\s*(?:(?!;)[\s\S])*?\.decode\(\)/g) {
        my $ty = $1;
        my $pre = substr($_, 0, $-[0]);
        my $line = 1 + ($pre =~ tr/\n//);
        $ty =~ s/\s+//g;
        $ty =~ s/^Result<//; $ty =~ s/^Option<//; $ty =~ s/>$//;
        $ty =~ s/<.*//;
        my @parts = split /::/, $ty;
        my $leaf = $parts[-1];
        print "$ARGV:$line:$leaf\n" if length $leaf;
      }
    ' "$f"
  done < <(find "${roots[@]}" -type f -name '*.rs' -print0 2>/dev/null)
}

lint_paths() {
  local roots=("$@")
  local fail=0

  # 1) payload fields must be OpaqueBlob / Vec<u8> / Bytes, never String/serde_json::Value.
  if grep -rnE 'payload\s*:\s*(String|serde_json::Value)' "${roots[@]}" 2>/dev/null; then
    echo "FAIL: an envelope payload is typed as structured data instead of OpaqueBlob."
    fail=1
  fi

  # 2) turbofish-style structured (de)serialization of envelope/content-shaped types.
  if grep -rnE '(from_slice|from_reader|decode)::<[^>]*(Envelope|Chat|Message|Signal|Content)[^>]*>' "${roots[@]}" 2>/dev/null; then
    echo "FAIL: server routing path appears to deserialize message content (turbofish)."
    fail=1
  fi

  # 3) type-inferred `let x: T = ...decode()` where T is not an allowlisted control-plane type.
  # A multi-line-aware (perl, whole-file slurp) pass: per-line grep cannot see a `.decode()` call
  # that lands on a later line than the `let x: T =` it belongs to, and a naive character class
  # cannot see a module-qualified type path (`content::ChatContent`) either. This scans each *.rs
  # file as one string, finds every `let NAME: TYPE = <no-semicolon-in-between> .decode()`, then
  # resolves TYPE down to its last `::`-path segment (and unwraps one layer of Result<..>/Option<..>
  # and any trailing generic args) before checking the allowlist.
  local hit file lineno ty
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    ty="${rest#*:}"
    if [ -n "$ty" ] && ! printf '%s' "$ty" | grep -qE "$ALLOWLIST"; then
      echo "FAIL: $file:$lineno type-inferred-decodes non-control-plane type '$ty' (frame.decode()-style)."
      fail=1
    fi
  done < <(find_type_inferred_decodes "${roots[@]}")

  return "$fail"
}

# `--selftest` proves the hardened rule actually trips on the pattern F15 found the old lint
# missed, and that it does NOT false-positive on the tree's legitimate control-plane decodes.
# There is no permanent bad-pattern fixture checked into the tree (grep-based lints are easy to
# accidentally match against their own fixtures); the fixture is generated into a scratch dir.
if [ "${1:-}" = "--selftest" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/src"
  cat > "$tmp/src/ws_fixture.rs" <<'RS'
// Fixture (F15): a hypothetical server-side decode of envelope CONTENT via type-inferred
// frame.decode(), mirroring ws.rs's real decode style, but for a content type instead of a
// control-plane request. The old (turbofish-only) lint never caught this shape; the hardened
// check-3 above must.
async fn handle_deliver_bad(frame: &meridian_proto::Frame) {
    let content: ChatContent = match frame.decode() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = content;
}
RS
  # Bypass repro #1 (independently reproduced in review): a module-qualified type path. The old
  # check-3 character class excluded `::`, so this never even matched as a candidate line.
  cat > "$tmp/src/ws_fixture_qualified_path.rs" <<'RS'
async fn handle_deliver_bad_qualified(frame: &meridian_proto::Frame) {
    let content: content::ChatContent = frame.decode().unwrap();
    let _ = content;
}
RS
  # Bypass repro #2 (independently reproduced in review): a multi-line `let x: T =\n .decode()`
  # split across lines, invisible to a purely line-based grep.
  cat > "$tmp/src/ws_fixture_multiline.rs" <<'RS'
async fn handle_deliver_bad_multiline(frame: &meridian_proto::Frame) {
    let content: ChatContent =
        match frame.decode() {
            Ok(c) => c,
            Err(_) => return,
        };
    let _ = content;
}
RS
  echo "-- selftest: expect FAIL on fixtures (frame.decode()-style content decode, incl. both bypasses) --"
  if lint_paths "$tmp"; then
    echo "SELFTEST FAILED: hardened lint did not catch the fixture violation(s)."
    exit 1
  fi
  echo "-- selftest: expect FAIL specifically on the module-qualified-path bypass repro --"
  qual_dir=$(mktemp -d)
  cp "$tmp/src/ws_fixture_qualified_path.rs" "$qual_dir/"
  if lint_paths "$qual_dir"; then
    echo "SELFTEST FAILED: module-qualified-path bypass was not caught."
    rm -rf "$qual_dir"
    exit 1
  fi
  rm -rf "$qual_dir"
  echo "-- selftest: expect FAIL specifically on the multi-line-statement bypass repro --"
  ml_dir=$(mktemp -d)
  cp "$tmp/src/ws_fixture_multiline.rs" "$ml_dir/"
  if lint_paths "$ml_dir"; then
    echo "SELFTEST FAILED: multi-line-statement bypass was not caught."
    rm -rf "$ml_dir"
    exit 1
  fi
  rm -rf "$ml_dir"
  echo "-- selftest: expect PASS on the real tree (no false positives on legitimate decodes) --"
  if ! lint_paths apps/proto apps/rendezvous; then
    echo "SELFTEST FAILED: lint has false positives on the clean tree."
    exit 1
  fi
  echo "SELFTEST OK"
  exit 0
fi

if lint_paths apps/proto apps/rendezvous; then
  FAIL=0
else
  FAIL=$?
fi
[ "$FAIL" -eq 0 ] && echo "OK: no structured (de)serialization of opaque payloads detected."
exit "$FAIL"
