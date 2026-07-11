#!/usr/bin/env bash
# Invariant: envelope payloads stay OPAQUE server-side — no structured (de)serialization of blob
# contents in proto/server routing paths. docs/security/anonymity-and-retention.md "must never" #1.
# Starter lint (grep-based); tighten as real code lands.
set -euo pipefail
FAIL=0
# 1) payload fields must be OpaqueBlob / Vec<u8> / Bytes, never String/serde_json::Value.
if grep -rnE 'payload\s*:\s*(String|serde_json::Value)' apps/proto apps/rendezvous 2>/dev/null; then
  echo "FAIL: an envelope payload is typed as structured data instead of OpaqueBlob."; FAIL=1
fi
# 2) the routing path must not deserialize payloads.
if grep -rnE '(from_slice|from_reader)::<.*(Envelope|Chat|Message).*>' apps/rendezvous 2>/dev/null; then
  echo "FAIL: server routing path appears to deserialize message content."; FAIL=1
fi
[ "$FAIL" -eq 0 ] && echo "OK: no structured (de)serialization of opaque payloads detected."
exit "$FAIL"
