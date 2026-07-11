#!/usr/bin/env bash
# Invariant: meridian-rendezvous must NOT depend on meridian-core (only meridian-proto).
# docs/adr/0008-infra-topology.md, apps/CLAUDE.md. This lint is fully enforceable today.
set -euo pipefail
CARGO="apps/rendezvous/Cargo.toml"
if grep -qE '^\s*meridian-core\s*=' "$CARGO"; then
  echo "FAIL: meridian-rendezvous depends on meridian-core — the server must depend only on meridian-proto."
  exit 1
fi
echo "OK: server does not depend on meridian-core."
