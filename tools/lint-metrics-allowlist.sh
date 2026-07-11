#!/usr/bin/env bash
# Invariant: the server exports ONLY allowlisted metrics (docs/operations/monitoring.md).
# Starter lint: extracts metric names from registration macros and checks them against the allowlist.
set -euo pipefail
ALLOW="tools/metrics-allowlist.txt"
FAIL=0
# crude extraction of metric names from common macros: counter!("name" ...), gauge!("name" ...)
NAMES=$(grep -rhoE '(counter|gauge|histogram|register_[a-z_]+)!\(\s*"[a-zA-Z0-9_]+"' apps/rendezvous 2>/dev/null \
        | grep -oE '"[a-zA-Z0-9_]+"' | tr -d '"' | sort -u || true)
for n in $NAMES; do
  if ! grep -qxF "$n" "$ALLOW"; then
    echo "FAIL: metric '$n' is not in the allowlist ($ALLOW)."; FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] && echo "OK: all registered metrics are allowlisted (found: $(echo "$NAMES" | wc -w))."
exit "$FAIL"
