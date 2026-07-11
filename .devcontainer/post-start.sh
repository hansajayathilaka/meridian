#!/usr/bin/env bash
# Runs on every container start. Keep it light.
set -uo pipefail
git config --global --add safe.directory "$(pwd)" 2>/dev/null || true
