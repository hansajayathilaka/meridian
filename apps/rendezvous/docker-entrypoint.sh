#!/bin/sh
set -e

# Docker creates a fresh named volume (or bind-mounted host directory) owned by root — the
# unprivileged `meridian` user this container otherwise runs as can't write into it, which makes
# SQLite fail with "unable to open database file" (code 14) on first boot. Fix ownership here,
# as root, before dropping to `meridian` to actually run the server.
if [ -d /data ]; then
    chown -R meridian:meridian /data
fi

exec gosu meridian "$@"
