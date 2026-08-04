#!/bin/sh
# demo-only entrypoint wrapper (task 2.11). Installs this demo's private CA into the OS trust
# store — needed so WebPKI-mode validation (federation.discovery = "srv"'s mandatory empty
# ca_bundle_path, and the `meridian` CLI's wss:// client, both of which validate against the
# OS/system store — see Dockerfile.rendezvous's header comment) accepts certs this demo's own
# private CA issued, without weakening anything: it is still exactly one CA, scoped to this
# ephemeral container, never the real production trust store.
#
# Idempotent no-op when no CA is mounted (the static-discovery profile pins ca_bundle_path
# explicitly instead and never needs this). Reuses, rather than reimplements, the production
# entrypoint's own /data-ownership + privilege-drop logic (apps/rendezvous/docker-entrypoint.sh) —
# execs straight into it once the CA step is done.
set -e

CA_DIR=/usr/local/share/ca-certificates/meridian-demo
if [ -d "$CA_DIR" ] && [ -n "$(ls -A "$CA_DIR" 2>/dev/null)" ]; then
    cp "$CA_DIR"/*.crt /usr/local/share/ca-certificates/ 2>/dev/null || true
    update-ca-certificates >/dev/null
fi

exec /usr/local/bin/rendezvous-entrypoint.sh "$@"
