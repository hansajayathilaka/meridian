#!/usr/bin/env bash
# Bootstrap a private CA + two org certs for the local two-org federation demo (feature 06).
# Air-gapped federation uses a private CA + static federation map (docs/operations/deployment.md).
set -euo pipefail
OUT="${1:-./infra/deploy/.ca}"
mkdir -p "$OUT"
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found — install it, or provide certs out of band."; exit 1
fi

if [ ! -f "$OUT/ca.key" ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -days 825 \
    -keyout "$OUT/ca.key" -out "$OUT/ca.crt" -subj "/CN=Meridian Dev CA" >/dev/null 2>&1
  echo "created private CA: $OUT/ca.crt"
fi

for org in org-a.test org-b.test; do
  if [ ! -f "$OUT/$org.crt" ]; then
    # `-addext subjectAltName` + `x509 -copy_extensions copyall` (task 2.11 fix): a CN-only leaf
    # (no SAN) fails modern TLS hostname verification outright — rustls-webpki (this server's own
    # TLS stack, apps/rendezvous/src/federation/link.rs) never falls back to the subject CN
    # ("we don't support CN-IDs"), so the s2s mTLS handshake itself — not just this crate's own
    # belt-and-suspenders SAN/CN re-check — would reject every cert this script issued before this
    # fix, for both federation mTLS and the client-facing wss:// edge. `peer_identities` in
    # federation/link.rs still falls back to CN only for certs that genuinely carry no SAN at all
    # (legacy compat); this fix means the demo's own certs never need that fallback.
    openssl req -newkey rsa:2048 -nodes -keyout "$OUT/$org.key" \
      -out "$OUT/$org.csr" -subj "/CN=$org" -addext "subjectAltName=DNS:$org" >/dev/null 2>&1
    openssl x509 -req -in "$OUT/$org.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
      -CAcreateserial -days 825 -out "$OUT/$org.crt" -copy_extensions copyall >/dev/null 2>&1
    rm -f "$OUT/$org.csr"
    # world-readable (not the default 0600 `openssl req -newkey` produces): the two-org demo
    # bind-mounts this key read-only into a container that drops privilege to a non-root uid
    # (meridian, see apps/rendezvous/docker-entrypoint.sh's `gosu`) BEFORE the federation TLS
    # listener opens it (apps/rendezvous/src/main.rs), so a root-only-readable key means the
    # server panics on boot with "Permission denied" the moment federation is enabled — caught by
    # actually running the demo (task 2.11), not by inspection. Dev-only key material in a
    # gitignored directory (see the NOTE at the end of this script) — 0644 costs nothing here that
    # 0600 was actually buying.
    chmod 644 "$OUT/$org.key"
    echo "issued cert for $org (CN + SAN=DNS:$org)"
  fi
done
echo "CA + org certs ready in $OUT (gitignored). Used by the two-org federation demo."
# NOTE: dev only. Production uses the org's real CA/WebPKI (docs/operations/deployment.md).
