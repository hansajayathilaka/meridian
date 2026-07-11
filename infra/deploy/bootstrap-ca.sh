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
    openssl req -newkey rsa:2048 -nodes -keyout "$OUT/$org.key" \
      -out "$OUT/$org.csr" -subj "/CN=$org" >/dev/null 2>&1
    openssl x509 -req -in "$OUT/$org.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
      -CAcreateserial -days 825 -out "$OUT/$org.crt" >/dev/null 2>&1
    rm -f "$OUT/$org.csr"
    echo "issued cert for $org"
  fi
done
echo "CA + org certs ready in $OUT (gitignored). Used by the two-org federation demo."
# NOTE: dev only. Production uses the org's real CA/WebPKI (docs/operations/deployment.md).
