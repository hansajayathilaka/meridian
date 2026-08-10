#!/usr/bin/env bash
# Docker build gate smoke test (task 3.12 / F12, Phase-3 review): the image must actually bind and
# must actually drop root before running application code (docker-entrypoint.sh's whole job — see
# docs/operations/docker-image.md §1). No plaintext ever crosses this box, so nothing here inspects
# request/response bodies; it only checks that the container comes up and that PID 1 is the
# unprivileged `meridian` user, not root.
#
# Invoked from .github/workflows/ci.yml's docker-build job, after `docker build --load` has
# produced the image locally. Not network-independent (starts a real container), so it is not run
# as part of `just test` — it belongs to the docker-build CI job only.
#
# Usage: docker-smoke-test.sh <image-tag> <container-name> <host-port>
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <image-tag> <container-name> <host-port>" >&2
  exit 2
fi

IMAGE_TAG="$1"
CONTAINER_NAME="$2"
HOST_PORT="$3"

# Cleanup (container + volume removal) is the caller's job — see .github/workflows/ci.yml's
# separate `cleanup` step (if: always()), which runs whether this script succeeds or fails.

docker run -d --name "$CONTAINER_NAME" \
  -e MERIDIAN_RENDEZVOUS_SERVER__DOMAIN=localhost \
  -e MERIDIAN_RENDEZVOUS_SERVER__ADMISSION=open \
  -e MERIDIAN_RENDEZVOUS_SERVER__DATABASE_URL=sqlite:///data/rendezvous.db \
  -v "${CONTAINER_NAME}-data":/data \
  -p "${HOST_PORT}:8443" \
  "$IMAGE_TAG"

# Wait for docker's own HEALTHCHECK (curl /healthz inside the container) to go healthy, rather than
# polling from the runner — this also exercises the HEALTHCHECK instruction itself, not just the
# server.
for i in $(seq 1 30); do
  status="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" || echo unknown)"
  if [ "$status" = "healthy" ]; then
    break
  fi
  if [ "$status" = "unhealthy" ] || [ "$(docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME")" != "true" ]; then
    echo "::error::container did not come up healthy (status=$status) — see logs below" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
  fi
  sleep 1
done
status="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" || echo unknown)"
if [ "$status" != "healthy" ]; then
  echo "::error::container never became healthy within 30s (status=$status)" >&2
  docker logs "$CONTAINER_NAME" >&2 || true
  exit 1
fi

# PID 1 inside the container must be the unprivileged `meridian` (uid 10001), never root — `docker
# exec` on its own is not proof of this: a fresh exec session defaults to root (no `USER`
# instruction in the image; gosu only affects the entrypoint's own exec'd process), so this must
# read the actual PID 1's uid from /proc, not run `whoami` in a new exec session.
uid="$(docker exec "$CONTAINER_NAME" sh -c 'cat /proc/1/status' | awk '/^Uid:/{print $2}')"
echo "PID 1 uid inside container: $uid"
if [ "$uid" != "10001" ]; then
  echo "::error::container's PID 1 is not running as the unprivileged meridian user (uid 10001); got uid=$uid — privilege drop is broken" >&2
  docker logs "$CONTAINER_NAME" >&2 || true
  exit 1
fi

# /data must have been chowned to meridian by docker-entrypoint.sh, or SQLite would fail to open
# its file there (code 14 SQLITE_CANTOPEN, docs/operations/docker-image.md §1).
owner="$(docker exec "$CONTAINER_NAME" stat -c '%U' /data)"
if [ "$owner" != "meridian" ]; then
  echo "::error::/data is not owned by meridian after entrypoint chown; got owner=$owner" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz"
echo
echo "OK: container bound, healthz responded, PID 1 runs as meridian (uid 10001), /data is meridian-owned."
