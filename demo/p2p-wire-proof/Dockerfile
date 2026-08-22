# demo/p2p-wire-proof — runtime-only image (task: ad-hoc P2P wire-level verification demo).
#
# Deliberately NOT a `cargo build`-in-container image like demo/two-orgs/Dockerfile.rendezvous:
# this demo's driver script (run-wire-proof.sh) builds `meridian-rendezvous` (--features sqlite)
# and `meridian` (--features webrtc) on the HOST first, copies them into ./bin/ (gitignored;
# build context is THIS directory, not the repo root, since the root .dockerignore excludes
# /target — see docker-compose.yml's `build:`), and this Dockerfile only COPYs them in. No
# package manager, no network access, nothing to fetch — the whole point is a network-monitoring
# proof of what crosses the wire between containers, so the image build itself has no reason to
# touch a network at all.
#
# Base is debian:stable-slim purely for a normal libc + shell + coreutils (id/cat/etc. used by the
# driver script's `docker compose exec`) — no TLS/curl/ca-certificates needed since this demo runs
# the rendezvous on plain `ws://` (single internal docker network, no edge/TLS concern here; see
# demo/two-orgs for the wss:// + private-CA federation demo).

FROM debian:stable-slim
RUN groupadd --system --gid 10001 meridian \
    && useradd --system --uid 10001 --gid meridian --create-home --home-dir /home/meridian meridian
COPY bin/meridian-rendezvous /usr/local/bin/meridian-rendezvous
COPY bin/meridian /usr/local/bin/meridian
USER meridian
WORKDIR /home/meridian
# No ENTRYPOINT/CMD here on purpose — docker-compose.yml sets `command:` per service (the
# rendezvous runs the server binary; alice/bob idle on `sleep infinity` and are driven by the
# driver script via `docker compose exec`, same pattern as demo/two-orgs's `client` service).
