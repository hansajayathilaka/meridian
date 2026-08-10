# meridian-rendezvous — the always-on signaling server (T02).
# Multi-stage: build the single static-ish binary, then run it on a minimal image.
# TLS (wss://) is terminated by the deployment's reverse proxy / VIP (ADR-8); the server speaks
# WebSocket on its bind address.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
# `sqlite` gives the published image real persistence (accounts/bundles survive a restart) instead
# of the in-memory default; sqlx's sqlite driver bundles its own SQLite via cc, so this needs no
# extra apt packages in either stage.
RUN cargo build --release -p meridian-rendezvous --features sqlite

FROM debian:stable-slim
# gosu drops root privileges after docker-entrypoint.sh fixes up volume ownership below — see there
# for why the container can't just start as `meridian` directly.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 meridian && useradd --system --uid 10001 --gid meridian meridian
COPY --from=build /src/target/release/meridian-rendezvous /usr/local/bin/meridian-rendezvous
COPY apps/rendezvous/rendezvous.example.toml /etc/meridian/rendezvous.toml
COPY apps/rendezvous/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# Deliberately no `USER meridian` here — the container starts as root so docker-entrypoint.sh can
# chown a mounted /data volume, then execs the server as `meridian` itself (never runs application
# code as root).
EXPOSE 8443
# Matches this image's actual bind address, 0.0.0.0:8443 — NOT config.rs's own compiled-in
# `[server].bind` default, which is `127.0.0.1:8443` (loopback-only, deliberately fail-closed for a
# bare `cargo run`/library embedding with no config supplied). The 0.0.0.0 this image binds to
# instead comes from `rendezvous.example.toml` (baked in at /etc/meridian/rendezvous.toml, COPY'd
# above), which this ENTRYPOINT loads by default; a container that skips that file (or supplies its
# own with a different bind) will listen elsewhere, and this HEALTHCHECK needs updating to match. If
# you override MERIDIAN_RENDEZVOUS_SERVER__BIND to a different port, override this HEALTHCHECK too
# (e.g. via compose's own `healthcheck:` block, which replaces this one).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD curl -fs http://127.0.0.1:8443/healthz || exit 1
# Config path is overridable; mount your own /etc/meridian/rendezvous.toml in production.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "/usr/local/bin/meridian-rendezvous", "--config", "/etc/meridian/rendezvous.toml"]
