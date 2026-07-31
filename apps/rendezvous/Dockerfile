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
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 meridian
COPY --from=build /src/target/release/meridian-rendezvous /usr/local/bin/meridian-rendezvous
COPY apps/rendezvous/rendezvous.example.toml /etc/meridian/rendezvous.toml
USER meridian
EXPOSE 8443
# Matches the [server].bind default (0.0.0.0:8443); if you override
# MERIDIAN_RENDEZVOUS_SERVER__BIND to a different port, override this HEALTHCHECK too (e.g. via
# compose's own `healthcheck:` block, which replaces this one).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD curl -fs http://127.0.0.1:8443/healthz || exit 1
# Config path is overridable; mount your own /etc/meridian/rendezvous.toml in production.
ENTRYPOINT ["/usr/local/bin/meridian-rendezvous", "--config", "/etc/meridian/rendezvous.toml"]
