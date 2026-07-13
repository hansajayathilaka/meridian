# meridian-rendezvous — the always-on signaling server (T02).
# Multi-stage: build the single static-ish binary, then run it on a minimal image.
# TLS (wss://) is terminated by the deployment's reverse proxy / VIP (ADR-8); the server speaks
# WebSocket on its bind address.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
# Build only the server binary (default features = in-memory store; add `sqlite` for persistence).
RUN cargo build --release -p meridian-rendezvous

FROM debian:stable-slim
RUN useradd --system --uid 10001 meridian
COPY --from=build /src/target/release/meridian-rendezvous /usr/local/bin/meridian-rendezvous
COPY apps/rendezvous/rendezvous.example.toml /etc/meridian/rendezvous.toml
USER meridian
EXPOSE 8443
# Config path is overridable; mount your own /etc/meridian/rendezvous.toml in production.
ENTRYPOINT ["/usr/local/bin/meridian-rendezvous", "--config", "/etc/meridian/rendezvous.toml"]
