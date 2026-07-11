# Development Container

Reopen the repo in this container and everything the critical path needs is installed and verified.

## Quick start
1. Prerequisites on your machine: Docker + VS Code with the **Dev Containers** extension (or any
   devcontainer-compatible editor / the `devcontainer` CLI).
2. Open the repo → **Reopen in Container** (or `Dev Containers: Rebuild and Reopen in Container`).
3. First build runs [`post-create.sh`](./post-create.sh): Rust targets, prebuilt cargo tools, pnpm
   deps, mermaid-cli, and a green run of the enforcement lints. When it prints ✅, you're ready.
4. Try it:
   ```
   just build          # compile the workspace
   just lint           # fmt + clippy + repo invariants
   just test           # build + adversarial harness stubs
   just check-docs     # validate mermaid + relative links
   cargo run -p meridian-cli
   just two-orgs       # local federation demo (Docker-in-Docker)
   ```

## What's in the image
- **Rust** (stable, from the base image) + `rustfmt`, `clippy`, and the **wasm32** target.
- **Prebuilt cargo tools:** `just`, `cargo-nextest`, `cargo-deny` (enforces the no-AGPL decision in
  [ADR 0011](../docs/adr/0011-ratchet-library.md)), `wasm-pack`, `trunk`.
- **Node LTS + pnpm** (via corepack) for the SvelteKit web and Tauri desktop UIs.
- **Tauri v2 Linux build deps** (webkit2gtk-4.1, gtk-3, app-indicator, rsvg, xdo).
- **Native build deps** for the crypto/webrtc crate graph (cmake, clang, nasm, pkg-config, openssl).
- **SQLite** (default server storage; Postgres runs via compose when you need it).
- **chromium + mermaid-cli** so `just check-docs` validates diagrams.
- **Docker-in-Docker** so the compose stacks and `just two-orgs` run self-contained.
- **openssl** for the federation demo CA (`infra/deploy/bootstrap-ca.sh`).

## Deliberately opt-in (kept out of the default image)
Baking these in would make the image multi-GB and slow the first build for everyone, so they're
enabled only when their phase starts:

- **Android SDK/NDK** (feature 12 — mobile). To enable: add the Android SDK devcontainer feature (or
  install the NDK) and `rustup target add aarch64-linux-android`, then use `cargo-ndk`. iOS builds are
  **not possible in a Linux container** (they need macOS/Xcode) — build those on a Mac host.
- **Vendored libwebrtc** for real-time media ([ADR 0014](../docs/adr/0014-media-stack.md), feature 10).
  This is a large prebuilt binary pulled via git-lfs (already installed). Wire it when feature 10 starts.

<!-- TODO: confirm — add the Android SDK feature block and the libwebrtc fetch step when features
     12 and 10 begin; tracked in docs/handoff-readiness.md §F. -->

## Performance notes
`target/` and the cargo registry are kept on named volumes, so rebuilds stay fast across container
restarts. If a volume ever gets into a bad state, remove it (`docker volume rm meridian-target
meridian-cargo-registry`) and rebuild the container.

## Ports
`8443` rendezvous (WSS) · `3478`/`5349` TURN/STUN · `5173` web (Vite) · `1420` desktop (Tauri) ·
`5432` Postgres. Forwarded automatically.
