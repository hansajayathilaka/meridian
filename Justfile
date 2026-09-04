# Meridian task runner. These recipes are what CI runs — local == CI.
# Developer loop reference: docs/architecture/stack.md §7

# Install toolchains (targets/tools). Scaffold: documents the intent.
setup:
    @echo "TODO: rustup targets (wasm32, aarch64-*); pnpm; cargo-nextest/-ndk/-deny; just"
    @echo "coverage (just coverage): rustup component add llvm-tools-preview && cargo install cargo-llvm-cov"

# Build the whole workspace.
build:
    cargo build --workspace

# Format + clippy + repo invariants.
lint: fmt-check lint-invariants
    cargo clippy --workspace --all-targets -- -D warnings

fmt-check:
    cargo fmt --all -- --check

# Enforceable architecture/security invariants (see tools/).
lint-invariants:
    bash tools/lint-server-no-core.sh
    # Guards the guard: proves the cargo-tree check still trips on a TRANSITIVE core dependency
    # (the route the old grep-based version could never see) rather than silently regressing.
    bash tools/lint-server-no-core.sh --selftest
    # ADR 0020 condition 3: meridian-tui depends on meridian-core only, never meridian-cli.
    bash tools/lint-tui-no-cli.sh
    bash tools/lint-tui-no-cli.sh --selftest
    bash tools/lint-no-serde-on-blob.sh
    # Guards the guard: proves check-3 above still trips on the F15 bypass patterns (module-
    # qualified type paths, multi-line `let x: T = ... .decode()`) rather than silently regressing.
    bash tools/lint-no-serde-on-blob.sh --selftest
    bash tools/lint-metrics-allowlist.sh
    # Invariant #4 (server logs no raw identifiers) — landed ahead of observability, so the first
    # log line added cannot break it silently. See apps/rendezvous/src/logid.rs.
    bash tools/lint-no-raw-id-logging.sh
    bash tools/lint-no-raw-id-logging.sh --selftest

# Tests: unit/integration + adversarial harnesses + (later) conformance vectors.
test: build harnesses
    cargo test --workspace
    # Real webrtc-rs transport backend (1.15): real ICE/SCTP/DTLS on localhost, opt-in feature so
    # default builds/CI-without-this-step stay pure-Rust and network-free.
    cargo test -p meridian-transport --features webrtc
    cargo test -p meridian-core --features webrtc
    cargo test -p meridian-cli --features webrtc
    @echo "TODO: migrate to cargo nextest run --workspace"
    @echo "TODO: conformance vectors — docs/testing/strategy.md §1"

# Run the adversarial harnesses (stubs until their features land).
harnesses:
    bash harnesses/opacity-audit/run.sh
    bash harnesses/mitm-sim/run.sh
    bash harnesses/ghost-device/run.sh
    bash harnesses/nat-matrix/run.sh

# Coverage measurement (task 1.21 / review finding F22). MEASUREMENT ONLY — deliberately not a
# blocking gate, and not part of `lint` or `test`. Needs `cargo install cargo-llvm-cov` and the
# `llvm-tools-preview` rustup component (see `setup`).
#
# NOTE: this reports region/line/function coverage. Rust on **stable** does not emit branch coverage
# (llvm-cov's Branches column stays empty), so a "branch coverage" target is not measurable with the
# toolchain this repo pins — see docs/architecture/features/01-identity-keystore-core.md.
coverage:
    cargo llvm-cov --workspace --summary-only

# Same, as an HTML report under target/llvm-cov/html for drilling into uncovered lines.
coverage-html:
    cargo llvm-cov --workspace --html
    @echo "report: target/llvm-cov/html/index.html"

# wasm32 substrate check (task 12.1 + task 12.4, T11 browser substrate): every crate meridian-core
# depends on, `meridian-core` itself, and `meridian-signaling`, all compiling clean for
# wasm32-unknown-unknown. Task 12.1 landed the first six (store/identity/crypto/proto/envelope/
# transport); task 12.4 closed the remaining two — meridian-signaling's `tokio-tungstenite`/
# `rustls` had no wasm32 story at all (fixed by `apps/signaling/src/ws_transport.rs`'s
# `WsConnection` seam, native unchanged / wasm32 → the browser's own `WebSocket`), and
# meridian-core's own `tokio` dependency turned out to need the same per-target split task 12.1
# already found necessary for `apps/transport/Cargo.toml` (a member's own `features = [...]` list
# *unions* onto the workspace default rather than restricting it). Deliberately package-scoped, not
# `--workspace --target wasm32-unknown-unknown`: no other workspace member (`meridian-cli`,
# `meridian-tui`, `meridian-rendezvous`, `meridian-desktop`, …) is wasm32-buildable or meant to be —
# only the shared-core dependency chain browser/desktop clients (T11) actually need.
check-wasm32:
    cargo check -p meridian-store -p meridian-identity -p meridian-crypto -p meridian-proto -p meridian-envelope -p meridian-transport -p meridian-signaling -p meridian-core --target wasm32-unknown-unknown

# Codegen (UniFFI + wasm-bindgen) and conformance vectors.
codegen:
    cargo run -p xtask -- codegen

vectors:
    cargo run -p xtask -- vectors

# Local two-org federation demo (task 2.11): brings up two full org stacks (rendezvous+coturn x2,
# private CA, TLS edges) with no internet required once built, and drives a real cross-org E2EE
# chat (+ P2P where it establishes) between them. `mode` is `static` (air-gap federation map, the
# default) or `srv` (real internal DNS SRV discovery) — see demo/two-orgs/README.md for both modes,
# what each proves, and troubleshooting. Tears itself down on exit; set KEEP_UP=1 to leave it up.
two-orgs mode="static":
    bash demo/two-orgs/run-walkthrough.sh {{mode}}

# Docker-based wire-level proof of the core P2P claim: a packet capture across rendezvous +
# coturn + two clients shows a chat message crossing client-to-client, never through the server —
# both under the default direct policy and under a forced relay-only/TURN path. See
# demo/p2p-wire-proof/README.md. Tears itself down on exit; set KEEP_UP=1 to leave it up.
p2p-wire-proof:
    bash demo/p2p-wire-proof/run-wire-proof.sh

# Same wire-level proof as `just p2p-wire-proof`, but against a real, already-deployed rendezvous
# server instead of a local Docker stack — no Docker needed, just the host's own tcpdump. Defaults
# to wss://rendezvous.hansajayathilaka.com; override with `RENDEZVOUS_URL=wss://... just
# p2p-wire-proof-live`. See demo/p2p-wire-proof/LIVE-SERVER-PROOF.md for a recorded run.
p2p-wire-proof-live:
    bash demo/p2p-wire-proof/run-live-server-proof.sh

# Validate docs: mermaid syntax + relative links.
check-docs:
    bash tools/check-docs.sh
