# Meridian task runner. These recipes are what CI runs — local == CI.
# Developer loop reference: docs/architecture/stack.md §7

# Install toolchains (targets/tools). Scaffold: documents the intent.
setup:
    @echo "TODO: rustup targets (wasm32, aarch64-*); pnpm; cargo-nextest/-ndk/-deny; just"

# Build the whole workspace.
build:
    cargo build --workspace

# Format + clippy + repo invariants.
lint: fmt-check lint-invariants
    @echo "TODO: cargo clippy --workspace -- -D warnings (once code lands)"
    cargo clippy --workspace --all-targets || true

fmt-check:
    cargo fmt --all -- --check

# Enforceable architecture/security invariants (see tools/).
lint-invariants:
    bash tools/lint-server-no-core.sh
    bash tools/lint-no-serde-on-blob.sh
    bash tools/lint-metrics-allowlist.sh

# Tests: unit/integration + adversarial harnesses + (later) conformance vectors.
test: build harnesses
    cargo test --workspace
    @echo "TODO: migrate to cargo nextest run --workspace"
    @echo "TODO: conformance vectors — docs/testing/strategy.md §1"

# Run the adversarial harnesses (stubs until their features land).
harnesses:
    bash harnesses/opacity-audit/run.sh
    bash harnesses/mitm-sim/run.sh
    bash harnesses/ghost-device/run.sh
    bash harnesses/nat-matrix/run.sh

# Codegen (UniFFI + wasm-bindgen) and conformance vectors.
codegen:
    cargo run -p xtask -- codegen

vectors:
    cargo run -p xtask -- vectors

# Local two-org federation demo (needs the CA bootstrap first).
two-orgs:
    bash infra/deploy/bootstrap-ca.sh
    @echo "TODO: docker compose -f infra/deploy/two-orgs.compose.yml up (see infra/CLAUDE.md)"

# Validate docs: mermaid syntax + relative links.
check-docs:
    bash tools/check-docs.sh
