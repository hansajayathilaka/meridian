#!/usr/bin/env bash
# One-time devcontainer setup for Meridian. Idempotent; safe to re-run.
set -uo pipefail
echo "▶ Meridian devcontainer setup…"

# Volume-mounted dirs are created as root — hand them to the dev user.
sudo chown -R "$(id -u):$(id -g)" target /usr/local/cargo/registry 2>/dev/null || true

# --- Rust: components + WASM target (Android/iOS are opt-in; see README) -------
rustup component add rustfmt clippy >/dev/null 2>&1 || true
rustup target add wasm32-unknown-unknown

# --- Fast, prebuilt cargo tooling via cargo-binstall ---------------------------
if ! command -v cargo-binstall >/dev/null 2>&1; then
  curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash || true
  export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"
fi
# just (task runner), test runner, license/advisory gate (ADR 0011), WASM build tools.
cargo binstall -y just cargo-nextest cargo-deny wasm-pack trunk || \
  echo "⚠ some cargo tools failed to binstall — run 'cargo install <tool>' manually if needed."

# --- Node / pnpm ---------------------------------------------------------------
corepack enable >/dev/null 2>&1 || true
corepack prepare pnpm@latest --activate >/dev/null 2>&1 || true
if [ -f pnpm-workspace.yaml ] || [ -f package.json ]; then
  pnpm install || echo "⚠ pnpm install had issues (fine for the scaffold; UIs are stubs)."
fi

# --- Docs tooling: mermaid-cli (uses the system chromium) ----------------------
npm i -g @mermaid-js/mermaid-cli >/dev/null 2>&1 || \
  echo "⚠ mermaid-cli global install failed — 'just check-docs' mermaid step will be skipped."

# --- Prime caches & verify the workspace is healthy ----------------------------
cargo fetch || true
echo "▶ Running enforcement lints (must be green)…"
bash tools/lint-server-no-core.sh
bash tools/lint-no-serde-on-blob.sh
bash tools/lint-metrics-allowlist.sh

cat <<'DONE'

✅ Meridian devcontainer ready.

  Build / test / lint:      just build   ·   just test   ·   just lint
  Run the reference CLI:    cargo run -p meridian-cli
  Validate docs:            just check-docs
  Two-org federation demo:  just two-orgs        (uses Docker-in-Docker)

  New to the repo?  Read CLAUDE.md, then run the /new-task command in Claude Code.
  Heavy toolchains (Android NDK, libwebrtc) are opt-in — see .devcontainer/README.md.
DONE
