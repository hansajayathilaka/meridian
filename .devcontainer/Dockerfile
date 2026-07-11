# Meridian development image.
# Base: official Rust devcontainer (Debian bookworm, rustup + stable + non-root `vscode` user).
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# --- System dependencies -----------------------------------------------------
# Grouped by why they're here so the list stays auditable.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && apt-get install -y --no-install-recommends \
    # Tauri v2 (Linux desktop) — webkit2gtk 4.1 on bookworm + app-indicator/rsvg
    libwebkit2gtk-4.1-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libxdo-dev \
    libsoup-3.0-dev \
    # Common native-build needs for the crypto/webrtc crate graph (ring/aws-lc, *-sys)
    build-essential \
    cmake \
    clang \
    libclang-dev \
    nasm \
    pkg-config \
    libssl-dev \
    # Server storage (SQLite default; Postgres via compose when needed)
    sqlite3 \
    libsqlite3-dev \
    # CA bootstrap for the two-org federation demo
    openssl \
    # Docs validation: mermaid-cli renders via headless chromium
    chromium \
    fonts-liberation \
    # General tooling
    curl wget file jq git-lfs unzip ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# mermaid-cli should use the system chromium, never try to download its own.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# --- Optional heavy toolchains (OFF by default; see .devcontainer/README.md) --
# Android cross-compile (feature 12) and vendored libwebrtc (ADR 0014, feature 10)
# are intentionally NOT installed here to keep the image small and fast.
# Enable Android by setting build arg INSTALL_ANDROID=true.
ARG INSTALL_ANDROID=false
# (Android SDK/NDK install is documented in .devcontainer/README.md rather than
#  baked in, to avoid a multi-GB default image. TODO: wire when feature 12 starts.)
