//! meridian-rendezvous — signaling server entry point.
//!
//! Responsibilities & "cannot" list: ../../docs/architecture/system-design.md §2
//! Feature spec: ../../docs/architecture/features/02-rendezvous-mvp.md
//! Wire protocol: ../../docs/api/rendezvous-protocol-v1.md
//!
//! Holds no plaintext by construction: it routes opaque signed envelopes and stores public prekey
//! material only. TLS termination for `wss://` is provided by the deployment's reverse proxy / VIP
//! (ADR-8); the server speaks WebSocket on its bind address.

use clap::Parser;
use meridian_rendezvous::{default_store, serve, AppState, Config};

/// Conventional config path used only when `--config` is not supplied at all (best-effort,
/// non-fatal if missing/unparseable — see the `None` arm of `main`'s config load below).
const DEFAULT_CONFIG_PATH: &str = "rendezvous.toml";

#[derive(Parser)]
#[command(
    name = "meridian-rendezvous",
    about = "Meridian signaling server (T02)"
)]
struct Args {
    /// Path to the TOML config (see docs/api/rendezvous-protocol-v1.md §Config). Defaults are used
    /// only when this flag is entirely absent; an explicitly supplied path that fails to load is a
    /// fatal error (fail-closed — never silently boot with weaker-than-intended settings).
    #[arg(long)]
    config: Option<String>,
    /// Override the bind address from config.
    #[arg(long)]
    bind: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut config = match &args.config {
        // Explicitly supplied on the CLI: a load/parse failure is fatal — never silently boot
        // with defaults, which could turn an invite-only/restricted config into open
        // registration (threat-model goal 6, "never silently weaker").
        Some(path) => match Config::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "config: failed to load explicitly-supplied --config {path}: {e}; refusing to boot with defaults"
                );
                std::process::exit(1);
            }
        },
        // No --config given: best-effort load the conventional `rendezvous.toml` from the
        // working directory, but silently fall back to defaults if it's absent or unparseable —
        // this is the documented "no config" default-boot path, not a user-requested load.
        None => Config::load(DEFAULT_CONFIG_PATH).unwrap_or_default(),
    };
    if let Some(bind) = args.bind {
        config.server.bind = bind;
    }

    let bind = config.server.bind.clone();
    let domain = config.server.domain.clone();
    let store = default_store(&config).await;
    let state = AppState::new(config, store);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    println!(
        "meridian-rendezvous: domain={domain} listening on {bind} — holds no plaintext by construction"
    );
    if let Err(e) = serve(state, listener).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
