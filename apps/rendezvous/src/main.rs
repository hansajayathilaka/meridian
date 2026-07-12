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

#[derive(Parser)]
#[command(
    name = "meridian-rendezvous",
    about = "Meridian signaling server (T02)"
)]
struct Args {
    /// Path to the TOML config (see docs/api/rendezvous-protocol-v1.md §Config).
    #[arg(long, default_value = "rendezvous.toml")]
    config: String,
    /// Override the bind address from config.
    #[arg(long)]
    bind: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}; falling back to defaults");
            Config::default()
        }
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
