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

    // `Config::load` merges the TOML file (explicit `--config`, or the conventional
    // `rendezvous.toml` when absent) with `MERIDIAN_<SECTION>__<FIELD>` env vars (ADR 0018,
    // docs/api/rendezvous-protocol-v1.md §5). It fails closed uniformly: a missing explicit
    // `--config`, a malformed TOML file (on either path), or a bad env var are all fatal — never
    // silently boot with weaker-than-intended settings (threat-model goal 6, "never silently
    // weaker"). Only a *missing* file on the implicit (no `--config`) path is non-fatal.
    let mut config = match Config::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}; refusing to boot with an ambiguous config");
            std::process::exit(1);
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
