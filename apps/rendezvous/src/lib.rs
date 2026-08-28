//! meridian-rendezvous — the always-on signaling server (T02).
//!
//! Responsibilities & the "cannot" list: ../../docs/architecture/system-design.md §2.
//! Wire protocol: ../../docs/api/rendezvous-protocol-v1.md. Data model:
//! ../../docs/architecture/data-model.md.
//!
//! The server routes opaque, client-signed envelopes and stores public prekey material. It holds
//! no plaintext content and no session/ratchet code, and depends only on `meridian-proto` (plus
//! `ed25519-dalek` to VERIFY client auth signatures). Exposed as a library so integration tests
//! can drive a real server in-process.

pub mod auth;
pub mod config;
/// s2s mTLS federation link establishment (task 2.4) — in-process TLS termination, never a
/// proxy/VIP (ADR 0017 C7). See `federation::mod` for the full scope boundary.
pub mod federation;
pub mod logid;
pub mod mailbox_purge;
pub mod metrics;
pub mod ratelimit;
/// TEST HOOK (task 1.32): malicious-relay attacks on the routed path that pass the envelope
/// signature check. Compiled in only under the `test-tamper-hook` cargo feature (F17).
#[cfg(feature = "test-tamper-hook")]
pub mod route_tamper;
pub mod state;
pub mod store;
pub mod turn;
mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

pub use config::Config;
pub use state::AppState;
pub use store::{MemoryStore, Store};

/// Build the axum router: `/` (WSS signaling), `/healthz`, `/metrics`.
pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(ws_handler))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Serve on an already-bound listener until it stops (tests bind an ephemeral port and read the
/// address back). Connection info is required so the WS handler can rate-limit per source IP.
pub async fn serve(state: Arc<AppState>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let app = build_app(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Build the configured default store. In-memory unless the `sqlite` feature is enabled.
#[cfg(not(feature = "sqlite"))]
pub async fn default_store(_config: &Config) -> Arc<dyn Store> {
    Arc::new(MemoryStore::new())
}

#[cfg(feature = "sqlite")]
pub async fn default_store(config: &Config) -> Arc<dyn Store> {
    Arc::new(
        store::SqliteStore::connect(&config.server.database_url)
            .await
            .expect("open SQLite store"),
    )
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws::handle_socket(socket, state, addr.ip()))
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> String {
    let depth = state.store.total_otks().await.unwrap_or(0);
    state.metrics.render(depth)
}
