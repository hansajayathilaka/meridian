//! `meridian-desktop` — Tauri v2 desktop shell (ADR 0010, task 12.3).
//!
//! Runs `meridian-core` in-process (no IPC boundary around secrets — the whole point of choosing
//! Tauri over Electron, ADR 0010) and constructs `apps/store::OsSecretStore` /
//! `apps/transport::WebRtcTransport` exactly as `apps/cli` does (`commands::OS_KEYSTORE_SERVICE`,
//! the `webrtc` feature). No window UI yet (12.15 owns that) — this binary only wires the Tauri
//! command/event layer defined in `commands.rs`/`tauri_commands.rs` to a live `meridian-core`
//! backend. See `commands.rs`'s module doc for the command-naming/event-shape convention this task
//! establishes.

mod commands;
mod tauri_commands;

use std::sync::Arc;

use commands::{DesktopState, TauriEventSink, OS_KEYSTORE_SERVICE};
use meridian_core::identity::{OsSecretStore, SecretStore};
use tauri::Manager;

/// The concrete `Transport` this binary's long-lived session state is generic over. Real
/// ICE/SCTP/DTLS (`WebRtcTransport`, 1.15's backend) when built with `--features webrtc` —
/// mirrors `apps/cli`'s identical feature-gated construction exactly. Without that feature, this
/// binary still compiles (`cargo check --workspace`'s default-feature signal stays complete), but
/// every command that would dial/answer a real peer over `AppTransport` fails closed with a clear
/// "rebuild with --features webrtc" error before ever touching a transport instance — see
/// `tauri_commands::require_webrtc`, mirroring `apps/cli/src/session_connect.rs`'s identical
/// non-webrtc fallback. `LoopbackTransport` here is never reachable from a real command in that
/// build; it exists purely so `AppTransport` has a concrete, always-available type to compile
/// against.
#[cfg(feature = "webrtc")]
pub(crate) type AppTransport = meridian_core::transport::WebRtcTransport;
#[cfg(not(feature = "webrtc"))]
pub(crate) type AppTransport = meridian_core::transport::LoopbackTransport;

fn build_transport() -> Arc<AppTransport> {
    #[cfg(feature = "webrtc")]
    {
        Arc::new(meridian_core::transport::WebRtcTransport::new())
    }
    #[cfg(not(feature = "webrtc"))]
    {
        Arc::new(meridian_core::transport::LoopbackTransport::new(
            meridian_core::transport::LoopbackFabric::new(),
        ))
    }
}

/// Where inbound `mrd.file/1` transfers are written — `$MERIDIAN_HOME/downloads` (next to the
/// account descriptor / sealed session+trust stores, `meridian_core::account::config_dir`), never
/// an arbitrary caller-supplied path from the WebView.
fn download_dir() -> std::path::PathBuf {
    meridian_core::account::config_dir()
        .map(|d| d.join("downloads"))
        .unwrap_or_else(|_| std::env::temp_dir().join("meridian-downloads"))
}

fn main() {
    let store: Box<dyn SecretStore> = Box::new(OsSecretStore::new(OS_KEYSTORE_SERVICE));
    let transport = build_transport();
    let downloads = download_dir();

    tauri::Builder::default()
        .setup(move |app| {
            let events = Arc::new(TauriEventSink(app.handle().clone()));
            let state: DesktopState<AppTransport> =
                DesktopState::new(store, transport, events, downloads);
            // Best-effort: pick up an already-onboarded account so `account_get` has something to
            // return on first launch, mirroring `apps/cli`'s own `AccountDescriptor::load()` calls.
            let _ = state.account_load();
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri_commands::invoke_handler())
        .run(tauri::generate_context!())
        .expect("error while running the meridian-desktop application");
}
