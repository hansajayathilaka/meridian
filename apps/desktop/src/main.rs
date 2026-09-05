//! `meridian-desktop` — Tauri v2 desktop shell (ADR 0010, task 12.3).
//!
//! Runs `meridian-core` in-process (no IPC boundary around secrets — the whole point of choosing
//! Tauri over Electron, ADR 0010) and constructs `apps/store::OsSecretStore` /
//! `apps/transport::WebRtcTransport` exactly as `apps/cli` does (`commands::OS_KEYSTORE_SERVICE`,
//! the `webrtc` feature). This binary wires the Tauri command/event layer defined in
//! `commands.rs`/`tauri_commands.rs` to a live `meridian-core` backend, and (task 12.15) the window
//! chrome around it: the one `main` window (`../tauri.conf.json`'s `app.windows`, backed by
//! `../capabilities/default.json`'s per-command ACL grants) and the native application menu built
//! below, whose Svelte counterpart lives in `../ui/src/App.svelte`. See `commands.rs`'s module doc
//! for the command-naming/event-shape convention this task establishes.

mod commands;
mod tauri_commands;

use std::sync::Arc;

use commands::{DesktopState, TauriEventSink, OS_KEYSTORE_SERVICE};
use meridian_core::identity::{OsSecretStore, SecretStore};
use tauri::menu::{MenuBuilder, MenuEvent, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, Runtime};

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

/// Menu item ids `handle_menu_event` switches on — plain string constants (not an enum) because
/// `tauri::menu::MenuId` is itself just a `String` wrapper (`muda::MenuId`) and comparing against a
/// `&str` is the builder API's own idiom (see the `tauri::menu` doc examples). None of these carry
/// any account/contact identity — only which *view* to switch to, or which non-identifying window/
/// app action to perform — so there is nothing here for the anonymity model to say about them.
///
/// `QUIT`/`WINDOW_MINIMIZE`/`WINDOW_CLOSE` are plain custom items, not `SubmenuBuilder`'s
/// `.quit()`/`.minimize()`/`.close_window()` predefined-item helpers, deliberately: `muda`'s GTK/
/// Linux backend (this crate's dev/CI target) only implements native predefined behavior for
/// `Separator`/`Copy`/`Cut`/`Paste`/`SelectAll`/`About` — every other predefined type (including
/// `Quit`/`Minimize`/`CloseWindow`/`Undo`/`Redo`) is silently *not added to the menu at all* on that
/// backend (`muda::platform_impl::gtk::is_item_supported!`). Rather than ship a menu that quietly
/// loses items depending on platform, `handle_menu_event` below implements these three explicitly
/// against `tauri`'s own cross-platform window API (`AppHandle::exit`/`WebviewWindow::minimize`/
/// `::close`) — the exact pattern `tauri::menu`'s own doc example uses for `"quit"`. Undo/Redo are
/// dropped from the Edit menu entirely rather than reimplemented: they are unsupported the same way
/// on GTK, and in-field undo (Ctrl+Z while typing) is a WebView/DOM-level capability independent of
/// any native menu item, so nothing is lost by not shipping a menu entry for it.
mod menu_ids {
    pub const SIGN_OUT: &str = "sign_out";
    pub const NAV_CONTACTS: &str = "nav_contacts";
    pub const NAV_REQUESTS: &str = "nav_requests";
    pub const QUIT: &str = "quit";
    pub const WINDOW_MINIMIZE: &str = "window_minimize";
    pub const WINDOW_CLOSE: &str = "window_close";
}

/// The one window this shell creates (`../tauri.conf.json`'s `app.windows[0].label`) —
/// `handle_menu_event`'s window-scoped actions resolve it by this label.
const MAIN_WINDOW_LABEL: &str = "main";

/// Builds the native application menu (task 12.15's "menus" half of window chrome) and attaches it
/// to `app` as the global menu bar. Kept to the platform-standard shape every desktop app ships —
/// an app/File submenu (About, Sign Out, Quit), a real Edit submenu (so cut/copy/paste work in the
/// WebView's text inputs — `SubmenuBuilder`'s predefined items forward to the OS's own text-editing
/// commands, not a hand-rolled reimplementation), a View submenu that switches this shell's own
/// in-app view (see `ui/src/App.svelte`'s `menu:navigate` listener), and a Window submenu
/// (minimize/close — see `menu_ids`'s own doc comment for why these three are custom items, not
/// `SubmenuBuilder`'s predefined helpers). No protocol/business logic lives here — every item either
/// emits a `menu:*` event the frontend already has a `MeridianClientAdapter`-backed handler for, or
/// is handled directly in `handle_menu_event` via a plain `tauri` window/app API call.
fn build_app_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<tauri::menu::Menu<R>> {
    let app_menu = SubmenuBuilder::new(app, "Meridian")
        .about(None)
        .separator()
        .text(menu_ids::SIGN_OUT, "Sign Out")
        .separator()
        .text(menu_ids::QUIT, "Quit")
        .build()?;

    let edit_menu = SubmenuBuilder::new(app, "Edit")
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view_menu = SubmenuBuilder::new(app, "View")
        .text(menu_ids::NAV_CONTACTS, "Contacts")
        .text(menu_ids::NAV_REQUESTS, "Message Requests")
        .build()?;

    let window_menu = SubmenuBuilder::new(app, "Window")
        .text(menu_ids::WINDOW_MINIMIZE, "Minimize")
        .text(menu_ids::WINDOW_CLOSE, "Close")
        .build()?;

    MenuBuilder::new(app)
        .items(&[&app_menu, &edit_menu, &view_menu, &window_menu])
        .build()
}

/// Routes a clicked menu item either to a `menu:*` event on the one `main` window
/// (`ui/src/App.svelte` is the only subscriber) or to a direct `tauri` window/app API call — see
/// `menu_ids`'s own doc comment for why quit/minimize/close are handled here rather than via
/// `SubmenuBuilder`'s predefined-item helpers. A failed `emit`/window action (e.g. no window left to
/// act on) is best-effort, matching `commands::TauriEventSink`'s own documented "a failed emit is
/// not itself an error" philosophy — never a reason to crash the whole app over a menu click.
fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    if event.id() == menu_ids::SIGN_OUT {
        let _ = app.emit("menu:sign-out", ());
    } else if event.id() == menu_ids::NAV_CONTACTS {
        let _ = app.emit("menu:navigate", "contacts");
    } else if event.id() == menu_ids::NAV_REQUESTS {
        let _ = app.emit("menu:navigate", "requests");
    } else if event.id() == menu_ids::QUIT {
        app.exit(0);
    } else if event.id() == menu_ids::WINDOW_MINIMIZE {
        if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
            let _ = window.minimize();
        }
    } else if event.id() == menu_ids::WINDOW_CLOSE {
        if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
            let _ = window.close();
        }
    }
    // Every other id (`about`, `cut`, `copy`, `paste`, `select-all`) is a `tauri`-builtin predefined
    // item — already fully handled by the menu system itself before this callback ever runs.
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

            let menu = build_app_menu(app.handle())?;
            app.set_menu(menu)?;

            Ok(())
        })
        .on_menu_event(handle_menu_event)
        .invoke_handler(tauri_commands::invoke_handler())
        .run(tauri::generate_context!())
        .expect("error while running the meridian-desktop application");
}
