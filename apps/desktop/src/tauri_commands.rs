//! Concrete `#[tauri::command]` wrappers over `commands::DesktopState<AppTransport>` — thin
//! marshaling only (parse args, call the generic, already-tested method in `commands.rs`, return
//! its `Result`). See `commands.rs`'s module doc for the naming convention and the security
//! invariant every wrapper here must uphold (result DTOs only, never key material).

use std::path::PathBuf;

use tauri::State;

use crate::commands::{
    AccountView, ChatEvent, ContactView, DesktopState, FileSentResult, SentMessage, SessionView,
};
use crate::AppTransport;

type S<'a> = State<'a, DesktopState<AppTransport>>;

#[cfg(feature = "webrtc")]
fn require_webrtc() -> Result<(), String> {
    Ok(())
}

/// Mirrors `apps/cli/src/session_connect.rs`'s identical non-`webrtc`-build fallback: every
/// command that would dial/answer a real cross-process peer fails closed with this message rather
/// than silently trying (and failing in a confusing way) over the placeholder `LoopbackTransport`
/// `AppTransport` resolves to without the feature — see `main.rs`'s `AppTransport` doc.
#[cfg(not(feature = "webrtc"))]
fn require_webrtc() -> Result<(), String> {
    Err(
        "meridian-desktop was built without the `webrtc` feature; rebuild with `--features \
         webrtc` to use session_connect/file_send/chat_send"
            .to_string(),
    )
}

#[tauri::command]
pub async fn account_create(state: S<'_>, hint: String) -> Result<AccountView, String> {
    state.account_create(&hint)
}

#[tauri::command]
pub async fn account_load(state: S<'_>) -> Result<Option<AccountView>, String> {
    state.account_load()
}

#[tauri::command]
pub async fn account_get(state: S<'_>) -> Result<Option<AccountView>, String> {
    Ok(state.account_get())
}

#[tauri::command]
pub async fn contact_add(
    state: S<'_>,
    id: String,
    petname: Option<String>,
) -> Result<ContactView, String> {
    state.contact_add(&id, petname).await
}

#[tauri::command]
pub async fn contact_list(state: S<'_>) -> Result<Vec<ContactView>, String> {
    state.contact_list().await
}

#[tauri::command]
pub async fn contact_rename(
    state: S<'_>,
    id: String,
    petname: String,
) -> Result<ContactView, String> {
    state.contact_rename(&id, &petname).await
}

#[tauri::command]
pub async fn contact_block(state: S<'_>, id: String, blocked: bool) -> Result<ContactView, String> {
    state.contact_block(&id, blocked).await
}

#[tauri::command]
pub async fn contact_mark_verified(state: S<'_>, id: String) -> Result<ContactView, String> {
    state.contact_mark_verified(&id).await
}

#[tauri::command]
pub async fn contact_acknowledge_key_change(
    state: S<'_>,
    id: String,
) -> Result<ContactView, String> {
    state.contact_acknowledge_key_change(&id).await
}

#[tauri::command]
pub async fn contact_answer_request(
    state: S<'_>,
    id: String,
    accept: bool,
) -> Result<Option<ChatEvent>, String> {
    state.contact_answer_request(&id, accept).await
}

#[tauri::command]
pub async fn session_connect(
    state: S<'_>,
    peer_id: String,
    server: String,
) -> Result<SessionView, String> {
    require_webrtc()?;
    state.session_connect(&peer_id, &server).await
}

#[tauri::command]
pub async fn session_get(state: S<'_>, peer_id: String) -> Result<Option<SessionView>, String> {
    state.session_get(&peer_id).await
}

#[tauri::command]
pub async fn session_close(state: S<'_>, peer_id: String) -> Result<(), String> {
    state.session_close(&peer_id).await
}

#[tauri::command]
pub async fn chat_send(state: S<'_>, peer_id: String, text: String) -> Result<SentMessage, String> {
    state.chat_send(&peer_id, &text).await
}

#[tauri::command]
pub async fn pump_once(state: S<'_>, peer_id: String) -> Result<Option<ChatEvent>, String> {
    state.pump_once(&peer_id).await
}

#[tauri::command]
pub async fn file_send(
    state: S<'_>,
    peer_id: String,
    path: String,
) -> Result<FileSentResult, String> {
    require_webrtc()?;
    state.file_send(&peer_id, &PathBuf::from(path)).await
}

pub fn invoke_handler() -> impl Fn(tauri::ipc::Invoke) -> bool {
    tauri::generate_handler![
        account_create,
        account_load,
        account_get,
        contact_add,
        contact_list,
        contact_rename,
        contact_block,
        contact_mark_verified,
        contact_acknowledge_key_change,
        contact_answer_request,
        session_connect,
        session_get,
        session_close,
        chat_send,
        pump_once,
        file_send,
    ]
}
