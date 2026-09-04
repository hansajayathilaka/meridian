//! Tauri command layer for `meridian-desktop` (task 12.3).
//!
//! ## Naming convention (established here; 12.6/12.15/12.16 should follow it)
//! - **Commands** are `snake_case`, prefixed by the `core-api-contracts.md` domain they marshal:
//!   `account_*` (identity lifecycle — `generate_account`/`parse_id`), `contact_*` (trust/contacts
//!   — `trust_state`/`mark_verified`), `session_*` (P2P session lifecycle — `open_session`),
//!   `chat_*` (messaging over an already-established session — `send_chat`), `file_*` (`mrd.file/1`
//!   transfers, the T09 stream type). Where a command corresponds directly to a
//!   `core-api-contracts.md` free function, its name echoes that function's own name
//!   (`chat_send` ~ `send_chat`, `contact_mark_verified` ~ `mark_verified`).
//! - **Events** pushed to the frontend are `domain:event`, colon-namespaced (the Tauri v2
//!   convention): `account:changed`, `chat:message`, `chat:receipt`, `chat:message_request`,
//!   `session:connected`, `session:stream_opened`, `session:closed`, `file:incoming`,
//!   `file:progress`, `file:received`, `file:failed`. Each payload is the JSON form of the
//!   `Serialize` DTO defined in this file with the matching name (`ChatEvent`, `IncomingFile`, …).
//!
//! ## Security invariant (this task's own named risk)
//! Every command return type and every event payload in this file is one of
//! `core-api-contracts.md`'s own **result** shapes — a message id, a contact/session view, a
//! safety number, a file manifest summary — never a `SecretStore`/ratchet/session key, never a raw
//! seed. Nothing in this file ever constructs a `#[derive(Serialize)]` struct that holds a
//! `Zeroizing<_>`, a raw `[u8; 32]` key, or any `SecretStore`/`KeyHandle` internals; grep this file
//! for `Zeroizing`/`k_f` when extending it — those types must never appear inside a type reachable
//! from `#[tauri::command]`'s return value or an `EventSink::emit` payload. Key material only ever
//! flows between `meridian-core` and the OS keystore in-process (ADR 0010) — this mirrors the
//! discipline `apps/cli` already follows (key material only ever surfaces via explicit,
//! deliberately-named export paths, never as an ordinary command/query result).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use meridian_core::account::AccountDescriptor;
use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, parse_id, KeyHandle, SecretStore};
use meridian_core::session::{answer, dial, P2pSession, SessionError, SessionEvent, SignalRelay};
use meridian_core::streams::{register_stream_type, StreamId, StreamRegistry};
use meridian_core::transport::Transport;
use meridian_core::trust::{Contact, SendGate, TrustState, TrustStore};
use meridian_streams::{
    open_chunk, send_file as streams_send_file, ChunkFrame, FileManifest, FileMeta, FileSend,
    FileStream, Hash, MerkleTree, SenderConfig, CHUNK_SIZE,
};

/// The OS keystore service name for `OsSecretStore` — mirrors `apps/cli/src/main.rs`'s
/// `OS_KEYSTORE_SERVICE` exactly (same keystore, so an account created in the CLI is reachable
/// from the desktop app and vice versa).
pub const OS_KEYSTORE_SERVICE: &str = "meridian";

/// A synthetic opening chat message `file_send` sends once per peer, only when needed, purely to
/// clear `PolicyCtx::first_contact` on the responder's side before this side's first
/// `mrd.file/1` OPEN — mirrors `apps/cli/src/send.rs::HELLO` exactly (see that module's doc for
/// the full reasoning). `TODO: confirm` with design (12.15): today this is delivered — and
/// surfaced to the frontend — as an ordinary `ChatContent::Text`/`chat:message` event; a
/// dedicated non-content "session opened" signal would be a wire-level change out of this task's
/// scope, so 12.15's UI may want to special-case this exact literal string rather than render it.
const FILE_OPEN_HELLO: &str = "(opening a file-transfer session)";

// ---------------------------------------------------------------------------
// Event sink — decouples emitting from a live `tauri::AppHandle` so the command layer is testable
// without a WebView/window (deliverable 5).
// ---------------------------------------------------------------------------

/// Where this crate's background work (the per-session pump loop, file-transfer progress) pushes
/// events for the frontend. Implemented for real by [`TauriEventSink`]; tests use
/// [`RecordingEventSink`] to assert on exactly what would have been emitted.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

/// Production [`EventSink`]: wraps a live `tauri::AppHandle` and forwards to `app.emit`. A failed
/// emit (e.g. no window ever subscribed) is not itself an error this crate's callers should have
/// to handle — mirrors every other best-effort notification in this codebase (e.g.
/// `apps/cli/src/chat.rs`'s `route_tolerant`'s own `let _ = …` sends).
pub struct TauriEventSink(pub tauri::AppHandle);

impl EventSink for TauriEventSink {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        use tauri::Emitter;
        let _ = self.0.emit(event, payload);
    }
}

/// Test-only [`EventSink`]: records every emitted `(event, payload)` pair in order, so a test can
/// assert the command layer actually pushed the events it claims to (deliverable 5's "confirm the
/// command layer correctly marshals requests/results"). `#[cfg(test)]`: nothing outside this
/// crate's own test module constructs one — production always uses [`TauriEventSink`].
#[cfg(test)]
#[derive(Default)]
pub struct RecordingEventSink(pub StdMutex<Vec<(String, serde_json::Value)>>);

#[cfg(test)]
impl EventSink for RecordingEventSink {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((event.to_string(), payload));
    }
}

// ---------------------------------------------------------------------------
// Result / event DTOs — see this module's doc comment on why every field here is a `core-api-
// contracts.md` *result* shape, never key material.
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub id: String,
    pub pubkey_hex: String,
    pub hint: String,
}

impl AccountView {
    fn from_descriptor(d: &AccountDescriptor) -> Result<Self, String> {
        Ok(Self {
            id: d.id_string()?,
            pubkey_hex: d.pubkey.clone(),
            hint: d.hint.clone(),
        })
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ContactView {
    pub id: String,
    pub pubkey_hex: String,
    pub petname: Option<String>,
    pub hint: String,
    pub state: String,
    pub user_blocked: bool,
}

impl ContactView {
    fn from_contact(c: &Contact) -> Result<Self, String> {
        Ok(Self {
            id: c.id_string().map_err(|e| e.to_string())?,
            pubkey_hex: hex::encode(c.pubkey),
            petname: c.petname.clone(),
            hint: c.hint.clone(),
            state: trust_state_str(c.state).to_string(),
            user_blocked: c.user_blocked,
        })
    }
}

/// Mirrors `apps/cli/src/contact.rs::state_str` exactly.
fn trust_state_str(state: TrustState) -> &'static str {
    match state {
        TrustState::New => "new",
        TrustState::Pinned => "pinned",
        TrustState::Verified => "verified",
        TrustState::Blocked => "blocked (key change)",
        TrustState::PinnedKeyChanged => "warn (key change)",
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    pub peer_pubkey_hex: String,
    pub transport: &'static str,
    pub path: String,
    pub streams: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SentMessage {
    pub id_hex: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ChatEvent {
    Message {
        peer_pubkey_hex: String,
        id_hex: String,
        body: String,
    },
    Receipt {
        peer_pubkey_hex: String,
        ack_hex: String,
    },
    MessageRequest {
        peer_pubkey_hex: String,
        safety_number: String,
    },
    StreamOpened {
        peer_pubkey_hex: String,
        sid: u64,
        stream_type: String,
    },
    StreamClosed {
        peer_pubkey_hex: String,
        sid: u64,
    },
    Closed {
        peer_pubkey_hex: String,
    },
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct IncomingFile {
    pub peer_pubkey_hex: String,
    pub name: String,
    pub size: u64,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FileSentResult {
    pub name: String,
    pub root_hex: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FileReceived {
    pub peer_pubkey_hex: String,
    pub name: String,
    pub root_hex: String,
    pub path: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FileFailed {
    pub peer_pubkey_hex: String,
    pub name: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Desktop state — generic over `Transport` so this crate's own tests can drive the exact same
// command logic against `LoopbackTransport` (deliverable 5) while production wires
// `meridian_core::transport::WebRtcTransport` (see `main.rs`).
// ---------------------------------------------------------------------------

/// One tracked inbound (not-yet-finalized) `mrd.file/1` transfer's unsealed per-file key.
type TransferKey = Zeroizing<[u8; 32]>;

pub struct DesktopState<T: Transport> {
    store: Box<dyn SecretStore>,
    transport: Arc<T>,
    events: Arc<dyn EventSink>,
    registry: Arc<StreamRegistry>,
    file_stream: Arc<FileStream>,
    download_dir: PathBuf,

    account: StdMutex<Option<AccountDescriptor>>,
    handle: StdMutex<Option<KeyHandle>>,
    /// The `@domain` hint last observed for a peer id string handed to any command
    /// (`parse_peer`'s side effect) — used only where a hint is needed for local bookkeeping
    /// (`TrustStore::observe`'s advisory `hint` parameter on message-request accept); never used
    /// as, or promoted to, a petname (see `apps/cli/src/contact.rs`'s identical invariant).
    peer_hints: StdMutex<HashMap<[u8; 32], String>>,

    chat: AsyncMutex<ChatState>,
    chat_loaded: StdMutex<bool>,
    trust: AsyncMutex<TrustStore>,
    trust_loaded: StdMutex<bool>,

    sessions: AsyncMutex<HashMap<[u8; 32], P2pSession<T>>>,
    /// Unsealed `k_f` for every inbound transfer this side has accepted and is still tracking,
    /// keyed by `(peer, sid)`. Removed once the transfer finalizes (written or definitively
    /// failed) — see `check_incoming_transfers`.
    transfers: AsyncMutex<HashMap<([u8; 32], StreamId), TransferKey>>,
    /// Peers this side has confirmed at least one `mrd.chat/1` content frame has flowed with,
    /// sent or received, over the current `P2pSession` — see `file_send`'s doc for why this
    /// gates whether it must send `FILE_OPEN_HELLO` first.
    content_opened: AsyncMutex<std::collections::HashSet<[u8; 32]>>,
}

impl<T: Transport> DesktopState<T> {
    pub fn new(
        store: Box<dyn SecretStore>,
        transport: Arc<T>,
        events: Arc<dyn EventSink>,
        download_dir: PathBuf,
    ) -> Self {
        // Safe-by-default policy (task 12.3 scope: no window UI, so no synchronous accept/reject
        // prompt exists yet — that seam is `FileStream::with_ask_user`, wired by 12.15): auto-
        // accept only small images from an already-established contact, decline everything else
        // until a real UI hook lands. Mirrors `meridian_streams::FileStream::new`'s own documented
        // default.
        let file_stream = Arc::new(FileStream::new(
            meridian_streams::DEFAULT_AUTO_ACCEPT_IMAGE_MAX_BYTES,
        ));
        Self::with_file_stream(store, transport, events, download_dir, file_stream)
    }

    /// Like [`new`](Self::new), but with a caller-supplied `FileStream` accept/reject policy —
    /// the seam a real UI hook (12.15) or this crate's own tests (exercising the accept path with
    /// `FileStream::with_ask_user(0, |_, _| true)`, mirroring `apps/cli/src/send.rs`'s identical
    /// test precedent) swap in instead of the safe-decline-by-default `new`.
    pub fn with_file_stream(
        store: Box<dyn SecretStore>,
        transport: Arc<T>,
        events: Arc<dyn EventSink>,
        download_dir: PathBuf,
        file_stream: Arc<FileStream>,
    ) -> Self {
        let mut registry = StreamRegistry::with_builtins();
        register_stream_type(&mut registry, file_stream.clone());
        Self {
            store,
            transport,
            events,
            registry: Arc::new(registry),
            file_stream,
            download_dir,
            account: StdMutex::new(None),
            handle: StdMutex::new(None),
            peer_hints: StdMutex::new(HashMap::new()),
            chat: AsyncMutex::new(ChatState::default()),
            chat_loaded: StdMutex::new(false),
            trust: AsyncMutex::new(TrustStore::default()),
            trust_loaded: StdMutex::new(false),
            sessions: AsyncMutex::new(HashMap::new()),
            transfers: AsyncMutex::new(HashMap::new()),
            content_opened: AsyncMutex::new(std::collections::HashSet::new()),
        }
    }

    fn emit(&self, event: &str, payload: impl Serialize) {
        self.events.emit(
            event,
            serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        );
    }

    fn require_account(&self) -> Result<([u8; 32], KeyHandle), String> {
        let account = self.account.lock().unwrap_or_else(|e| e.into_inner());
        let handle = self.handle.lock().unwrap_or_else(|e| e.into_inner());
        match (&*account, &*handle) {
            (Some(descriptor), Some(handle)) => {
                let raw = hex::decode(&descriptor.pubkey).map_err(|_| {
                    "corrupt account descriptor: pubkey is not valid hex".to_string()
                })?;
                let pk: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    "corrupt account descriptor: pubkey is not 32 bytes".to_string()
                })?;
                Ok((pk, handle.clone()))
            }
            _ => Err("no account loaded — call account_create or account_load first".to_string()),
        }
    }

    fn parse_peer(&self, id: &str) -> Result<[u8; 32], String> {
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pk = *identity.pubkey();
        self.peer_hints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pk, identity.hint().to_string());
        Ok(pk)
    }

    fn hint_for(&self, peer_ik: &[u8; 32]) -> String {
        self.peer_hints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_ik)
            .cloned()
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------
    // Account lifecycle
    // -----------------------------------------------------------------

    /// `account_create` ~ `generate_account` (core-api-contracts.md).
    pub fn account_create(&self, hint: &str) -> Result<AccountView, String> {
        let account = generate_account(self.store.as_ref(), hint).map_err(|e| e.to_string())?;
        let descriptor = AccountDescriptor::new_os(&account, OS_KEYSTORE_SERVICE);
        descriptor.save()?;
        let handle = KeyHandle::from_label(&descriptor.label);
        let view = AccountView::from_descriptor(&descriptor)?;
        *self.account.lock().unwrap_or_else(|e| e.into_inner()) = Some(descriptor);
        *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        self.emit("account:changed", &view);
        Ok(view)
    }

    /// Loads a previously-created account descriptor from `$MERIDIAN_HOME` (idempotent — a no-op
    /// once an account is already loaded/created this session). Returns `Ok(None)` rather than an
    /// error when no account exists yet, so a fresh install's first-launch check is a plain
    /// `Option`, not an error path.
    pub fn account_load(&self) -> Result<Option<AccountView>, String> {
        if let Some(view) = self.account_get() {
            return Ok(Some(view));
        }
        match AccountDescriptor::load() {
            Ok(descriptor) => {
                let handle = KeyHandle::from_label(&descriptor.label);
                let view = AccountView::from_descriptor(&descriptor)?;
                *self.account.lock().unwrap_or_else(|e| e.into_inner()) = Some(descriptor);
                *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
                Ok(Some(view))
            }
            Err(_) => Ok(None),
        }
    }

    /// `account_get` ~ reading the currently-loaded identity (no direct `core-api-contracts.md`
    /// counterpart — a query, not a mutating operation).
    pub fn account_get(&self) -> Option<AccountView> {
        self.account
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(|d| AccountView::from_descriptor(d).ok())
    }

    // -----------------------------------------------------------------
    // Contacts / trust
    // -----------------------------------------------------------------

    async fn ensure_trust_loaded(&self) -> Result<(), String> {
        if *self.trust_loaded.lock().unwrap_or_else(|e| e.into_inner()) {
            return Ok(());
        }
        let (_, handle) = self.require_account()?;
        let path = meridian_core::account::trust_path()?;
        let loaded = match std::fs::read(&path) {
            Ok(sealed) => TrustStore::open_at_rest(self.store.as_ref(), &handle, &sealed)
                .map_err(|e| format!("opening trust store {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrustStore::default(),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        *self.trust.lock().await = loaded;
        *self.trust_loaded.lock().unwrap_or_else(|e| e.into_inner()) = true;
        Ok(())
    }

    async fn save_trust(&self) -> Result<(), String> {
        let (_, handle) = self.require_account()?;
        let path = meridian_core::account::trust_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        let trust = self.trust.lock().await;
        let sealed = trust
            .seal_at_rest(self.store.as_ref(), &handle)
            .map_err(|e| format!("sealing trust store: {e}"))?;
        std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
    }

    /// `contact_add` — TOFU-pins `id` (mirrors `apps/cli/src/contact.rs::cmd_add`'s
    /// `TrustStore::observe` call) and, only from the caller-supplied `petname` (never derived
    /// from `id`/the wire — the petname-never-from-wire invariant), assigns a local display name.
    pub async fn contact_add(
        &self,
        id: &str,
        petname: Option<String>,
    ) -> Result<ContactView, String> {
        self.ensure_trust_loaded().await?;
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pubkey = *identity.pubkey();
        self.peer_hints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pubkey, identity.hint().to_string());
        {
            let mut trust = self.trust.lock().await;
            trust.observe(pubkey, identity.hint(), now_unix());
            if let Some(name) = petname {
                trust
                    .set_petname(&pubkey, Some(name))
                    .map_err(|e| e.to_string())?;
            }
        }
        self.save_trust().await?;
        let view = self.contact_view(&pubkey).await?;
        self.emit("contact:changed", &view);
        Ok(view)
    }

    /// `contact_list`.
    pub async fn contact_list(&self) -> Result<Vec<ContactView>, String> {
        self.ensure_trust_loaded().await?;
        let trust = self.trust.lock().await;
        trust.contacts().map(ContactView::from_contact).collect()
    }

    /// `contact_rename` — an empty `petname` clears it (mirrors `TrustStore::set_petname`'s
    /// `None`/empty-string equivalence, `apps/cli/src/contact.rs::cmd_rename`).
    pub async fn contact_rename(&self, id: &str, petname: &str) -> Result<ContactView, String> {
        self.ensure_trust_loaded().await?;
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pubkey = *identity.pubkey();
        let value = if petname.is_empty() {
            None
        } else {
            Some(petname.to_string())
        };
        {
            let mut trust = self.trust.lock().await;
            trust
                .set_petname(&pubkey, value)
                .map_err(|e| e.to_string())?;
        }
        self.save_trust().await?;
        let view = self.contact_view(&pubkey).await?;
        self.emit("contact:changed", &view);
        Ok(view)
    }

    /// `contact_block` — a purely local, user-initiated block (`Contact::user_blocked`),
    /// independent of the key-change `TrustState::Blocked` `meridian_core::trust` already
    /// enforces. Mirrors `apps/cli/src/contact.rs::cmd_block`.
    pub async fn contact_block(&self, id: &str, blocked: bool) -> Result<ContactView, String> {
        self.ensure_trust_loaded().await?;
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pubkey = *identity.pubkey();
        {
            let mut trust = self.trust.lock().await;
            trust
                .set_user_blocked(&pubkey, blocked)
                .map_err(|e| e.to_string())?;
        }
        self.save_trust().await?;
        let view = self.contact_view(&pubkey).await?;
        self.emit("contact:changed", &view);
        Ok(view)
    }

    /// `contact_mark_verified` ~ `mark_verified` (core-api-contracts.md) — call only after an
    /// out-of-band safety-number compare confirms a match; this command itself performs no
    /// comparison (the safety number is `session_view`'s job to surface for display).
    pub async fn contact_mark_verified(&self, id: &str) -> Result<ContactView, String> {
        self.ensure_trust_loaded().await?;
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pubkey = *identity.pubkey();
        {
            let mut trust = self.trust.lock().await;
            trust.mark_verified(&pubkey).map_err(|e| e.to_string())?;
        }
        self.save_trust().await?;
        let view = self.contact_view(&pubkey).await?;
        self.emit("contact:changed", &view);
        Ok(view)
    }

    /// `contact_acknowledge_key_change` ~ `TrustStore::acknowledge_key_change` — re-pins a
    /// **pinned** (TOFU) contact's new key without a safety-number compare, exactly as
    /// `docs/security/verification-ux.md` specifies; has no effect on (and does not clear) a
    /// **verified** contact's hard `Blocked` state — see `TrustError::NotAcknowledgeable`.
    pub async fn contact_acknowledge_key_change(&self, id: &str) -> Result<ContactView, String> {
        self.ensure_trust_loaded().await?;
        let identity = parse_id(id).map_err(|e| e.to_string())?;
        let pubkey = *identity.pubkey();
        {
            let mut trust = self.trust.lock().await;
            trust
                .acknowledge_key_change(&pubkey)
                .map_err(|e| e.to_string())?;
        }
        self.save_trust().await?;
        let view = self.contact_view(&pubkey).await?;
        self.emit("contact:changed", &view);
        Ok(view)
    }

    async fn contact_view(&self, pubkey: &[u8; 32]) -> Result<ContactView, String> {
        let trust = self.trust.lock().await;
        let contact = trust
            .contact(pubkey)
            .ok_or("no contact recorded for this key")?;
        ContactView::from_contact(contact)
    }

    // -----------------------------------------------------------------
    // Session lifecycle (P2P, T04) — `session_dial`/`session_answer` are the directly-testable
    // core; the production `#[tauri::command]` wrapper in `tauri_commands.rs` supplies a
    // `RendezvousRelay` built from a live `SignalingClient`, while this crate's own tests supply a
    // `MemRelay` pair (mirrors `apps/cli/src/send.rs`'s test harness exactly).
    // -----------------------------------------------------------------

    async fn ensure_chat_loaded(&self) -> Result<(), String> {
        if *self.chat_loaded.lock().unwrap_or_else(|e| e.into_inner()) {
            return Ok(());
        }
        let (_, handle) = self.require_account()?;
        let path = meridian_core::account::sessions_path()?;
        let loaded = match std::fs::read(&path) {
            Ok(sealed) => ChatState::open_at_rest(self.store.as_ref(), &handle, &sealed)
                .map_err(|e| format!("opening chat/session store {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChatState::default(),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        *self.chat.lock().await = loaded;
        *self.chat_loaded.lock().unwrap_or_else(|e| e.into_inner()) = true;
        Ok(())
    }

    async fn save_chat(&self) -> Result<(), String> {
        let (_, handle) = self.require_account()?;
        let path = meridian_core::account::sessions_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        let chat = self.chat.lock().await;
        let sealed = chat
            .seal_at_rest(self.store.as_ref(), &handle)
            .map_err(|e| format!("sealing chat/session store: {e}"))?;
        std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
    }

    /// Establish a P2P session as the dialer. `chat`'s X3DH session with `peer_ik` must already
    /// exist (`meridian_core::session::dial`'s own precondition) — the production caller fetches
    /// the peer's bundle over `relay`'s underlying `SignalingClient` and calls
    /// `ChatState::start_initiator_session` first; this crate's own tests do the equivalent via
    /// `meridian_core::signaling::generate_bundle` directly (no network).
    pub async fn session_dial(
        &self,
        relay: &mut dyn SignalRelay,
        peer_ik: [u8; 32],
    ) -> Result<SessionView, String> {
        self.ensure_chat_loaded().await?;
        let (our_ik, handle) = self.require_account()?;
        let mut chat = self.chat.lock().await;
        let mut session = dial(
            self.transport.clone(),
            self.store.as_ref(),
            &handle,
            our_ik,
            peer_ik,
            &mut chat,
            relay,
            self.registry.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut view = session_view(&mut session).await;
        view.peer_pubkey_hex = hex::encode(peer_ik);
        drop(chat);
        self.sessions.lock().await.insert(peer_ik, session);
        self.save_chat().await?;
        self.emit("session:connected", &view);
        Ok(view)
    }

    /// Establish a P2P session as the answerer (the responder's first content frame from an
    /// unrecognized peer lands as a `ChatEvent::MessageRequest` on the next `pump_once`/background
    /// pump — never auto-delivered; see `contact_answer_request`).
    pub async fn session_answer(
        &self,
        relay: &mut dyn SignalRelay,
        peer_ik: [u8; 32],
    ) -> Result<SessionView, String> {
        self.ensure_chat_loaded().await?;
        let (our_ik, handle) = self.require_account()?;
        let mut chat = self.chat.lock().await;
        let mut session = answer(
            self.transport.clone(),
            self.store.as_ref(),
            &handle,
            our_ik,
            peer_ik,
            &mut chat,
            relay,
            self.registry.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut view = session_view(&mut session).await;
        view.peer_pubkey_hex = hex::encode(peer_ik);
        drop(chat);
        self.sessions.lock().await.insert(peer_ik, session);
        self.save_chat().await?;
        self.emit("session:connected", &view);
        Ok(view)
    }

    /// `session_connect` — the production, network-backed counterpart to `session_dial`/
    /// `session_answer`: connects to `server`'s signaling, publishes a fresh prekey bundle,
    /// decides the dial/answer role by identity-key order (mirrors
    /// `apps/cli/src/session_connect.rs` exactly), fetches + X3DHs against the peer's bundle if
    /// initiating, and dials/answers over `self.transport` before dropping the signaling
    /// connection (T04's "servers out of the data path" property). Not covered by this crate's own
    /// unit tests (deliberately — it needs a live rendezvous server; that path is already covered
    /// by `apps/cli/tests/session_connect*.rs` and `apps/rendezvous`'s own test suite). Generic
    /// over `T` at the type level like every other method here, but only meaningful with a real
    /// cross-process transport (`WebRtcTransport`) — see `tauri_commands::require_webrtc`, which
    /// gates the production command wrapper.
    pub async fn session_connect(
        &self,
        peer_id: &str,
        server: &str,
    ) -> Result<SessionView, String> {
        use meridian_core::signal_relay::RendezvousRelay;
        use meridian_core::signaling::{SignalError, SignalingClient, DEFAULT_OTK_COUNT};

        let peer_ik = self.parse_peer(peer_id)?;
        let peer_hint = self.hint_for(&peer_ik);
        let (our_ik, handle) = self.require_account()?;
        self.ensure_chat_loaded().await?;

        let mut client =
            SignalingClient::connect(server, self.store.as_ref(), &handle, our_ik, None, 1)
                .await
                .map_err(|e| format!("connecting to {server}: {e}"))?;

        let generated = client
            .publish_bundle(self.store.as_ref(), &handle, DEFAULT_OTK_COUNT)
            .await
            .map_err(|e| format!("publishing bundle: {e}"))?;
        let otks: Vec<([u8; 32], [u8; 32])> = generated
            .bundle
            .otks
            .iter()
            .zip(generated.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        {
            let mut chat = self.chat.lock().await;
            chat.vault.set_bundle(
                generated.bundle.spk,
                *generated.spk_secret,
                otks,
                now_unix(),
            );
        }

        let initiator = our_ik.as_slice() <= peer_ik.as_slice();
        if initiator && !self.chat.lock().await.has_session(&peer_ik) {
            let mut stale_hint_err: Option<String> = None;
            let mut bundle = None;
            for attempt in 0..40u32 {
                match client
                    .fetch_bundle(peer_ik, Some(peer_hint.clone()), false)
                    .await
                {
                    Ok(b) => {
                        bundle = Some(b);
                        break;
                    }
                    Err(SignalError::Server(e)) if e.code == "not_found" => {
                        stale_hint_err =
                            Some(format!("{peer_id} did not publish a bundle in time"));
                        if attempt < 39 {
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        }
                    }
                    Err(SignalError::NotFoundAtHint { hint, detail }) => {
                        stale_hint_err = Some(format!(
                            "{peer_id} unreachable at hint {hint}: no account found there ({detail}) \
                             — the hint may be stale"
                        ));
                        if attempt < 39 {
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        }
                    }
                    Err(e) => return Err(format!("fetching {peer_id}: {e}")),
                }
            }
            let bundle = bundle.ok_or_else(|| {
                stale_hint_err.unwrap_or_else(|| "bundle fetch failed".to_string())
            })?;
            let mut chat = self.chat.lock().await;
            chat.start_initiator_session(
                self.store.as_ref(),
                &handle,
                &our_ik,
                &peer_ik,
                &bundle.spk,
                bundle.otks.first().copied(),
            )
            .map_err(|e| format!("establishing session: {e}"))?;
        }

        let view = {
            let mut relay = RendezvousRelay::new(&mut client, Some(peer_hint));
            if initiator {
                self.session_dial(&mut relay, peer_ik).await?
            } else {
                self.session_answer(&mut relay, peer_ik).await?
            }
        };

        // T04's "servers out of the data path" property — the rendezvous connection is no longer
        // needed once the P2P session is up (mirrors `apps/cli/src/session_connect.rs`).
        let _ = client.close().await;
        Ok(view)
    }

    /// A snapshot of a currently-open session with `peer_id`, or `None` if there is none.
    pub async fn session_get(&self, peer_id: &str) -> Result<Option<SessionView>, String> {
        let peer_ik = self.parse_peer(peer_id)?;
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&peer_ik) else {
            return Ok(None);
        };
        let mut view = session_view(session).await;
        view.peer_pubkey_hex = hex::encode(peer_ik);
        Ok(Some(view))
    }

    pub async fn session_close(&self, peer_id: &str) -> Result<(), String> {
        let peer_ik = self.parse_peer(peer_id)?;
        let mut sessions = self.sessions.lock().await;
        if let Some(mut session) = sessions.remove(&peer_ik) {
            let _ = session.close().await;
            self.emit(
                "session:closed",
                ChatEvent::Closed {
                    peer_pubkey_hex: hex::encode(peer_ik),
                },
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Chat send/receive (T03/T04)
    // -----------------------------------------------------------------

    /// `chat_send` ~ `send_chat` (core-api-contracts.md). Gated by `TrustStore::can_send` exactly
    /// like `apps/cli/src/chat.rs::send_gated` — a verified contact's key change hard-blocks the
    /// send (no bypass), a pinned contact's key change must be acknowledged first
    /// (`contact_acknowledge_key_change`).
    pub async fn chat_send(&self, peer_id: &str, text: &str) -> Result<SentMessage, String> {
        let peer_ik = self.parse_peer(peer_id)?;
        let (_, handle) = self.require_account()?;
        self.ensure_trust_loaded().await?;
        {
            let trust = self.trust.lock().await;
            match trust.can_send(&peer_ik) {
                SendGate::Ok => {}
                SendGate::Blocked(reason) => return Err(format!("blocked: {reason}")),
                SendGate::Warn(reason) => {
                    return Err(format!(
                        "{reason} — call contact_acknowledge_key_change first, or \
                         contact_mark_verified after an out-of-band compare"
                    ))
                }
            }
        }
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(&peer_ik).ok_or_else(|| {
            "no active P2P session with this peer — call session_dial/session_answer first"
                .to_string()
        })?;
        let mut chat = self.chat.lock().await;
        let id = session
            .send_chat(self.store.as_ref(), &handle, &mut chat, text)
            .await
            .map_err(|e| e.to_string())?;
        drop(chat);
        drop(sessions);
        self.content_opened.lock().await.insert(peer_ik);
        self.save_chat().await?;
        Ok(SentMessage {
            id_hex: hex::encode(id),
        })
    }

    /// Answer a pending first-contact message request (task 2.10/2.14's gate, surfaced by
    /// `pump_once` as `ChatEvent::MessageRequest`). Accepting TOFU-pins the sender (mirrors
    /// `apps/cli/src/chat.rs::answer_request`'s `TrustStore::observe` call) and returns the held
    /// intro as a `ChatEvent::Message`/`ChatEvent::Receipt`; rejecting is silent (no trace left in
    /// `trust`), matching `ChatState::reject_request`'s documented security property.
    pub async fn contact_answer_request(
        &self,
        peer_id: &str,
        accept: bool,
    ) -> Result<Option<ChatEvent>, String> {
        let peer_ik = self.parse_peer(peer_id)?;
        self.ensure_trust_loaded().await?;
        let mut chat = self.chat.lock().await;
        if accept {
            let req = chat
                .accept_request(&peer_ik)
                .ok_or_else(|| "no pending message request for this contact".to_string())?;
            drop(chat);
            let hint = self.hint_for(&peer_ik);
            {
                let mut trust = self.trust.lock().await;
                trust.observe(peer_ik, &hint, now_unix());
            }
            self.save_trust().await?;
            self.save_chat().await?;
            let event = content_to_event(peer_ik, req.intro);
            self.emit(event_name(&event), &event);
            Ok(Some(event))
        } else {
            chat.reject_request(&peer_ik);
            drop(chat);
            self.save_chat().await?;
            Ok(None)
        }
    }

    /// Service exactly one inbound event on `peer_id`'s session — the directly-testable core of
    /// the background pump loop `main.rs` spawns per connected session in production. Returns
    /// `Ok(None)` for an event with nothing to surface (a keepalive, or a raw stream frame that
    /// only updated a tracked file transfer's progress — see `check_incoming_transfers`).
    pub async fn pump_once(&self, peer_id: &str) -> Result<Option<ChatEvent>, String> {
        let peer_ik = self.parse_peer(peer_id)?;
        let (_, handle) = self.require_account()?;
        if !self.sessions.lock().await.contains_key(&peer_ik) {
            return Err("no active P2P session with this peer".to_string());
        }
        match self.pump_raw(peer_ik, &handle).await {
            Ok(event) => {
                let mapped = self.handle_session_event(peer_ik, event).await;
                self.check_incoming_transfers(peer_ik).await;
                if mapped.is_some() {
                    let _ = self.save_chat().await;
                }
                Ok(mapped)
            }
            Err(SessionError::Chat(ChatError::MessageRequest)) => {
                let chat = self.chat.lock().await;
                let req = chat
                    .pending_request(&peer_ik)
                    .expect("ChatError::MessageRequest just inserted this request");
                let event = ChatEvent::MessageRequest {
                    peer_pubkey_hex: hex::encode(peer_ik),
                    safety_number: req.safety_number.clone(),
                };
                drop(chat);
                // A content frame reached this side — `P2pSession::pump` already cleared its own
                // internal `chat_first_contact_gate` the moment this fired (see that method's
                // `CHAT_LABEL` arm), whether the request is later accepted or rejected.
                self.content_opened.lock().await.insert(peer_ik);
                self.emit(event_name(&event), &event);
                Ok(Some(event))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The raw `P2pSession::pump` call — never surfaced directly to a Tauri command; used by
    /// `pump_once` and by `file_send`'s own accept/reject wait loop, which needs the un-mapped
    /// `SessionEvent`/`SessionError` to detect exactly its own stream id's `Accept`/`Reject`.
    async fn pump_raw(
        &self,
        peer_ik: [u8; 32],
        handle: &KeyHandle,
    ) -> Result<Option<SessionEvent>, SessionError> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&peer_ik)
            .expect("caller already verified an active session exists for this peer");
        let mut chat = self.chat.lock().await;
        session.pump(self.store.as_ref(), handle, &mut chat).await
    }

    /// Maps a raw `SessionEvent` to this crate's `ChatEvent` DTO, performing the matching side
    /// effect (tracking a new inbound file transfer, dropping a closed session) and emitting.
    async fn handle_session_event(
        &self,
        peer_ik: [u8; 32],
        event: Option<SessionEvent>,
    ) -> Option<ChatEvent> {
        let mapped = match event? {
            SessionEvent::Chat(content) => {
                self.content_opened.lock().await.insert(peer_ik);
                Some(content_to_event(peer_ik, content))
            }
            SessionEvent::Keepalive | SessionEvent::KeepaliveEcho(_) => None,
            SessionEvent::StreamOpened(sid, ty) => {
                if ty == meridian_streams::file::NAME {
                    if let Err(e) = self.track_incoming_file(peer_ik, sid).await {
                        self.emit(
                            "file:failed",
                            FileFailed {
                                peer_pubkey_hex: hex::encode(peer_ik),
                                name: String::new(),
                                reason: e,
                            },
                        );
                    }
                }
                Some(ChatEvent::StreamOpened {
                    peer_pubkey_hex: hex::encode(peer_ik),
                    sid,
                    stream_type: ty,
                })
            }
            SessionEvent::StreamClosed(sid) => Some(ChatEvent::StreamClosed {
                peer_pubkey_hex: hex::encode(peer_ik),
                sid,
            }),
            SessionEvent::Closed => {
                self.sessions.lock().await.remove(&peer_ik);
                Some(ChatEvent::Closed {
                    peer_pubkey_hex: hex::encode(peer_ik),
                })
            }
        };
        if let Some(event) = &mapped {
            self.emit(event_name(event), event);
        }
        mapped
    }

    // -----------------------------------------------------------------
    // File transfer (T09, `mrd.file/1`)
    // -----------------------------------------------------------------

    /// `file_send` ~ `open_stream` + the T09 sender engine (core-api-contracts.md's stream-
    /// registry extension point in action). Initiator-only, matching
    /// `apps/cli/src/send.rs`'s own recorded `TODO: confirm` on `P2pSession` having no split
    /// reader/writer half (see that module's doc for the full reasoning) — a future task giving
    /// `P2pSession` a real split would remove this restriction on both clients.
    pub async fn file_send(&self, peer_id: &str, path: &Path) -> Result<FileSentResult, String> {
        let peer_ik = self.parse_peer(peer_id)?;
        let (our_ik, handle) = self.require_account()?;
        if !self.sessions.lock().await.contains_key(&peer_ik) {
            return Err(
                "no active P2P session with this peer — call session_dial/session_answer first"
                    .to_string(),
            );
        }

        // A stranger's first `mrd.file/1` OPEN is always rejected outright by
        // `decide_file_offer`, regardless of file type/size (`PolicyCtx::first_contact`) — and a
        // freshly dialed/answered `P2pSession` starts with exactly that flag set on the
        // responder's side until *any* chat content frame has been pumped there (see
        // `meridian_core::session::P2pSession`'s `chat_first_contact_gate` doc). Send one first,
        // exactly once per peer, mirroring `apps/cli/src/send.rs`'s identical `HELLO` precedent.
        if !self.content_opened.lock().await.contains(&peer_ik) {
            let mut chat = self.chat.lock().await;
            let mut sessions = self.sessions.lock().await;
            let session = sessions
                .get_mut(&peer_ik)
                .expect("checked above that a session exists for this peer");
            session
                .send_chat(self.store.as_ref(), &handle, &mut chat, FILE_OPEN_HELLO)
                .await
                .map_err(|e| e.to_string())?;
            drop(sessions);
            drop(chat);
            self.content_opened.lock().await.insert(peer_ik);
        }

        let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| path.display().to_string());
        let root: Hash = MerkleTree::from_bytes(&data).root();

        let (sid, k_f) = {
            let mut chat = self.chat.lock().await;
            let (params, k_f) = FileStream::build_open_params(
                &mut chat,
                self.store.as_ref(),
                &handle,
                &our_ik,
                &peer_ik,
                FileMeta {
                    name: name.clone(),
                    size: data.len() as u64,
                    root,
                },
            )
            .map_err(|e| e.to_string())?;
            let mut sessions = self.sessions.lock().await;
            let session = sessions
                .get_mut(&peer_ik)
                .expect("checked above that a session exists for this peer");
            let sid = session
                .open_stream(
                    self.store.as_ref(),
                    &handle,
                    &mut chat,
                    meridian_streams::file::NAME,
                    params,
                )
                .await
                .map_err(|e| format!("{name}: opening transfer: {e}"))?;
            (sid, k_f)
        };

        // Wait for the peer's Accept/Reject for exactly this sid, servicing anything else `pump`
        // surfaces along the way — mirrors `apps/cli/src/send.rs::run_initiator_inner`.
        loop {
            match self.pump_raw(peer_ik, &handle).await {
                Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
                Ok(event) => {
                    self.handle_session_event(peer_ik, event).await;
                }
                Err(SessionError::StreamRejected {
                    sid: rsid,
                    code,
                    reason,
                }) if rsid == sid => {
                    return Err(format!("{name}: declined ({code}: {reason})"));
                }
                Err(SessionError::Chat(ChatError::MessageRequest)) => {
                    let chat = self.chat.lock().await;
                    let req = chat
                        .pending_request(&peer_ik)
                        .expect("ChatError::MessageRequest just inserted this request");
                    let event = ChatEvent::MessageRequest {
                        peer_pubkey_hex: hex::encode(peer_ik),
                        safety_number: req.safety_number.clone(),
                    };
                    drop(chat);
                    self.emit(event_name(&event), &event);
                }
                Err(e) => return Err(format!("{name}: {e}")),
            }
        }

        let events = self.events.clone();
        let peer_hex = hex::encode(peer_ik);
        let name_for_progress = name.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<meridian_streams::SendProgress>();
        let forward = tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                events.emit(
                    "file:progress",
                    serde_json::json!({
                        "peer_pubkey_hex": peer_hex,
                        "name": name_for_progress,
                        "bytes_sent": p.bytes_sent,
                        "total_bytes": p.total_bytes,
                        "bytes_per_sec": p.bytes_per_sec,
                    }),
                );
            }
        });

        let result = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.get_mut(&peer_ik).expect(
                "session was open moments ago and this crate has no concurrent removal path",
            );
            let mut chat = self.chat.lock().await;
            streams_send_file(
                session,
                &mut chat,
                FileSend {
                    sid,
                    k_f: &k_f,
                    name: name.clone(),
                    data: &data,
                },
                &SenderConfig::default(),
                Some(&tx),
            )
            .await
        };
        drop(tx);
        let _ = forward.await;
        result.map_err(|e| format!("{name}: {e}"))?;

        Ok(FileSentResult {
            name,
            root_hex: hex::encode(root),
        })
    }

    async fn track_incoming_file(&self, peer_ik: [u8; 32], sid: StreamId) -> Result<(), String> {
        let (our_ik, handle) = self.require_account()?;
        let Some(transfer) = self.file_stream.transfer(sid) else {
            return Ok(());
        };
        let Some(manifest) = transfer.manifest else {
            return Ok(());
        };
        let k_f_bytes = {
            let mut chat = self.chat.lock().await;
            chat.open_bytes(
                self.store.as_ref(),
                &handle,
                &our_ik,
                &peer_ik,
                &manifest.key,
                false,
            )
            .map_err(|e| e.to_string())?
        };
        let k_f: [u8; 32] = k_f_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "unsealed transfer key has the wrong length".to_string())?;
        self.transfers
            .lock()
            .await
            .insert((peer_ik, sid), Zeroizing::new(k_f));
        self.emit(
            "file:incoming",
            IncomingFile {
                peer_pubkey_hex: hex::encode(peer_ik),
                name: manifest.name,
                size: manifest.size,
            },
        );
        Ok(())
    }

    /// Checks every tracked, not-yet-settled inbound transfer from `peer_ik` for completion
    /// (every chunk index `0..leaf_count` present), finalizing (verify + write to
    /// `self.download_dir`) or definitively failing it. Mirrors
    /// `apps/cli/src/send.rs::run_responder`'s identical completion check.
    async fn check_incoming_transfers(&self, peer_ik: [u8; 32]) {
        let sids: Vec<StreamId> = {
            let transfers = self.transfers.lock().await;
            transfers
                .keys()
                .filter(|(p, _)| *p == peer_ik)
                .map(|(_, s)| *s)
                .collect()
        };
        for sid in sids {
            let Some(k_f) = self.transfers.lock().await.get(&(peer_ik, sid)).cloned() else {
                continue;
            };
            let Some(transfer) = self.file_stream.transfer(sid) else {
                continue;
            };
            let Some(manifest) = transfer.manifest.clone() else {
                continue;
            };
            let leaf_count = leaf_count_for_size(manifest.size) as u64;
            if !(0..leaf_count).all(|i| transfer.pending_chunks.contains_key(&i)) {
                continue;
            }
            match finalize_transfer(
                &manifest,
                &k_f,
                &transfer.pending_chunks,
                &self.download_dir,
            ) {
                Ok(path) => {
                    self.transfers.lock().await.remove(&(peer_ik, sid));
                    self.emit(
                        "file:received",
                        FileReceived {
                            peer_pubkey_hex: hex::encode(peer_ik),
                            name: manifest.name,
                            root_hex: hex::encode(manifest.root),
                            path: path.display().to_string(),
                        },
                    );
                }
                Err(e) => {
                    self.transfers.lock().await.remove(&(peer_ik, sid));
                    self.emit(
                        "file:failed",
                        FileFailed {
                            peer_pubkey_hex: hex::encode(peer_ik),
                            name: manifest.name,
                            reason: e,
                        },
                    );
                }
            }
        }
    }
}

fn event_name(event: &ChatEvent) -> &'static str {
    match event {
        ChatEvent::Message { .. } => "chat:message",
        ChatEvent::Receipt { .. } => "chat:receipt",
        ChatEvent::MessageRequest { .. } => "chat:message_request",
        ChatEvent::StreamOpened { .. } => "session:stream_opened",
        ChatEvent::StreamClosed { .. } => "session:stream_closed",
        ChatEvent::Closed { .. } => "session:closed",
    }
}

fn content_to_event(peer_ik: [u8; 32], content: ChatContent) -> ChatEvent {
    match content {
        ChatContent::Text { id, body } => ChatEvent::Message {
            peer_pubkey_hex: hex::encode(peer_ik),
            id_hex: hex::encode(id),
            body,
        },
        ChatContent::Receipt { ack } => ChatEvent::Receipt {
            peer_pubkey_hex: hex::encode(peer_ik),
            ack_hex: hex::encode(ack),
        },
    }
}

async fn session_view<T: Transport>(session: &mut P2pSession<T>) -> SessionView {
    let (_, remote_hex) = {
        let (local, remote) = session.fingerprints();
        (local.clone(), remote.clone())
    };
    let _ = remote_hex; // fingerprints are not surfaced in the DTO today — display is 12.15's job.
    let info = session.info().await;
    SessionView {
        peer_pubkey_hex: String::new(), // filled in by the caller, which knows the peer key.
        transport: info.transport,
        path: info.path.to_string(),
        streams: info.streams,
    }
}

/// Wall-clock unix seconds — mirrors `apps/cli/src/main.rs::now_unix` exactly (same reasoning:
/// `meridian-core` stays clock-free for its wasm32 target; this is a native binary).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Number of [`CHUNK_SIZE`] leaves a file of `size` bytes was split into — mirrors
/// `apps/cli/src/send.rs::leaf_count_for_size` exactly.
fn leaf_count_for_size(size: u64) -> usize {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_SIZE as u64) as usize
    }
}

/// Reassembles a completed transfer's chunks, verifies the whole-file merkle root, and — only on
/// a match — writes it under `out_dir`. Mirrors `apps/cli/src/send.rs::finalize_transfer` (see
/// that function's doc for the out-of-range/overflow defense-in-depth reasoning), condensed.
fn finalize_transfer(
    manifest: &FileManifest,
    k_f: &[u8; 32],
    pending_chunks: &BTreeMap<u64, Vec<u8>>,
    out_dir: &Path,
) -> Result<PathBuf, String> {
    const MAX_TRANSFER_SIZE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    if manifest.size > MAX_TRANSFER_SIZE_BYTES {
        return Err(format!(
            "declared file size {} bytes exceeds the {MAX_TRANSFER_SIZE_BYTES} byte sanity cap",
            manifest.size
        ));
    }
    let leaf_count = leaf_count_for_size(manifest.size);
    let mut buf = vec![0u8; manifest.size as usize];
    for raw in pending_chunks.values() {
        let frame = ChunkFrame::decode(raw).map_err(|e| format!("malformed chunk frame: {e}"))?;
        if frame.i as usize >= leaf_count {
            continue;
        }
        let plaintext = open_chunk(k_f, frame.i, &frame.data)
            .map_err(|_| format!("chunk {} failed to authenticate", frame.i))?;
        let start = (frame.i as usize)
            .checked_mul(CHUNK_SIZE)
            .ok_or_else(|| format!("chunk {} offset overflow", frame.i))?;
        let end = start
            .checked_add(plaintext.len())
            .ok_or_else(|| format!("chunk {} index overflow", frame.i))?;
        if end > buf.len() {
            return Err(format!(
                "chunk {} overruns the file's declared size — not written",
                frame.i
            ));
        }
        buf[start..end].copy_from_slice(&plaintext);
    }

    let root = MerkleTree::from_bytes(&buf).root();
    if root != manifest.root {
        return Err(format!(
            "merkle root mismatch: expected b3:{}…, got b3:{}… — transfer corrupted, not written",
            hex::encode(&manifest.root[..2]),
            hex::encode(&root[..2]),
        ));
    }

    std::fs::create_dir_all(out_dir).map_err(|e| format!("creating {}: {e}", out_dir.display()))?;
    let name = sanitize_file_name(&manifest.name);
    let (mut file, path) = create_unique_file(out_dir, &name)
        .map_err(|e| format!("creating output file for {}: {e}", manifest.name))?;
    use std::io::Write as _;
    file.write_all(&buf)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Mirrors `apps/cli/src/send.rs::sanitize_file_name` exactly (blocks path traversal).
fn sanitize_file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or("received-file")
        .to_string()
}

/// Mirrors `apps/cli/src/send.rs::create_unique_file` exactly (TOCTOU/symlink-safe via
/// `create_new`, numeric-suffix collision avoidance).
fn create_unique_file(dir: &Path, name: &str) -> Result<(std::fs::File, PathBuf), String> {
    for n in 0u32.. {
        let path = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{name}.{n}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    unreachable!("u32 suffix space exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;

    use meridian_core::identity::{generate_account, AccountId, MemorySecretStore};
    use meridian_core::session::MemRelay;
    use meridian_core::signaling::generate_bundle;
    use meridian_core::transport::{LoopbackFabric, LoopbackTransport};

    const TEST_NOW_UNIX: u64 = 1_700_000_000;

    /// One test peer: its own `MemorySecretStore`-backed account (never `OsSecretStore` — this
    /// crate's `SecretStore` is a boxed trait object precisely so tests never touch a real OS
    /// keychain) driving its own [`DesktopState<LoopbackTransport>`].
    ///
    /// Two peers in one test share one process-global `$MERIDIAN_HOME` (`EnvGuard::set`, below) —
    /// unlike `apps/core/src/account.rs`'s own single-peer tests, this module's `save_trust`/
    /// `save_chat` calls from *both* peers land on the same `trust.bin`/`sessions.bin` path. This
    /// is harmless here specifically because every test seeds `chat_loaded`/`trust_loaded` (or
    /// reaches them via `ensure_*_loaded`'s own from-empty default) once, in memory, and never
    /// re-reads either file back from disk afterward — the on-disk collision is write-only noise
    /// no assertion in this module observes. Each peer's `download_dir` is **not** derived from
    /// `$MERIDIAN_HOME`, so file-transfer test isolation (deliverable 5's actual point) is real.
    struct Peer {
        state: DesktopState<LoopbackTransport>,
        account: AccountId,
        events: Arc<RecordingEventSink>,
    }

    impl Peer {
        fn new(hint: &str, fabric: &LoopbackFabric, download_dir: &Path) -> Self {
            let store = MemorySecretStore::new();
            let account = generate_account(&store, hint).expect("generate_account");
            let events = Arc::new(RecordingEventSink::default());
            let transport = Arc::new(LoopbackTransport::new(fabric.clone()));
            let state = DesktopState::new(
                Box::new(store),
                transport,
                events.clone() as Arc<dyn EventSink>,
                download_dir.to_path_buf(),
            );
            *state.account.lock().unwrap() = Some(AccountDescriptor::new_os(&account, "test"));
            *state.handle.lock().unwrap() = Some(account.handle().clone());
            Self {
                state,
                account,
                events,
            }
        }

        /// Like [`new`], but with an explicit `FileStream` accept/reject policy — used only by the
        /// file-transfer accept-path test, which needs an auto-accepting hook (the production
        /// default declines everything without an established, size-limited image match).
        fn with_file_stream(
            hint: &str,
            fabric: &LoopbackFabric,
            download_dir: &Path,
            file_stream: Arc<FileStream>,
        ) -> Self {
            let store = MemorySecretStore::new();
            let account = generate_account(&store, hint).expect("generate_account");
            let events = Arc::new(RecordingEventSink::default());
            let transport = Arc::new(LoopbackTransport::new(fabric.clone()));
            let state = DesktopState::with_file_stream(
                Box::new(store),
                transport,
                events.clone() as Arc<dyn EventSink>,
                download_dir.to_path_buf(),
                file_stream,
            );
            *state.account.lock().unwrap() = Some(AccountDescriptor::new_os(&account, "test"));
            *state.handle.lock().unwrap() = Some(account.handle().clone());
            Self {
                state,
                account,
                events,
            }
        }

        fn ik(&self) -> [u8; 32] {
            *self.account.public_key().as_bytes()
        }

        fn id_string(&self) -> String {
            self.account.to_id_string()
        }
    }

    /// Establishes a real X3DH ratchet session between two already-constructed peers (no
    /// network) — mirrors `apps/cli/src/send.rs`'s test module's `establish_ratchet` exactly.
    async fn establish_ratchet(alice: &Peer, bob: &Peer) {
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
        let bundle =
            generate_bundle(alice_store(bob), bob.account.handle(), bob_ik, 5).expect("bundle");
        let otks: Vec<([u8; 32], [u8; 32])> = bundle
            .bundle
            .otks
            .iter()
            .zip(bundle.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        {
            let mut bob_chat = bob.state.chat.lock().await;
            bob_chat
                .vault
                .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks, TEST_NOW_UNIX);
            *bob.state.chat_loaded.lock().unwrap() = true;
        }
        {
            let mut alice_chat = alice.state.chat.lock().await;
            alice_chat
                .start_initiator_session(
                    alice_store(alice),
                    alice.account.handle(),
                    &alice_ik,
                    &bob_ik,
                    &bundle.bundle.spk,
                    bundle.bundle.otks.first().copied(),
                )
                .expect("start session");
            *alice.state.chat_loaded.lock().unwrap() = true;
        }
    }

    /// Test-only accessor: every `SecretStore` this module's `Peer` uses is a `MemorySecretStore`
    /// boxed inside `DesktopState`; reach through the trait object the same way command code does.
    fn alice_store(peer: &Peer) -> &dyn SecretStore {
        peer.state.store.as_ref()
    }

    /// Dials + answers a real `P2pSession<LoopbackTransport>` pair, mirroring
    /// `apps/cli/src/send.rs`'s test `connect` helper — proves `session_dial`/`session_answer`
    /// marshal into a real `meridian-core` session, not a stub.
    async fn connect(alice: &Peer, bob: &Peer) {
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
        let (mut relay_a, mut relay_b) = MemRelay::pair(alice_ik, bob_ik);
        let (ra, rb) = tokio::join!(
            alice.state.session_dial(&mut relay_a, bob_ik),
            bob.state.session_answer(&mut relay_b, alice_ik),
        );
        ra.expect("dial established");
        rb.expect("answer established");
    }

    #[test]
    fn account_create_then_get_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let store = MemorySecretStore::new();
        let transport = Arc::new(LoopbackTransport::new(LoopbackFabric::new()));
        let events = Arc::new(RecordingEventSink::default());
        let state = DesktopState::new(
            Box::new(store),
            transport,
            events.clone() as Arc<dyn EventSink>,
            tmp.path().join("downloads"),
        );

        assert!(state.account_get().is_none());
        let view = state
            .account_create("desktop.example")
            .expect("account_create");
        assert!(view.id.starts_with("mrd1:"));
        assert_eq!(state.account_get(), Some(view.clone()));

        // Security invariant: the DTO carries only public data — no field name that could plausibly
        // hold a seed/private key, and its serialized field set is exactly the expected allowlist.
        let json = serde_json::to_value(&view).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["id", "pubkey_hex", "hint"]
                .into_iter()
                .map(String::from)
                .collect()
        );

        let events = events.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "account:changed");
    }

    #[test]
    fn account_load_reads_a_descriptor_saved_by_account_create() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let store1 = MemorySecretStore::new();
        let transport1 = Arc::new(LoopbackTransport::new(LoopbackFabric::new()));
        let state1 = DesktopState::new(
            Box::new(store1),
            transport1,
            Arc::new(RecordingEventSink::default()),
            tmp.path().join("downloads"),
        );
        let created = state1.account_create("desktop.example").expect("create");

        // A second, freshly-constructed state (simulating a relaunch) loads the same descriptor.
        let store2 = MemorySecretStore::new();
        let transport2 = Arc::new(LoopbackTransport::new(LoopbackFabric::new()));
        let state2 = DesktopState::new(
            Box::new(store2),
            transport2,
            Arc::new(RecordingEventSink::default()),
            tmp.path().join("downloads"),
        );
        let loaded = state2
            .account_load()
            .expect("load")
            .expect("an account exists");
        assert_eq!(loaded, created);
    }

    #[tokio::test]
    async fn contact_lifecycle_never_derives_petname_from_the_wire() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let fabric = LoopbackFabric::new();
        let alice = Peer::new("contact.alice", &fabric, &tmp.path().join("downloads"));
        let bob = Peer::new(
            "totallylegitbob.example",
            &fabric,
            &tmp.path().join("downloads"),
        );

        let added = alice
            .state
            .contact_add(&bob.id_string(), None)
            .await
            .expect("contact_add");
        assert_eq!(
            added.petname, None,
            "no petname supplied — must not derive one from the hint"
        );
        assert_eq!(added.state, "pinned");

        let renamed = alice
            .state
            .contact_rename(&bob.id_string(), "Bob (verified friend)")
            .await
            .expect("contact_rename");
        assert_eq!(renamed.petname.as_deref(), Some("Bob (verified friend)"));

        let list = alice.state.contact_list().await.expect("contact_list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, added.id);

        let verified = alice
            .state
            .contact_mark_verified(&bob.id_string())
            .await
            .expect("mark_verified");
        assert_eq!(verified.state, "verified");

        let blocked = alice
            .state
            .contact_block(&bob.id_string(), true)
            .await
            .expect("block");
        assert!(blocked.user_blocked);
    }

    #[tokio::test]
    async fn chat_send_and_receive_round_trip_over_a_real_p2p_session() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let fabric = LoopbackFabric::new();
        let alice = Peer::new("chat.alice", &fabric, &tmp.path().join("downloads"));
        let bob = Peer::new("chat.bob", &fabric, &tmp.path().join("downloads"));
        establish_ratchet(&alice, &bob).await;
        connect(&alice, &bob).await;

        // Bob is not yet a known contact from Alice's side — `chat_send` still succeeds (`SendGate`
        // only ever *blocks*/*warns* on a recorded key change, never on "unknown"), proving the
        // command layer marshals into a genuine `send_chat` call rather than short-circuiting.
        let sent = alice
            .state
            .chat_send(&bob.id_string(), "hello over p2p")
            .await
            .expect("chat_send");
        assert_eq!(sent.id_hex.len(), 32, "16-byte message id, hex-encoded");

        // Bob's first pump on an unrecognized sender lands as a gated MessageRequest — never
        // auto-delivered (system-design.md §3.5).
        let event = bob
            .state
            .pump_once(&alice.id_string())
            .await
            .expect("pump_once");
        assert!(matches!(event, Some(ChatEvent::MessageRequest { .. })));

        let answered = bob
            .state
            .contact_answer_request(&alice.id_string(), true)
            .await
            .expect("contact_answer_request")
            .expect("the held intro is returned");
        match answered {
            ChatEvent::Message { body, .. } => assert_eq!(body, "hello over p2p"),
            other => panic!("expected a Message event, got {other:?}"),
        }

        // Accepting TOFU-pinned Alice on Bob's side.
        let bob_contacts = bob.state.contact_list().await.expect("contact_list");
        assert_eq!(bob_contacts.len(), 1);
        assert_eq!(bob_contacts[0].id, alice.id_string());

        // No secret material anywhere in what was emitted.
        for (_, payload) in bob.events.0.lock().unwrap().iter() {
            let s = payload.to_string();
            assert!(!s.contains("k_f"), "no k_f field ever serialized: {s}");
        }
    }

    #[tokio::test]
    async fn a_declined_file_is_never_written_and_the_sender_sees_the_decline() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let fabric = LoopbackFabric::new();
        let alice = Peer::new(
            "file.decline.alice",
            &fabric,
            &tmp.path().join("alice-downloads"),
        );
        let bob = Peer::new(
            "file.decline.bob",
            &fabric,
            &tmp.path().join("bob-downloads"),
        );
        establish_ratchet(&alice, &bob).await;
        connect(&alice, &bob).await;

        // Bob's `FileStream` (constructed by `DesktopState::new`) auto-declines anything that
        // isn't a small, already-established-contact image — a plain `.bin` reaches `AskUser`
        // then the default-`false` hook, so it is declined without any UI wired yet (12.15's job).
        let file_path = tmp.path().join("secret.bin");
        std::fs::write(&file_path, vec![7u8; 500]).unwrap();

        let alice_id = alice.id_string();
        let bob_id = bob.id_string();
        // Alice's `file_send` blocks in its own accept/reject wait loop until Bob's `Reject`
        // comes back — which only happens once Bob's side has pumped *both* frames `file_send`
        // produces: the `FILE_OPEN_HELLO` opening chat message (first contact between these two
        // peers — accept it, a stand-in for a real user decision, so the check below reaches the
        // file-level `AskUser` step rather than being rejected earlier for "first-contact") and
        // the following `mrd.file/1` OPEN itself (declined synchronously inside `on_open` by the
        // default, safe-until-a-real-UI-hook `FileStream`). Drive both sides concurrently,
        // mirroring `apps/cli/src/send.rs`'s own equivalent test (`bob_task`/`send_result` via
        // `tokio::join!`); bob's loop is bounded (never more than the two real frames this
        // scenario produces) rather than pumping forever once nothing more is coming.
        let bob_task = async {
            for _ in 0..5u32 {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    bob.state.pump_once(&alice_id),
                )
                .await
                {
                    Ok(Ok(Some(ChatEvent::MessageRequest { .. }))) => {
                        bob.state
                            .contact_answer_request(&alice_id, true)
                            .await
                            .expect("accept the opening message request");
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => break,
                }
            }
        };
        let (send_result, ()) = tokio::join!(alice.state.file_send(&bob_id, &file_path), bob_task);

        let err = send_result.expect_err("a declined transfer must surface as an error");
        assert!(err.contains("declined"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn file_send_and_receive_round_trip_is_byte_identical() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path());
        let fabric = LoopbackFabric::new();
        let out_dir = tmp.path().join("bob-downloads");
        let alice = Peer::new("file.alice", &fabric, &tmp.path().join("alice-downloads"));
        // Bob auto-accepts everything for this test via an explicit `FileStream` policy — the
        // production default (`DesktopState::new`) safely declines until a real UI hook (12.15)
        // exists; exercising the accept path needs an opt-in, mirroring
        // `apps/cli/src/send.rs`'s own test precedent (`FileStream::with_ask_user(0, |_, _| true)`).
        let accepting = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let bob = Peer::with_file_stream("file.bob", &fabric, &out_dir, accepting);
        establish_ratchet(&alice, &bob).await;
        connect(&alice, &bob).await;

        let file_path = tmp.path().join("movie.bin");
        let data: Vec<u8> = (0..(3 * CHUNK_SIZE + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&file_path, &data).unwrap();

        let bob_id = bob.id_string();
        let alice_id = alice.id_string();
        let bob_events = bob.events.clone();
        let bob_pump = tokio::spawn(async move {
            // Drive Bob's side, one pump at a time, until `check_incoming_transfers` has emitted
            // `file:received` — never more than that: once every real frame this transfer will
            // ever produce has arrived, the next `pump()` would block forever on
            // `Transport::recv()` waiting for traffic that is never coming (the session stays
            // open; `file_send` does not close it). A per-pump timeout is the backstop against a
            // genuine bug leaving nothing to receive.
            loop {
                let received = bob_events
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(name, _)| name == "file:received");
                if received {
                    break;
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    bob.state.pump_once(&alice_id),
                )
                .await
                {
                    // `file_send`'s own `FILE_OPEN_HELLO` (Alice and Bob have no prior session)
                    // lands as a gated message request — accept it (a stand-in for a real user
                    // decision, 12.15's job) so the *following* `mrd.file/1` OPEN's own
                    // `PolicyCtx::first_contact` reads `false`
                    // (`P2pSession::decide_open`'s `chat.pending_request(..).is_some()` half of
                    // that check, independent of the already-cleared `chat_first_contact_gate`).
                    Ok(Ok(Some(ChatEvent::MessageRequest { .. }))) => {
                        bob.state
                            .contact_answer_request(&alice_id, true)
                            .await
                            .expect("accept the opening message request");
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => panic!("bob's pump_once errored before receiving the file: {e}"),
                    Err(_) => panic!("timed out waiting for the file transfer to finish"),
                }
            }
        });

        let sent = alice
            .state
            .file_send(&bob_id, &file_path)
            .await
            .expect("file_send");
        assert_eq!(sent.name, "movie.bin");

        bob_pump.await.unwrap();

        let written = std::fs::read_dir(&out_dir)
            .expect("out_dir exists")
            .filter_map(|e| e.ok())
            .find(|e| e.file_name() == "movie.bin")
            .map(|e| e.path())
            .expect("movie.bin was written");
        let on_disk = std::fs::read(written).expect("readable");
        assert_eq!(
            on_disk, data,
            "received file must be byte-identical to the source"
        );
    }

    /// Serializes test access to `MERIDIAN_HOME` — mirrors `apps/core/src/account.rs`'s own
    /// `EnvGuard` exactly (same process-global env var).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var("MERIDIAN_HOME").ok();
            // SAFETY: guarded by ENV_LOCK, single-threaded test access to this process-global.
            unsafe {
                std::env::set_var("MERIDIAN_HOME", dir);
            }
            Self { _lock: lock, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: guarded by ENV_LOCK, single-threaded test access to this process-global.
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                    None => std::env::remove_var("MERIDIAN_HOME"),
                }
            }
        }
    }
}
