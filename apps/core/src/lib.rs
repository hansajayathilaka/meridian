//! meridian-core — shared core facade.
//!
//! Public API contract: ../../docs/api/core-api-contracts.md
//! Module architecture:  ../../docs/architecture/diagrams/core-modules.mermaid
//!
//! The core re-exports each sub-crate's public surface so shims (`cli`, `ffi`, `wasm`, Tauri)
//! depend on this one crate. Sub-crates land per the roadmap
//! (../../docs/architecture/roadmap.md); T01 wires in `identity` (+ `store`).

/// Self-certifying identity: `mrd1:…@domain` IDs, Ed25519 sign/verify, keystore, QR (T01).
pub use meridian_identity as identity;

/// Secret storage: the `SecretStore` trait and its OS/file/memory impls (T01).
pub use meridian_store as store;

/// Client-side signaling: connect/auth to a rendezvous, publish/fetch prekey bundles (with
/// mandatory verification), and route opaque envelopes (T02).
pub use meridian_signaling as signaling;

/// Shared wire types (frames, bundles, opaque routing) — surfaced for shims that build frames.
pub use meridian_proto as proto;

/// Content-shaped, end-to-end-encrypted payload types (message envelope, chat/signal content,
/// `mrd.ctrl/1` frames) — deliberately NOT part of `meridian-proto` so `meridian-rendezvous` has no
/// dependency path to them (F15; see apps/envelope/src/lib.rs).
pub use meridian_envelope as envelope;

/// E2EE session layer: X3DH, header-encrypted Double Ratchet, safety numbers (T03).
pub use meridian_crypto as crypto;

/// The `Transport` trait + implementations (loopback; webrtc-rs behind a feature). The seam that
/// lets one core run on five targets (T04, ADR 0014).
pub use meridian_transport as transport;

/// The account descriptor (`account.json`) and `$MERIDIAN_HOME` layout helpers (T01, relocated in
/// task 4.13 so every shim — CLI, and per ADR 0020 the core-only `meridian-tui` — reaches the same
/// on-disk account/session-store layout through one code path.
pub mod account;

/// Chat session manager — signs/verifies + seals/opens `mrd.chat/1` envelopes and owns the
/// persistable session store. Transport-agnostic (relay today, P2P/mailbox later).
pub mod chat;

/// Guarded receiver-side desync recovery (task 4.9, following through on task 1.18's deferred
/// "dangerous half"): the decision + state-mutation glue for reacting to *repeated*
/// `chat::ChatError::Desync` by fetching a fresh bundle and forcing a re-handshake, gated by
/// `trust::TrustStore::can_send`. Still I/O-free; see the module doc.
pub mod desync;

/// The P2P **session substrate** (T04): the dial/answer state machine that carries chat over a
/// direct WebRTC data channel with the servers out of the path, with DTLS-fingerprint binding
/// (§4.6), the `mrd.ctrl/1` control channel, and keepalive/ICE-restart.
pub mod session;

/// A [`session::SignalRelay`] adapter over the real rendezvous [`signaling::SignalingClient`]
/// (1.24) — the counterpart to [`session::MemRelay`] for cross-process P2P session establishment.
pub mod signal_relay;

/// The stream-type **registry** (T04): the extension point (`register_stream_type`) that lets
/// file/call/location/tunnel stream types be added with zero core edits (§5.3, ADR contract).
pub mod streams;

/// Relay policy (T05, §5.4): the `direct | prefer-relay | relay-only` knob resolved across
/// org-default / per-user / per-contact scope, and the [`meridian_transport::IceConfig`] it yields.
pub mod relay;

/// Trust module + contact store (T08, tasks 4.3/4.4): the client-agnostic `new → pinned (TOFU) →
/// verified`/`blocked` state machine every client shares, sealed at rest like `chat`'s
/// `ChatState`. Task 4.4 adds key-change detection (`TrustStore::observe_key_change`) and the
/// un-softenable `can_send` gate (`SendGate`) documented in `docs/security/verification-ux.md`.
pub mod trust;

/// Org directory-attestation ingest (T08, task 4.8): verify + ingest a signed, org-issued
/// HR-name→account-key mapping as a display-name suggestion with recorded provenance — never a
/// key authority, never merged into `trust::Contact::petname`. See the module doc comment for the
/// structural (not just tested) enforcement of that boundary.
pub mod directory;

/// Crate version — kept for build-info/diagnostics.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
