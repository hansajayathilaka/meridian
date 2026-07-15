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

/// Shared wire types (frames, bundles, opaque envelopes) — surfaced for shims that build frames.
pub use meridian_proto as proto;

/// E2EE session layer: X3DH, header-encrypted Double Ratchet, safety numbers (T03).
pub use meridian_crypto as crypto;

/// The `Transport` trait + implementations (loopback; webrtc-rs behind a feature). The seam that
/// lets one core run on five targets (T04, ADR 0014).
pub use meridian_transport as transport;

/// Chat session manager — signs/verifies + seals/opens `mrd.chat/1` envelopes and owns the
/// persistable session store. Transport-agnostic (relay today, P2P/mailbox later).
pub mod chat;

/// The P2P **session substrate** (T04): the dial/answer state machine that carries chat over a
/// direct WebRTC data channel with the servers out of the path, with DTLS-fingerprint binding
/// (§4.6), the `mrd.ctrl/1` control channel, and keepalive/ICE-restart.
pub mod session;

/// The stream-type **registry** (T04): the extension point (`register_stream_type`) that lets
/// file/call/location/tunnel stream types be added with zero core edits (§5.3, ADR contract).
pub mod streams;

/// Relay policy (T05, §5.4): the `direct | prefer-relay | relay-only` knob resolved across
/// org-default / per-user / per-contact scope, and the [`meridian_transport::IceConfig`] it yields.
pub mod relay;

/// Crate version — kept for build-info/diagnostics.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
