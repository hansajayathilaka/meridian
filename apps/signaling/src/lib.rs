//! meridian-signaling — the client half of the client↔rendezvous protocol (T02).
//!
//! Part of `meridian-core` (re-exported as `meridian_core::signaling`). It connects to a
//! rendezvous over WebSocket, authenticates by signing a server challenge with the account key
//! (through the [`SecretStore`](meridian_store::SecretStore) — the key never leaves it), publishes
//! signed prekey bundles, fetches peer bundles **with mandatory signature verification against the
//! requested key**, and routes opaque signed envelopes between online peers.
//!
//! Wire format & framing: `../../docs/api/rendezvous-protocol-v1.md`. The security-critical rule —
//! a fetched bundle that does not verify under the exact requested key is a hard failure — lives in
//! [`bundle::verify_bundle`] and is exercised by the malicious-server harness (T02 deliverable 4).

mod bundle;
mod client;
mod error;

pub use bundle::{generate_bundle, verify_bundle, GeneratedBundle};
pub use client::SignalingClient;
pub use error::{Result, SignalError};

/// Default one-time-prekey batch size published at registration (feature spec: ≤100).
pub const DEFAULT_OTK_COUNT: usize = meridian_proto::MAX_ONE_TIME_PREKEYS;
