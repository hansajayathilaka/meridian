//! meridian-crypto — the E2EE session layer (T03).
//!
//! Part of `meridian-core` (re-exported as `meridian_core::crypto`). It provides:
//! - **X3DH** ([`x3dh`]) — the prekey handshake against the frozen `v:1` bundle, deriving the
//!   initial root key and shared header keys (system-design §4.2).
//! - **Double Ratchet with header encryption** ([`ratchet`], [`session::Session`]) — per-message
//!   forward secrecy and post-compromise security, independent of transport (§4.3).
//! - **Safety numbers** ([`fingerprint`]) — the verification backstop's computation (§4.4).
//!
//! Design & security context: [ADR 0003](../../../docs/adr/0003-e2ee-protocol.md),
//! [ADR 0011](../../../docs/adr/0011-ratchet-library.md) (and its 2026-07 superseding note on why
//! the ratchet is composed here rather than delegated to vodozemac), the
//! [crypto-protocols skill](../../../.claude/skills/crypto-protocols/SKILL.md), and the envelope
//! spec [`messaging-envelope-v1.md`](../../../docs/api/messaging-envelope-v1.md).
//!
//! Everything here is built from audited RustCrypto primitives (`x25519-dalek`, `ed25519-dalek`,
//! `hkdf`, `hmac`, `sha2`, `chacha20poly1305`); no primitive is hand-rolled. The X3DH/ratchet
//! *integration* is on the Phase-1 external crypto-review gate ([testing/strategy.md](../../../docs/testing/strategy.md) §7).

mod error;
mod primitives;

pub mod at_rest;
pub mod fingerprint;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use error::{CryptoError, Result};
pub use fingerprint::{display_groups, safety_number};
pub use ratchet::{DoubleRatchet, MAX_SKIP};
pub use session::{PrekeyMaterial, Session};
