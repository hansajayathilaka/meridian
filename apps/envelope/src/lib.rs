//! meridian-envelope — content-shaped, end-to-end-encrypted payload types.
//!
//! These are the plaintext/signed shapes that ride *inside* a `meridian_proto::OpaqueBlob`: the
//! message envelope (X3DH preamble + ratchet ciphertext), chat content, P2P signaling content, and
//! the `mrd.ctrl/1` session-control frames. A server never constructs, inspects, or decodes any of
//! these — only endpoints do, after decrypting.
//!
//! ## Why this is its own crate (F15)
//! `meridian-rendezvous` legitimately depends on `meridian-proto` (opaque routing frames, prekey
//! bundles, control-plane request/reply types). It must NEVER be able to import these
//! content-shaped types — not even transitively, not even behind a Cargo feature (a feature-flag
//! split was tried and rejected: Cargo unifies feature flags across a `cargo build --workspace`, so
//! a feature gate does not hold under the exact commands CI and the dev loop use). Putting these
//! types in a crate that `apps/rendezvous/Cargo.toml` never lists as a dependency — direct or
//! dev — is a dependency-graph exclusion instead: compiler-enforced under every build command,
//! immune to feature unification.
//!
//! `apps/rendezvous` MUST NOT add a dependency on this crate, ever. See apps/proto/CLAUDE.md,
//! docs/security/anonymity-and-retention.md "must never" #1, and the defense-in-depth grep lint
//! `tools/lint-no-serde-on-blob.sh`.

pub mod chat;
pub mod ctrl;
pub mod envelope;
pub mod signal;

pub use chat::{ChatContent, MessageId};
pub use ctrl::{ChanCfgWire, CtrlFrame, Direction, Limits, StreamAdvert, CTRL_VERSION};
pub use envelope::{MessageEnvelope, Prekey, ENVELOPE_DOMAIN};
pub use signal::SignalContent;
