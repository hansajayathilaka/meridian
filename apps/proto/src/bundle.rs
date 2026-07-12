//! Prekey bundle — the X3DH key material a client publishes to its rendezvous and peers fetch.
//!
//! T02 stores and routes bundles; it does **not** run X3DH (that is T03). The server treats a
//! bundle as public, structured-but-inert data (all fields are public keys or signatures over
//! them). The security-critical check — every signature verifies **under the requested account
//! key** — is performed by the *fetching client*, never trusted from the server (system-design
//! §3.3 step 4).

use serde::{Deserialize, Serialize};

use crate::OpaqueBlob;

/// Classical (X3DH) bundle layout. `v:2` is reserved for the PQXDH hybrid (wire-protocol §7).
pub const BUNDLE_VERSION: u16 = 1;

/// Upper bound on one-time prekeys a client publishes / a server accepts in one bundle
/// (feature spec T02: "≤100 one-time prekeys").
pub const MAX_ONE_TIME_PREKEYS: usize = 100;

/// A signed prekey bundle. Every `*_sig` is an Ed25519 signature by `account_pub` over the
/// corresponding public key bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// Bundle format version ([`BUNDLE_VERSION`]).
    pub v: u16,
    /// The Ed25519 account identity key this bundle belongs to (the principal).
    #[serde(with = "crate::bytes::b32")]
    pub account_pub: [u8; 32],
    /// X25519 signed prekey (public), rotated ~weekly.
    #[serde(with = "crate::bytes::b32")]
    pub spk: [u8; 32],
    /// Ed25519(account) over `spk`.
    #[serde(with = "crate::bytes::b64")]
    pub spk_sig: [u8; 64],
    /// X25519 one-time prekeys (public); consumed one per first contact.
    #[serde(with = "crate::bytes::vec_b32")]
    pub otks: Vec<[u8; 32]>,
    /// Ed25519(account) over each corresponding `otks[i]`. Length MUST equal `otks`.
    #[serde(with = "crate::bytes::vec_b64")]
    pub otk_sigs: Vec<[u8; 64]>,
    /// Account-signed device record (T13). Opaque here — the server stores it verbatim and never
    /// edits it; clients verify it under the account key. `None` until T13 lands.
    /// TODO: confirm device-record schema in T13 (docs/architecture/features/13-multi-device.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_record: Option<OpaqueBlob>,
}

impl PrekeyBundle {
    /// Structural sanity independent of signatures: version, paired sig counts, OTK bound.
    /// Signature verification is a separate, mandatory client step ([`verify_under`] callers).
    pub fn structurally_valid(&self) -> bool {
        self.v == BUNDLE_VERSION
            && self.otks.len() == self.otk_sigs.len()
            && self.otks.len() <= MAX_ONE_TIME_PREKEYS
    }

    /// How many one-time prekeys this bundle carries.
    pub fn otk_count(&self) -> usize {
        self.otks.len()
    }
}
