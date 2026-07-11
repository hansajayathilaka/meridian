//! meridian-identity — the self-certifying identity layer (T01).
//!
//! A user's identity **is** their Ed25519 public key; the `@home-domain` is only an advisory
//! routing hint (system-design §3.1, [ADR-0001]). This crate freezes the shareable ID format and
//! provides the detached sign/verify API every later envelope depends on.
//!
//! Frozen wire format: `../../docs/api/identity-format.md`. Public API contract:
//! `../../docs/api/core-api-contracts.md` ("Identity (T01 — frozen wire behavior)").
//!
//! [ADR-0001]: ../../docs/adr/0001-identity-scheme.md
//!
//! # Example
//! ```
//! use meridian_identity::{generate_account, parse_id, same_principal, MemorySecretStore};
//!
//! let store = MemorySecretStore::new();
//! let account = generate_account(&store, "chat.example").unwrap();
//!
//! // The canonical string round-trips, and the same key under a different hint is the same
//! // principal.
//! let id = account.to_id_string();
//! let parsed = parse_id(&id).unwrap();
//! assert_eq!(parsed.pubkey(), account.public_key().as_bytes());
//!
//! let other_hint = parse_id(&account.public_key().to_id_string("other.example").unwrap()).unwrap();
//! assert!(same_principal(&parsed, &other_hint));
//! ```
//!
//! `no_std`: the encode/parse core (`id`) leans only on `core`/`alloc` + `data-encoding` so it can
//! move behind a `no_std` feature for future embedded use (T01 risk note). The crate is `std`
//! today for `getrandom`/keystore ergonomics. TODO: confirm the `no_std` split when an embedded
//! target actually appears.

mod error;
mod id;
mod keys;
mod qr;

pub use error::{HintError, IdError};
pub use id::{
    decode_key_part, encode_key_part, parse_id, same_principal, to_id_string, validate_hint,
    Identity, CHECKSUM_LEN, KEY_PART_LEN, MULTICODEC_ED25519_PUB, PUBKEY_LEN, SCHEME,
};
pub use keys::{
    generate_account, pubkey_from_seed, sign, verify, AccountId, GenerateError, PublicKey,
    Signature,
};
pub use qr::{decode_luma, render_luma, render_terminal, QrError};

// Re-export the store surface so a single `meridian_identity::` import (and the core facade) can
// drive account creation without a separate `meridian_store` dependency in every shim.
pub use meridian_store::{
    install_mock_keystore, platform_keystore_available, FileSecretStore, KeyHandle,
    MemorySecretStore, OsSecretStore, SecretStore, SignOrDh, StoreError,
};
