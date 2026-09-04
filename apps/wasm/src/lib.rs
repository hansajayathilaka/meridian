//! `meridian-wasm` — the wasm-bindgen cdylib that proves the browser build pipeline end to end
//! (task 12.10, T11).
//!
//! This crate is a **scaffold**, not the real browser core: every function below routes through
//! `meridian_core::identity::MemorySecretStore` (an in-process, filesystem-free stand-in — see
//! `apps/store/src/mem.rs`), never the real browser `Transport`/`SecretStore` impls. Wiring these
//! into a browser-facing facade (account creation over `WebCryptoSecretStore`, a session driven by
//! `BrowserTransport`) is a separate, later task (12.13):
//! - the real `BrowserTransport` over `RTCPeerConnection`/`RTCDataChannel` now exists
//!   ([`transport::BrowserTransport`], task 12.11) but is not yet reachable from this scaffold's
//!   exported `#[wasm_bindgen]` surface;
//! - `WebCryptoSecretStore` + IndexedDB session persistence (task 12.12/12.13) —
//!   `WebCryptoSecretStore` itself already exists (task 12.5, `apps/store/src/webcrypto.rs`) but is
//!   deliberately not reachable from this crate yet.
//!
//! The point of landing this scaffold first (the feature spec's own risk note: "schedule the WASM
//! smoke build as day-1 of this task regardless") is to catch anything a plain `cargo check
//! --target wasm32-unknown-unknown` (task 12.4) cannot: `wasm-bindgen`'s macro-generated glue,
//! actual codegen/linking through `wasm-pack build --release`, and bundle size — *before* the
//! harder real Transport/store pieces exist.
//!
//! ## Exported surface
//! - [`generate_account`] — creates a new Ed25519 account (`meridian_identity::generate_account`)
//!   against a private `MemorySecretStore`, returning a [`WasmAccount`] that owns both the account
//!   and the store so later calls can sign through it.
//! - [`WasmAccount::sign`] — detached Ed25519 signature over caller-supplied bytes
//!   (`meridian_identity::sign`), through the account's own store — the private key never crosses
//!   the wasm boundary.
//! - [`verify`] — detached-signature verification (`meridian_identity::verify`), a free function
//!   since it needs no store, only public bytes.
//! - [`safety_number`] — the 60-digit human-verifiable fingerprint of two identity keys
//!   (`meridian_crypto::fingerprint::safety_number`, re-exported as `meridian_core::crypto`).
//!
//! ## Headless test runner (`TODO: confirm` resolution for this task)
//! `wasm-pack test --node`, not `wasm-bindgen-test` against a real headless Chromium. This task's
//! smoke test only exercises plain function calls through the wasm boundary — no WebCrypto,
//! IndexedDB, or other browser-only API — so Node is sufficient, and it sidesteps the
//! Chromium/ChromeDriver version-matching fragility task 12.5 recorded (reconfirmed here: this
//! sandbox ships a `chromedriver` binary but no matching browser binary at all). Recorded here so
//! 12.11/12.12/12.13 — whose own smoke tests likely also need no browser-only API — can reuse this
//! choice; a task that *does* need a real browser API (WebCrypto non-extractability, IndexedDB)
//! should keep using 12.5's real-Chromium approach instead, same reasoning in reverse.

use meridian_core::{crypto, identity};
use wasm_bindgen::prelude::*;

/// The browser realization of `Transport` (task 12.11) — see the module doc there. `wasm32`-gated:
/// it wraps `web_sys::RtcPeerConnection`, meaningless (and undeployable) on any other target.
#[cfg(target_arch = "wasm32")]
pub mod transport;

/// The IndexedDB record-sealing/schema module (ADR 0026 binding conditions 2–5, task 12.12) — see
/// `store::indexeddb`'s module doc. `wasm32`-gated: it wraps `web_sys::IdbFactory`/`IdbDatabase`,
/// meaningless (and undeployable) on any other target.
#[cfg(target_arch = "wasm32")]
pub mod store;

/// A generated account: the identity itself plus the (private, in-process) store backing it.
///
/// Opaque to JS beyond the getters/methods below — the private key never leaves `store`.
#[wasm_bindgen]
pub struct WasmAccount {
    account: identity::AccountId,
    store: identity::MemorySecretStore,
}

#[wasm_bindgen]
impl WasmAccount {
    /// The canonical `mrd1:…@hint` string for this account.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.account.to_id_string()
    }

    /// The raw 32-byte Ed25519 public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.account.public_key().as_bytes().to_vec()
    }

    /// Detached Ed25519 signature over `msg`, produced through this account's own store — the
    /// private key itself is never returned to the caller.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = identity::sign(&self.store, self.account.handle(), msg).map_err(js_err)?;
        Ok(sig.as_bytes().to_vec())
    }
}

/// Generate a new Ed25519 account under `hint` (the `@home-domain` routing hint,
/// `meridian_identity::validate_hint`'s rules apply), backed by a fresh, private
/// `MemorySecretStore`.
#[wasm_bindgen(js_name = generateAccount)]
pub fn generate_account(hint: &str) -> Result<WasmAccount, JsError> {
    let store = identity::MemorySecretStore::new();
    let account = identity::generate_account(&store, hint).map_err(js_err)?;
    Ok(WasmAccount { account, store })
}

/// Verify a detached Ed25519 signature. `public_key` must be exactly 32 bytes and `sig` exactly
/// 64 bytes; returns `Ok(false)` (not an error) for any cryptographically invalid signature —
/// only malformed *input lengths* are reported as errors.
#[wasm_bindgen]
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, JsError> {
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    let pk = identity::PublicKey::from_bytes(pk_bytes).map_err(js_err)?;
    let sig = identity::Signature::from_slice(sig).map_err(js_err)?;
    Ok(identity::verify(&pk, msg, &sig))
}

/// The order-independent 60-digit safety number for two 32-byte identity public keys
/// (`meridian_core::crypto::safety_number`).
#[wasm_bindgen(js_name = safetyNumber)]
pub fn safety_number(a: &[u8], b: &[u8]) -> Result<String, JsError> {
    let a: [u8; 32] = a
        .try_into()
        .map_err(|_| JsError::new("first key must be 32 bytes"))?;
    let b: [u8; 32] = b
        .try_into()
        .map_err(|_| JsError::new("second key must be 32 bytes"))?;
    Ok(crypto::safety_number(&a, &b))
}

/// Flatten any `Display`-able error (every error type these functions call into is a `thiserror`
/// enum) into a `JsError`, the idiomatic wasm-bindgen `Result` error type (surfaces as a real JS
/// `Error` with `.message`, not an opaque `JsValue`).
fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    // Node is sufficient (see this module's doc) — no `run_in_browser` configure call.

    #[wasm_bindgen_test]
    fn generate_sign_verify_round_trip() {
        let account = generate_account("chat.example").expect("generate_account");
        let msg = b"hello from meridian-wasm";
        let sig = account.sign(msg).expect("sign");
        let ok = verify(&account.public_key(), msg, &sig).expect("verify");
        assert!(ok);

        // A tampered message must not verify.
        let tampered = b"hello from meridian-wasn";
        let bad = verify(&account.public_key(), tampered, &sig).expect("verify");
        assert!(!bad);
    }

    #[wasm_bindgen_test]
    fn safety_number_is_order_independent_and_60_digits() {
        let a = generate_account("a.example").expect("generate_account a");
        let b = generate_account("b.example").expect("generate_account b");

        let ab = safety_number(&a.public_key(), &b.public_key()).expect("safety_number ab");
        let ba = safety_number(&b.public_key(), &a.public_key()).expect("safety_number ba");
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 60);
        assert!(ab.chars().all(|c| c.is_ascii_digit()));
    }
}
