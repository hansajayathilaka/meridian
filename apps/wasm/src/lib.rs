//! `meridian-wasm` — the wasm-bindgen cdylib exposing the browser client's identity + transport
//! surface (task 12.10 scaffold; task 12.13 step 1 — the Rust-side async `SecretStore` bridge;
//! task 12.13 step 2 — the TS adapter, `apps/web/src/lib/adapter.ts`, plus this crate's own
//! [`WasmTransport`] addition, T11).
//!
//! [`generate_account`]/[`WasmAccount::sign`] are real: backed by
//! `meridian_core::store::WebCryptoSecretStore` (task 12.5) through the async
//! `meridian_identity::generate_account_async`/`sign_async` helpers (ADR 0028) — the private
//! account key is imported as a non-extractable `crypto.subtle` `CryptoKey` and never crosses the
//! wasm boundary. `verify`/`safety_number` need no store at all, so they stay plain, synchronous
//! functions, unchanged from task 12.10. [`WasmTransport`] (added by step 2) is a thin marshaling
//! wrapper around the already-implemented, already-reviewed [`transport::BrowserTransport`] (task
//! 12.11) — see that type's own doc comment for exactly what it adds and why.
//!
//! Still **not** wired into this crate's exported surface — a genuinely large remaining gap, not
//! invented around by step 2 (see `apps/web/src/lib/adapter.ts`'s own top doc comment for the full
//! report):
//! - a session/chat orchestration layer (`meridian_core::chat::ChatState`, X3DH, the ratchet) —
//!   nothing exported here can open a conversation or send/receive an actual chat message yet, only
//!   move opaque bytes over a raw data channel via [`WasmTransport`];
//! - IndexedDB persistence via [`store::indexeddb`] (task 12.12) — the module exists but is not
//!   yet reachable from this crate's exported `#[wasm_bindgen]` surface (its `put_sealed`/
//!   `get_sealed` JSON-only record shape also cannot carry a non-extractable `CryptoKey` object,
//!   which is what would actually be needed to survive a reload — a separate, deeper gap, also
//!   reported in `adapter.ts`'s own doc comment rather than worked around here).
//!
//! ## Exported surface
//! - [`generate_account`] — creates a new Ed25519 account
//!   (`meridian_identity::generate_account_async`) against a fresh `WebCryptoSecretStore`,
//!   returning a [`WasmAccount`] that owns both the account and the store so later calls can sign
//!   through it. `async fn` — wasm-bindgen generates a Promise-returning JS binding for this
//!   natively, no manual `future_to_promise` needed.
//! - [`WasmAccount::sign`] — detached Ed25519 signature over caller-supplied bytes
//!   (`meridian_identity::sign_async`), through the account's own store — the private key never
//!   crosses the wasm boundary. `async fn`, same reason.
//! - [`verify`] — detached-signature verification (`meridian_identity::verify`), a free,
//!   synchronous function since it needs no store, only public bytes.
//! - [`safety_number`] — the 60-digit human-verifiable fingerprint of two identity keys
//!   (`meridian_crypto::fingerprint::safety_number`, re-exported as `meridian_core::crypto`),
//!   synchronous, same reason.
//! - [`WasmTransport`] — a 1:1 marshaling wrapper over [`transport::BrowserTransport`]'s existing
//!   `Transport` methods (task 12.13 step 2 addition) — see its own doc comment.
//!
//! ## Headless test runner
//! [`verify`]/[`safety_number`] stay covered by this module's own `#[cfg(test)]` suite, run via
//! `wasm-pack test --node` (task 12.10's original choice — neither needs a browser-only API).
//! [`generate_account`]/[`WasmAccount::sign`] now touch real `crypto.subtle`, so their coverage
//! moved to `tests/webcrypto_account.rs`, a real-headless-Chromium
//! `wasm_bindgen_test_configure!(run_in_browser)` suite (`wasm-pack test --chrome --headless`) —
//! the same tool tasks 12.5/12.11/12.12 already established for anything that needs a genuine
//! browser-only API, per this module's own former guidance to reuse it "in reverse" here.

use meridian_core::{crypto, identity};
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Uint8Array};

/// The browser realization of `Transport` (task 12.11) — see the module doc there. `wasm32`-gated:
/// it wraps `web_sys::RtcPeerConnection`, meaningless (and undeployable) on any other target.
#[cfg(target_arch = "wasm32")]
pub mod transport;

/// The IndexedDB record-sealing/schema module (ADR 0026 binding conditions 2–5, task 12.12) — see
/// `store::indexeddb`'s module doc. `wasm32`-gated: it wraps `web_sys::IdbFactory`/`IdbDatabase`,
/// meaningless (and undeployable) on any other target.
#[cfg(target_arch = "wasm32")]
pub mod store;

/// A generated account: the identity itself plus the (private) `WebCryptoSecretStore` backing it.
///
/// Opaque to JS beyond the getters/methods below — the private key is imported into `store` as a
/// non-extractable `crypto.subtle` `CryptoKey` (ADR 0026/task 12.5) and never leaves it.
///
/// `wasm32`-gated, like [`transport`]/[`store`]: `WebCryptoSecretStore`
/// (`meridian_identity::WebCryptoSecretStore`/`AsyncSecretStore`, ADR 0028) and the
/// Promise-returning glue `#[wasm_bindgen]` generates for `async fn`s (`wasm_bindgen_futures`,
/// only a dependency on this target — see `Cargo.toml`) are both meaningless off it; unlike
/// `verify`/`safety_number` below, this type has no cross-platform-safe fallback to keep
/// ungated.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct WasmAccount {
    account: identity::AccountId,
    store: identity::WebCryptoSecretStore,
}

#[cfg(target_arch = "wasm32")]
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

    /// Detached Ed25519 signature over `msg`, produced through this account's own
    /// `WebCryptoSecretStore` (`meridian_identity::sign_async`, ADR 0028) — the private key itself
    /// is never returned to the caller. `async fn`: wasm-bindgen generates a Promise-returning JS
    /// binding for this natively.
    pub async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = identity::sign_async(&self.store, self.account.handle(), msg)
            .await
            .map_err(js_err)?;
        Ok(sig.as_bytes().to_vec())
    }
}

/// Generate a new Ed25519 account under `hint` (the `@home-domain` routing hint,
/// `meridian_identity::validate_hint`'s rules apply), backed by a fresh `WebCryptoSecretStore`
/// (`meridian_identity::generate_account_async`, ADR 0028). `async fn`: wasm-bindgen generates a
/// Promise-returning JS binding for this natively. `wasm32`-gated — see [`WasmAccount`]'s doc
/// comment.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateAccount)]
pub async fn generate_account(hint: &str) -> Result<WasmAccount, JsError> {
    let store = identity::WebCryptoSecretStore::new();
    let account = identity::generate_account_async(&store, hint)
        .await
        .map_err(js_err)?;
    Ok(WasmAccount { account, store })
}

/// A thin, additive `#[wasm_bindgen]` marshaling wrapper around [`transport::BrowserTransport`]
/// (task 12.11) — added by task 12.13 step 2 (the TS adapter, `apps/web/src/lib/adapter.ts`) because
/// `BrowserTransport` itself carries **no** `#[wasm_bindgen]` surface at all: it is a plain Rust
/// `Transport` impl, reachable only from other Rust code (this crate's own `tests/browser_transport.rs`)
/// until now. Every method below is a 1:1 pass-through to the identical, already-implemented,
/// already-tested (12.11) `meridian_core::transport::Transport` trait method on the wrapped
/// `BrowserTransport` — no new negotiation/ICE/data-channel logic is added here, only value-type
/// marshaling (opaque core types like `SessionHandle`/`Sdp`/`IceCandidate` down to the
/// `u64`/`Uint8Array`/`String` primitives `#[wasm_bindgen]` can carry across the JS boundary).
/// Exists so the TS adapter's integration test can exercise a **real**
/// two-peer `RTCPeerConnection`/`RTCDataChannel` round trip end to end, in a genuine headless
/// browser — the transport substrate `sendChat`/`onMessage` would ride on, once a session/chat
/// orchestration layer (`meridian_core::chat::ChatState`, X3DH, the ratchet) is itself wired into
/// this crate's exported surface, which it is **not** yet (see `apps/web/src/lib/adapter.ts`'s own
/// module doc for the full gap report — that is explicitly out of this task's scope, not invented
/// here). Deliberately carries **zero** protocol/wire/crypto logic of its own: it never frames an
/// envelope, never touches a ratchet, and the bytes `send`/`recv` below move are whatever opaque
/// bytes the caller hands it — exactly `Transport`'s own "dumb pipe" contract
/// (`apps/transport/src/lib.rs`'s module doc).
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct WasmTransport(transport::BrowserTransport);

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmTransport {
    /// A fresh backend with no sessions yet — see [`transport::BrowserTransport::new`].
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmTransport {
        WasmTransport(transport::BrowserTransport::new())
    }

    /// `Transport::new_session` with a plain STUN-URL list (host + server-reflexive candidates
    /// only, no TURN relay/ephemeral-credential plumbing — out of this thin wrapper's scope).
    /// Returns the opaque session handle as a `u64`.
    #[wasm_bindgen(js_name = newSession)]
    pub async fn new_session(&self, stun_servers: Vec<String>) -> Result<u64, JsError> {
        use meridian_core::transport::{IceConfig, Transport};
        let cfg = IceConfig {
            stun_servers,
            ..IceConfig::default()
        };
        let handle = self.0.new_session(cfg).await.map_err(js_transport_err)?;
        Ok(handle.0)
    }

    /// `Transport::add_data_channel` with a reliable+ordered config (mirrors
    /// `ChannelCfg::reliable_ordered`, the shape `mrd.ctrl/1`/`mrd.chat/1` both use) under `label`.
    /// Returns the opaque channel id as a `u64`.
    #[wasm_bindgen(js_name = addDataChannel)]
    pub async fn add_data_channel(&self, session: u64, label: String) -> Result<u64, JsError> {
        use meridian_core::transport::{ChannelCfg, SessionHandle, Transport};
        let cid = self
            .0
            .add_data_channel(&SessionHandle(session), ChannelCfg::reliable_ordered(label))
            .await
            .map_err(js_transport_err)?;
        Ok(cid.0)
    }

    /// `Transport::local_description` — the raw SDP bytes.
    #[wasm_bindgen(js_name = localDescription)]
    pub fn local_description(&self, session: u64) -> Result<Vec<u8>, JsError> {
        use meridian_core::transport::{SessionHandle, Transport};
        let sdp = self
            .0
            .local_description(&SessionHandle(session))
            .map_err(js_transport_err)?;
        Ok(sdp.0)
    }

    /// `Transport::set_remote_description`.
    #[wasm_bindgen(js_name = setRemoteDescription)]
    pub async fn set_remote_description(&self, session: u64, sdp: Vec<u8>) -> Result<(), JsError> {
        use meridian_core::transport::{Sdp, SessionHandle, Transport};
        self.0
            .set_remote_description(&SessionHandle(session), Sdp(sdp))
            .await
            .map_err(js_transport_err)
    }

    /// `Transport::local_candidates`, flattened to plain SDP candidate strings.
    #[wasm_bindgen(js_name = localCandidates)]
    pub async fn local_candidates(&self, session: u64) -> Result<Vec<String>, JsError> {
        use meridian_core::transport::{SessionHandle, Transport};
        let candidates = self
            .0
            .local_candidates(&SessionHandle(session))
            .await
            .map_err(js_transport_err)?;
        Ok(candidates.into_iter().map(|c| c.0).collect())
    }

    /// `Transport::add_ice_candidate`.
    #[wasm_bindgen(js_name = addIceCandidate)]
    pub async fn add_ice_candidate(&self, session: u64, candidate: String) -> Result<(), JsError> {
        use meridian_core::transport::{IceCandidate, SessionHandle, Transport};
        self.0
            .add_ice_candidate(&SessionHandle(session), IceCandidate(candidate))
            .await
            .map_err(js_transport_err)
    }

    /// `Transport::send` — opaque bytes on `channel`. Carries no framing of its own (see this
    /// type's own doc comment).
    pub async fn send(&self, session: u64, channel: u64, data: Vec<u8>) -> Result<(), JsError> {
        use meridian_core::transport::{ChannelId, SessionHandle, Transport};
        self.0
            .send(&SessionHandle(session), &ChannelId(channel), &data)
            .await
            .map_err(js_transport_err)
    }

    /// `Transport::recv` — the next inbound `(channel, bytes)` frame on any of this session's data
    /// channels, or `undefined` once the session has closed. `channel`/`data` are returned as a
    /// two-element JS array (`[channel_id, bytes]`) rather than a bespoke class — this wrapper adds
    /// no new JS-visible type beyond what a caller can destructure directly.
    pub async fn recv(&self, session: u64) -> Result<JsValue, JsError> {
        use meridian_core::transport::{SessionHandle, Transport};
        let frame = self
            .0
            .recv(&SessionHandle(session))
            .await
            .map_err(js_transport_err)?;
        Ok(match frame {
            Some((cid, bytes)) => {
                let arr = Array::new();
                arr.push(&JsValue::from(cid.0));
                arr.push(&JsValue::from(Uint8Array::from(bytes.as_slice())));
                arr.into()
            }
            None => JsValue::UNDEFINED,
        })
    }

    /// `Transport::close`.
    pub async fn close(&self, session: u64) -> Result<(), JsError> {
        use meridian_core::transport::{SessionHandle, Transport};
        self.0
            .close(&SessionHandle(session))
            .await
            .map_err(js_transport_err)
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "wasm32")]
fn js_transport_err(e: meridian_core::transport::TransportError) -> JsError {
    JsError::new(&e.to_string())
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

    // Node is sufficient (see this module's doc) — no `run_in_browser` configure call. `verify`/
    // `safety_number` need no store at all, so this suite drives account creation directly through
    // `meridian_core::identity`'s synchronous `MemorySecretStore` path, not this crate's own (now
    // async, real-`crypto.subtle`-backed) `generate_account`/`WasmAccount::sign` — those move to
    // `tests/webcrypto_account.rs`'s real headless-Chromium suite (see this module's doc).

    /// A signed message plus the signer's raw public key, built via the plain, synchronous
    /// `meridian_core::identity` path (no wasm-bindgen surface, no WebCrypto) — enough to exercise
    /// [`verify`] without this crate's own async `generate_account`/`WasmAccount::sign`.
    fn signed(hint: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let store = identity::MemorySecretStore::new();
        let account = identity::generate_account(&store, hint).expect("generate_account");
        let sig = identity::sign(&store, account.handle(), msg).expect("sign");
        (
            account.public_key().as_bytes().to_vec(),
            sig.as_bytes().to_vec(),
        )
    }

    #[wasm_bindgen_test]
    fn verify_round_trips_and_rejects_tampering() {
        let msg = b"hello from meridian-wasm";
        let (public_key, sig) = signed("chat.example", msg);

        let ok = verify(&public_key, msg, &sig).expect("verify");
        assert!(ok);

        // A tampered message must not verify.
        let tampered = b"hello from meridian-wasn";
        let bad = verify(&public_key, tampered, &sig).expect("verify");
        assert!(!bad);
    }

    #[wasm_bindgen_test]
    fn safety_number_is_order_independent_and_60_digits() {
        let store = identity::MemorySecretStore::new();
        let a = identity::generate_account(&store, "a.example").expect("generate_account a");
        let b = identity::generate_account(&store, "b.example").expect("generate_account b");

        let ab = safety_number(a.public_key().as_bytes(), b.public_key().as_bytes())
            .expect("safety_number ab");
        let ba = safety_number(b.public_key().as_bytes(), a.public_key().as_bytes())
            .expect("safety_number ba");
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 60);
        assert!(ab.chars().all(|c| c.is_ascii_digit()));
    }
}
