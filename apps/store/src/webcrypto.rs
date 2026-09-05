//! `WebCrypto`-backed non-extractable secret store (browser only) — ADR 0026 binding condition 1.
//!
//! `store()` imports the given raw account seed as one or more non-extractable `CryptoKey`s via
//! `SubtleCrypto.importKey('raw', ..., extractable: false, ...)` and discards every local
//! reference to the raw bytes immediately afterward — no code path in this module may export or
//! log the raw seed after import. [`WebCryptoSecretStore::use_key`] computes signing/DH results
//! via `crypto.subtle`'s non-extractable-key operations, returning only the computed output —
//! never the key itself. [`WebCryptoSecretStore::derive_key`] computes a domain-separated
//! HKDF-Expand output via `crypto.subtle`'s `deriveBits`; that output is, deliberately per ADR
//! 0026, the *only* extractable byte material this store ever produces (used as a per-purpose
//! at-rest sealing key by a later task, never persisted by this one). This is the first
//! `SecretStore` impl in the tree that can honestly report `nonextractable() == true`.
//!
//! Because a single Ed25519 seed can only back one WebCrypto algorithm per imported `CryptoKey`
//! (`SubtleCrypto` binds a key to the algorithm it was imported for), [`WebCryptoSecretStore::store`]
//! performs three non-extractable imports from the one raw seed instead of one: `{name:
//! "Ed25519"}` for [`SignOrDh::Sign`], `{name: "X25519"}` for [`SignOrDh::Dh`] (imported from the
//! seed's birationally-equivalent X25519 scalar, computed via `crypto.subtle.digest("SHA-512",
//! ...)` — the same construction [`crate::ed25519_seed_to_x25519_dh`] uses natively, just computed
//! through WebCrypto instead of `sha2` so the conversion input never leaves `crypto.subtle`'s
//! world before the X25519 key is locked away non-extractable), and `{name: "HKDF"}` for
//! [`WebCryptoSecretStore::derive_key`]. All three imports happen once, at `store()` time; the raw
//! seed and the SHA-512 intermediate are both local temporaries that go out of scope at the end of
//! `store()`, leaving only non-extractable `CryptoKey` handles alive.
//!
//! ## `TODO: confirm` — `SecretStore`'s synchronous signature vs. `crypto.subtle`'s async-only API
//!
//! Every `SubtleCrypto` operation (`importKey`, `sign`, `deriveBits`, `digest`, ...) returns a
//! `Promise` — by spec, unconditionally, precisely so implementations may dispatch to hardware or
//! an out-of-process enclave. `SecretStore` (`docs/api/core-api-contracts.md`) is synchronous:
//! `fn store(&self, ...) -> Result<KeyHandle>`, not `async fn`. On a single-threaded JS/WASM
//! target with no `SharedArrayBuffer`/`Atomics.wait` bridge (which itself would need a dedicated
//! worker plus cross-origin-isolation `COOP`/`COEP` deployment headers — infrastructure named
//! nowhere in ADR 0026, this task, or `stack.md`) or Binaryen `--asyncify` post-processing (also
//! unmentioned anywhere), there is no way to block a synchronous Rust call on an in-flight
//! `Promise` without hanging the calling thread forever — the `Promise` can only settle once
//! control returns to the JS event loop, which a still-executing synchronous call never does.
//! Spinning on `wasm_bindgen_futures::JsFuture` from a non-async fn (e.g. via a naive
//! `futures::executor::block_on`) does not "block" on this target; `std::thread::park` here
//! returns immediately (there is no real thread to park), so the poll loop busy-spins without
//! ever yielding to JS, and the `Promise` never resolves — this was verified by inspection of the
//! target's behavior rather than assumed, per this task's own "verify, don't assume" instruction.
//!
//! ADR 0026 states this impl is achievable "with zero trait changes," reasoning only about the
//! *shape* of `use_key`/`derive_key`'s return values (computed output, not raw key material), not
//! about this sync/async plumbing gap. Rather than ship a version that either hangs the calling
//! thread or silently fabricates a result, `impl SecretStore for WebCryptoSecretStore`'s three
//! secret-touching methods below are honest: they type-check and satisfy the trait object (so
//! `WebCryptoSecretStore` is usable anywhere a `&dyn SecretStore` is expected, e.g. for
//! `nonextractable()` diagnostics), but return a clear [`StoreError::Backend`] rather than
//! hang or lie. The **real** implementation lives on inherent `async fn`s of the same names
//! (`WebCryptoSecretStore::store`/`use_key`/`derive_key`/`nonextractable`) — Rust resolves
//! `store_instance.store(...)` to these (inherent methods take priority over trait methods in
//! method-call syntax), so direct callers naturally get the working async path, while generic
//! `S: SecretStore`/`&dyn SecretStore` callers get the honest error. These are not new operations
//! beyond the trait's surface — same three names, same inputs/outputs, only `async` — so this
//! does not expand what this store can do, only how it must be called on this target. Flagged
//! back for an architect decision (an async `SecretStore` companion trait for `wasm32`, or an
//! accepted worker+Atomics bridge design) rather than invented silently here.

use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::{Array, ArrayBuffer, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, EcdhKeyDeriveParams, HkdfParams, SubtleCrypto};

use crate::{
    AsyncSecretStore, KeyHandle, Result, SecretStore, SignOrDh, StoreError, DERIVE_KEY_SALT,
    ED25519_SEED_LEN,
};

/// The three non-extractable `CryptoKey`s imported from one account seed at `store()` time — one
/// per WebCrypto algorithm this store ever performs an operation with. See the module docs.
struct KeySet {
    /// `{name: "Ed25519"}`, usages `["sign"]`.
    sign: CryptoKey,
    /// `{name: "X25519"}`, usages `["deriveBits"]`.
    dh: CryptoKey,
    /// `{name: "HKDF"}`, usages `["deriveBits"]`.
    hkdf: CryptoKey,
}

/// A browser-only [`SecretStore`] backed by non-extractable `crypto.subtle` `CryptoKey`s (ADR
/// 0026). One process-local instance holds every account key imported into it for the lifetime of
/// the page/worker; persistence across a reload is IndexedDB's job (task 12.12), out of this
/// task's scope.
pub struct WebCryptoSecretStore {
    keys: RefCell<HashMap<String, KeySet>>,
}

impl Default for WebCryptoSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WebCryptoSecretStore {
    /// A store with no keys imported yet.
    pub fn new() -> Self {
        Self {
            keys: RefCell::new(HashMap::new()),
        }
    }

    /// The real, async implementation backing [`SecretStore::store`] (see module docs for why the
    /// trait's synchronous method can't do this work itself on this target). Imports `secret`
    /// (a 32-byte Ed25519 seed) as three non-extractable `CryptoKey`s and discards every local
    /// reference to the raw bytes — and the transient SHA-512 X25519-conversion intermediate —
    /// once import completes.
    pub async fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle> {
        if secret.len() != ED25519_SEED_LEN {
            return Err(StoreError::BadSecretLength {
                expected: ED25519_SEED_LEN,
                got: secret.len(),
            });
        }
        let subtle = subtle_crypto()?;

        let sign =
            import_pkcs8_okp_key(&subtle, &PKCS8_ED25519_PREFIX, secret, "Ed25519", &["sign"])
                .await?;
        let dh = import_x25519_dh_key(&subtle, secret).await?;
        let hkdf = import_raw_key(&subtle, secret, "HKDF", &["deriveBits"]).await?;
        // `secret` (the caller's slice) and every intermediate byte buffer above are local to
        // this function and go out of scope here — only the three non-extractable `CryptoKey`
        // handles below survive past this point.

        self.keys
            .borrow_mut()
            .insert(label.to_string(), KeySet { sign, dh, hkdf });
        Ok(KeyHandle {
            label: label.to_string(),
        })
    }

    /// The real, async implementation backing [`SecretStore::use_key`]. Computes the requested
    /// operation via `crypto.subtle`'s non-extractable-key APIs (`sign`/`deriveBits`), returning
    /// only the computed output bytes — the underlying `CryptoKey` never leaves this module.
    pub async fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
        let subtle = subtle_crypto()?;
        let key = self.key_for(h, op)?;
        match op {
            SignOrDh::Sign => {
                let promise = subtle
                    .sign_with_str_and_u8_array("Ed25519", &key, input)
                    .map_err(js_err)?;
                let sig = JsFuture::from(promise).await.map_err(js_err)?;
                Ok(as_bytes(sig))
            }
            SignOrDh::Dh => {
                // `input` is the peer's raw 32-byte X25519 public key (trait contract). Public
                // keys carry no secrecy, but are imported non-extractable anyway for uniformity;
                // no usages are needed on a public key beyond serving as `deriveBits`'s `public`
                // parameter.
                let peer = import_raw_key(&subtle, input, "X25519", &[]).await?;
                let params = EcdhKeyDeriveParams::new("X25519", &peer);
                let promise = subtle
                    .derive_bits_with_object(&params, &key, 256)
                    .map_err(js_err)?;
                let shared = JsFuture::from(promise).await.map_err(js_err)?;
                Ok(as_bytes(shared))
            }
        }
    }

    /// The real, async implementation backing [`SecretStore::derive_key`]. Computes
    /// HKDF-SHA256-Expand(salt=0, ikm=seed, info) via `crypto.subtle.deriveBits`, mirroring
    /// [`crate::derive_key_from_seed`]'s construction exactly (same zero salt, same `info`
    /// domain separation) but performed entirely inside `crypto.subtle`. Per ADR 0026 this output
    /// is deliberately extractable raw bytes — the base account key above stays non-extractable
    /// throughout; only this derived, per-purpose value is ever raw WASM memory.
    pub async fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]> {
        let subtle = subtle_crypto()?;
        let key = {
            let keys = self.keys.borrow();
            keys.get(h.label())
                .ok_or_else(|| StoreError::NotFound(h.label().to_string()))?
                .hkdf
                .clone()
        };
        let salt = Uint8Array::from(DERIVE_KEY_SALT.as_slice());
        let info_arr = Uint8Array::from(info);
        let params = HkdfParams::new_with_str("HKDF", "SHA-256", &info_arr, &salt);
        let promise = subtle
            .derive_bits_with_object(&params, &key, 256)
            .map_err(js_err)?;
        let bits = JsFuture::from(promise).await.map_err(js_err)?;
        let bytes = as_bytes(bits);
        bytes.try_into().map_err(|_| {
            StoreError::Backend("crypto.subtle deriveBits returned unexpected length".into())
        })
    }

    /// Non-extractable keys are this store's whole point — always `true`.
    pub fn nonextractable(&self) -> bool {
        true
    }

    fn key_for(&self, h: &KeyHandle, op: SignOrDh) -> Result<CryptoKey> {
        let keys = self.keys.borrow();
        let set = keys
            .get(h.label())
            .ok_or_else(|| StoreError::NotFound(h.label().to_string()))?;
        Ok(match op {
            SignOrDh::Sign => set.sign.clone(),
            SignOrDh::Dh => set.dh.clone(),
        })
    }
}

impl SecretStore for WebCryptoSecretStore {
    fn store(&self, _label: &str, _secret: &[u8]) -> Result<KeyHandle> {
        Err(sync_bridge_unavailable())
    }

    fn use_key(&self, _h: &KeyHandle, _op: SignOrDh, _input: &[u8]) -> Result<Vec<u8>> {
        Err(sync_bridge_unavailable())
    }

    fn nonextractable(&self) -> bool {
        true
    }

    fn derive_key(&self, _h: &KeyHandle, _info: &[u8]) -> Result<[u8; 32]> {
        Err(sync_bridge_unavailable())
    }
}

/// ADR 0028: the real, working async view of this store. Each method here delegates straight to
/// the inherent `async fn` of the same name above — Rust resolves the `self.store(...)` etc. calls
/// below to those inherent methods (inherent methods take priority over trait methods in
/// method-call syntax), so this impl is deliberately a one-line-per-method forwarder, never a
/// second implementation of the WebCrypto logic itself.
impl AsyncSecretStore for WebCryptoSecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle> {
        self.store(label, secret).await
    }

    async fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>> {
        self.use_key(h, op, input).await
    }

    fn nonextractable(&self) -> bool {
        self.nonextractable()
    }

    async fn derive_key(&self, h: &KeyHandle, info: &[u8]) -> Result<[u8; 32]> {
        self.derive_key(h, info).await
    }
}

/// See the module docs' `TODO: confirm` section — the synchronous `SecretStore` trait cannot
/// genuinely bridge to `crypto.subtle`'s async-only API on this target. Call
/// `WebCryptoSecretStore::store`/`use_key`/`derive_key` (the inherent `async fn`s) directly
/// instead of going through `&dyn SecretStore`.
fn sync_bridge_unavailable() -> StoreError {
    StoreError::Backend(
        "WebCryptoSecretStore has no synchronous bridge to crypto.subtle (async-only by spec); \
         call the inherent async store/use_key/derive_key methods directly, not the SecretStore \
         trait object — see apps/store/src/webcrypto.rs module docs"
            .into(),
    )
}

/// Import `raw` as a non-extractable `CryptoKey` for `alg` via WebCrypto's `"raw"` format,
/// restricted to `usages`. Per the Web Crypto "Secure Curves" spec, `"raw"` format for an OKP
/// algorithm (`Ed25519`/`X25519`) only accepts a *public* key (hence this is only ever called
/// with an empty/`"verify"`-shaped usage list for those two, and with `"HKDF"`, whose raw format
/// is the actual symmetric key bytes). Never returns anything but the opaque `CryptoKey` handle.
async fn import_raw_key(
    subtle: &SubtleCrypto,
    raw: &[u8],
    alg: &str,
    usages: &[&str],
) -> Result<CryptoKey> {
    let data = Uint8Array::from(raw);
    let usages = str_array(usages);
    let promise = subtle
        .import_key_with_str("raw", &data, alg, false, &usages)
        .map_err(js_err)?;
    let key = JsFuture::from(promise).await.map_err(js_err)?;
    Ok(key.unchecked_into())
}

/// RFC 8410 §7's fixed, content-free PKCS#8 `OneAsymmetricKey` DER prefix for an Ed25519 private
/// key: `SEQUENCE { version=0, AlgorithmIdentifier{OID 1.3.101.112}, OCTET STRING(OCTET
/// STRING(seed)) }` up to (not including) the 32 raw seed bytes. This is a fixed structural
/// template with zero cryptographic content — required because the Web Crypto "Secure Curves"
/// spec's `"raw"` import format for OKP algorithms only accepts public keys; private/signing keys
/// must be wrapped in this minimal PKCS#8 envelope to import via `SubtleCrypto.importKey`.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// As [`PKCS8_ED25519_PREFIX`], but for X25519 (OID 1.3.101.110) private-key import.
const PKCS8_X25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// Import a 32-byte OKP (Ed25519/X25519) private-key scalar as a non-extractable `CryptoKey`,
/// wrapping it in the fixed PKCS#8 `prefix` first (see [`PKCS8_ED25519_PREFIX`]). The assembled
/// DER buffer — which briefly holds the raw private scalar — is zeroized and dropped once the
/// import completes; only the opaque `CryptoKey` handle survives.
async fn import_pkcs8_okp_key(
    subtle: &SubtleCrypto,
    prefix: &[u8; 16],
    raw: &[u8],
    alg: &str,
    usages: &[&str],
) -> Result<CryptoKey> {
    let mut der = zeroize::Zeroizing::new(Vec::with_capacity(prefix.len() + raw.len()));
    der.extend_from_slice(prefix);
    der.extend_from_slice(raw);

    let data = Uint8Array::from(der.as_slice());
    let usages = str_array(usages);
    let promise = subtle
        .import_key_with_str("pkcs8", &data, alg, false, &usages)
        .map_err(js_err)?;
    let key = JsFuture::from(promise).await.map_err(js_err)?;
    Ok(key.unchecked_into())
}

/// Derive the X25519 scalar birationally equivalent to Ed25519 `seed`
/// (`clamp(SHA-512(seed)[..32])`, libsodium's `crypto_sign_ed25519_sk_to_curve25519` — the same
/// construction as [`crate::ed25519_seed_to_x25519_dh`]) via `crypto.subtle.digest`, then import
/// it (PKCS#8-wrapped, see [`import_pkcs8_okp_key`]) as a non-extractable `{name: "X25519"}` key.
/// The digest result and the clamped scalar are both local temporaries zeroized/dropped once the
/// import completes.
async fn import_x25519_dh_key(subtle: &SubtleCrypto, seed: &[u8]) -> Result<CryptoKey> {
    let promise = subtle
        .digest_with_str_and_u8_array("SHA-512", seed)
        .map_err(js_err)?;
    let digest = JsFuture::from(promise).await.map_err(js_err)?;
    let digest = zeroize::Zeroizing::new(as_bytes(digest));

    let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&digest[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    import_pkcs8_okp_key(
        subtle,
        &PKCS8_X25519_PREFIX,
        scalar.as_slice(),
        "X25519",
        &["deriveBits"],
    )
    .await
}

/// `js_sys::global().crypto.subtle` — works uniformly in a window, a worker, or Node (all expose
/// `globalThis.crypto`), so this module never needs `web_sys::Window`/`WorkerGlobalScope`.
fn subtle_crypto() -> Result<SubtleCrypto> {
    let global = js_sys::global();
    let crypto = js_sys::Reflect::get(&global, &JsValue::from_str("crypto")).map_err(js_err)?;
    if crypto.is_undefined() || crypto.is_null() {
        return Err(StoreError::Backend(
            "no `crypto` global in this JS context".into(),
        ));
    }
    let crypto: web_sys::Crypto = crypto.unchecked_into();
    Ok(crypto.subtle())
}

fn str_array(items: &[&str]) -> JsValue {
    let arr = Array::new();
    for s in items {
        arr.push(&JsValue::from_str(s));
    }
    arr.into()
}

/// `crypto.subtle`'s byte-returning operations resolve their `Promise` with an `ArrayBuffer`.
fn as_bytes(v: JsValue) -> Vec<u8> {
    let buf: ArrayBuffer = v.unchecked_into();
    Uint8Array::new(&buf).to_vec()
}

/// Coarse, non-leaking error mapping from a rejected `Promise`/thrown `JsValue` — mirrors
/// [`StoreError`]'s existing "don't hand callers an oracle" philosophy (`error.rs`).
fn js_err(e: JsValue) -> StoreError {
    StoreError::Backend(format!("{e:?}"))
}

// SAFETY: `wasm32-unknown-unknown` has no real OS threads on this crate's target — `std::thread`
// spawn on it is not supported at all — so nothing can ever actually move a `WebCryptoSecretStore`
// (or the `CryptoKey`/`JsValue` handles inside it) across a genuine thread boundary; wasm-bindgen's
// JS-object wrapper types are `!Send + !Sync` in general (they're tied to one JS realm, which
// matters on true multi-threaded wasm+`SharedArrayBuffer` builds) but that constraint is vacuous
// here. `Send + Sync` is required by `SecretStore`'s frozen signature
// (`docs/api/core-api-contracts.md`) for every impl uniformly, native and browser alike; asserting
// it this way — rather than dropping the bound — is the standard, accepted pattern for wrapping
// `wasm-bindgen` handles on this single-threaded target.
unsafe impl Send for WebCryptoSecretStore {}
unsafe impl Sync for WebCryptoSecretStore {}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn seed(byte: u8) -> [u8; ED25519_SEED_LEN] {
        [byte; ED25519_SEED_LEN]
    }

    #[wasm_bindgen_test]
    async fn store_then_sign_round_trips() {
        let store = WebCryptoSecretStore::new();
        let h = store.store("acct", &seed(7)).await.expect("store");
        let sig = store
            .use_key(&h, SignOrDh::Sign, b"hello meridian")
            .await
            .expect("sign");
        assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
    }

    #[wasm_bindgen_test]
    async fn store_then_dh_round_trips_and_is_symmetric() {
        let store = WebCryptoSecretStore::new();
        let ha = store.store("a", &seed(1)).await.expect("store a");
        let hb = store.store("b", &seed(2)).await.expect("store b");

        // Recover each side's raw X25519 public key the same way the wire format does natively
        // (Ed25519 verifying key -> Montgomery form) so this test can assert the shared secret is
        // symmetric without depending on any un-scoped IndexedDB/identity crate.
        let pub_a = ed25519_dalek::SigningKey::from_bytes(&seed(1))
            .verifying_key()
            .to_montgomery()
            .to_bytes();
        let pub_b = ed25519_dalek::SigningKey::from_bytes(&seed(2))
            .verifying_key()
            .to_montgomery()
            .to_bytes();

        let shared_a = store
            .use_key(&ha, SignOrDh::Dh, &pub_b)
            .await
            .expect("dh a");
        let shared_b = store
            .use_key(&hb, SignOrDh::Dh, &pub_a)
            .await
            .expect("dh b");
        assert_eq!(shared_a, shared_b, "DH must be symmetric");
        assert_eq!(shared_a.len(), 32);
    }

    #[wasm_bindgen_test]
    async fn derive_key_round_trips_and_is_domain_separated() {
        let store = WebCryptoSecretStore::new();
        let h = store.store("acct", &seed(9)).await.expect("store");

        let k1 = store
            .derive_key(&h, b"purpose-one")
            .await
            .expect("derive 1");
        let k1_again = store
            .derive_key(&h, b"purpose-one")
            .await
            .expect("derive 1 again");
        let k2 = store
            .derive_key(&h, b"purpose-two")
            .await
            .expect("derive 2");

        assert_eq!(k1, k1_again, "same info must derive the same key");
        assert_ne!(k1, k2, "different info must derive different keys");
    }

    #[wasm_bindgen_test]
    fn nonextractable_reports_true() {
        let store = WebCryptoSecretStore::new();
        assert!(store.nonextractable());
        assert!(SecretStore::nonextractable(&store));
    }

    #[wasm_bindgen_test]
    async fn sync_trait_methods_are_honest_not_hanging() {
        // The `dyn SecretStore` sync surface must never silently succeed with fabricated data,
        // and must never hang the calling thread — see the module docs' `TODO: confirm`. All
        // three trait methods share the same `sync_bridge_unavailable()` implementation, so
        // exercise all three through dyn dispatch, not just `store`.
        let store = WebCryptoSecretStore::new();
        let dyn_store: &dyn SecretStore = &store;
        let h = KeyHandle::from_label("x");

        assert!(dyn_store.store("x", &seed(1)).is_err());
        assert!(dyn_store.use_key(&h, SignOrDh::Sign, b"hello").is_err());
        assert!(dyn_store.derive_key(&h, b"info").is_err());
    }

    /// Deliverable 4: the raw seed must never be recoverable as an extractable `CryptoKey`.
    /// Attempts `crypto.subtle.exportKey('raw', key)` against each of the three `CryptoKey`s a
    /// real `store()` call imports, and asserts every one rejects (per the Web Crypto spec, an
    /// `exportKey` call against a non-extractable key rejects its Promise with
    /// `InvalidAccessError` — this only proves something if the underlying engine truly enforces
    /// `extractable: false`, which real Web Crypto implementations (this test runs against a real
    /// headless browser, not a JS-level polyfill) do.
    #[wasm_bindgen_test]
    async fn stored_keys_are_never_extractable() {
        let store = WebCryptoSecretStore::new();
        let h = store.store("acct", &seed(3)).await.expect("store");
        let subtle = subtle_crypto().expect("subtle");

        let keys = {
            let map = store.keys.borrow();
            let set = map.get(h.label()).expect("key set present");
            (set.sign.clone(), set.dh.clone(), set.hkdf.clone())
        };

        for (name, key) in [("sign", keys.0), ("dh", keys.1), ("hkdf", keys.2)] {
            let promise = subtle
                .export_key("raw", &key)
                .expect("export_key call itself");
            let result = JsFuture::from(promise).await;
            assert!(
                result.is_err(),
                "{name} key must not be exportable (extractable must be false)"
            );
        }
    }
}
