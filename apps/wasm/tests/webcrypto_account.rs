//! Real-browser coverage for [`meridian_wasm::generate_account`]/[`meridian_wasm::WasmAccount::sign`]
//! (task 12.13 step 1, ADR 0028) — the async, `WebCryptoSecretStore`-backed replacement for the
//! task 12.10 `MemorySecretStore` stubs.
//!
//! Needs real `crypto.subtle`, not guaranteed available (or, even where present, not exercising the
//! genuine non-extractable-`CryptoKey` enforcement `apps/store/src/webcrypto.rs`'s own tests rely
//! on a real engine for) under Node — run with `wasm-pack test --chrome --headless` (see
//! `apps/wasm/src/lib.rs`'s own module doc for why this crate's plain unit tests stay Node-only and
//! this lives in a separate integration-test binary instead, same precedent as
//! `tests/browser_transport.rs`/`tests/indexeddb_audit.rs`).

use meridian_wasm::{generate_account, safety_number, verify};
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn generate_sign_verify_round_trip() {
    let account = generate_account("chat.example")
        .await
        .expect("generate_account");
    let msg = b"hello from meridian-wasm";
    let sig = account.sign(msg).await.expect("sign");
    let ok = verify(&account.public_key(), msg, &sig).expect("verify");
    assert!(ok, "a genuine signature must verify");

    // A tampered message must not verify.
    let tampered = b"hello from meridian-wasn";
    let bad = verify(&account.public_key(), tampered, &sig).expect("verify");
    assert!(!bad, "a tampered message must not verify");
}

#[wasm_bindgen_test]
async fn two_accounts_produce_distinct_keys_and_non_interchangeable_signatures() {
    let a = generate_account("a.example")
        .await
        .expect("generate_account a");
    let b = generate_account("b.example")
        .await
        .expect("generate_account b");
    assert_ne!(
        a.public_key(),
        b.public_key(),
        "two freshly generated accounts must not share a public key"
    );

    let msg = b"cross-account signature must not verify";
    let sig_a = a.sign(msg).await.expect("sign a");
    // `a`'s signature must not verify under `b`'s public key.
    assert!(!verify(&b.public_key(), msg, &sig_a).expect("verify"));
}

#[wasm_bindgen_test]
async fn safety_number_is_order_independent_and_60_digits() {
    let a = generate_account("a.example")
        .await
        .expect("generate_account a");
    let b = generate_account("b.example")
        .await
        .expect("generate_account b");

    let ab = safety_number(&a.public_key(), &b.public_key()).expect("safety_number ab");
    let ba = safety_number(&b.public_key(), &a.public_key()).expect("safety_number ba");
    assert_eq!(ab, ba);
    assert_eq!(ab.len(), 60);
    assert!(ab.chars().all(|c| c.is_ascii_digit()));
}

#[wasm_bindgen_test]
async fn account_id_carries_the_requested_hint() {
    let account = generate_account("chat.example")
        .await
        .expect("generate_account");
    assert!(
        account.id().ends_with("@chat.example"),
        "id() must carry the hint this account was generated under: {}",
        account.id()
    );
}
