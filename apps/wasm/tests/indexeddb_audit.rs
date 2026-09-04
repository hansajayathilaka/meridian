//! Browser-side at-rest audit (task 12.12 deliverable 3) — the IndexedDB counterpart to
//! `apps/tui/tests/at_rest_audit.rs` (task 4.27) and `apps/cli/src/opacity.rs`'s wire-envelope
//! audit (task 8.12's own precedent citation). Per ADR 0026 binding condition 4 (mirroring ADR 0021
//! condition 2 exactly), the unsealed `state`-equivalent IndexedDB record must never contain a
//! petname, message body, key material, or contact-identifying content (pubkey hex, `mrd1:`-prefixed
//! id) — only view geometry and an opaque, locally-generated conversation handle.
//!
//! ## Technique, mirrored from 4.27
//! `apps/tui/tests/at_rest_audit.rs::scan_for_leaks`/`contains` recursively scans every on-disk
//! *file's raw bytes* for a set of `(label, needle)` sentinel markers via a plain
//! `haystack.windows(needle.len()).any(|w| w == needle)` substring search — no JSON-aware parsing,
//! so it also catches a leak that only appears inside an escaped string or a re-encoded form. This
//! test applies the identical `contains`/scan primitive to the raw bytes IndexedDB actually holds
//! for the `state` object store's records ([`IndexedDbStore::get_state_raw`]), rather than to files
//! on disk (there is no filesystem in a browser sandbox). It also reproduces 4.27's own
//! "non-vacuity" check (found and required by that task's review): a deliberately-injected leak,
//! written via [`IndexedDbStore::put_state_raw`] (test-only, bypasses the typed `StateRecord` shape
//! on purpose), proves the scan primitive itself would catch a real leak rather than passing
//! vacuously.
//!
//! Needs real IndexedDB, unavailable in Node — run with `wasm-pack test --chrome --headless` (see
//! `apps/wasm/src/lib.rs`'s own module doc for why this crate's plain unit tests stay Node-only and
//! this lives in a separate integration-test binary instead).

use std::collections::BTreeMap;

use meridian_wasm::store::indexeddb::{Bucket, IndexedDbStore, StateRecord};
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

// ---------------------------------------------------------------------------
// Sentinels — every one of these must never appear in the unsealed `state` record's raw bytes.
// Mirrors `at_rest_audit.rs`'s own sentinel convention: one distinct, obviously-searchable marker
// per leak category, so a failure names exactly *which* value leaked.
// ---------------------------------------------------------------------------

const MARKER_PETNAME: &str = "SENTINEL-PETNAME-audit-bobby-9f1c2e";
const MARKER_BODY: &str = "SENTINEL-BODY-audit-hello-there-7a3d";
const MARKER_CONTACT_PUBKEY_HEX: &str =
    "5f2e1a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";
const MARKER_MRD1_ID: &str =
    "mrd1:5f2e1a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7@audit.example";
const MARKER_KEY_MATERIAL: [u8; 32] = [0xEE; 32];

fn markers() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("petname", MARKER_PETNAME.as_bytes().to_vec()),
        ("message body", MARKER_BODY.as_bytes().to_vec()),
        (
            "contact pubkey hex",
            MARKER_CONTACT_PUBKEY_HEX.as_bytes().to_vec(),
        ),
        ("mrd1: id", MARKER_MRD1_ID.as_bytes().to_vec()),
        ("key material", MARKER_KEY_MATERIAL.to_vec()),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn scan_for_leaks(bytes: &[u8], markers: &[(&str, Vec<u8>)]) -> Vec<String> {
    markers
        .iter()
        .filter(|(_, needle)| contains(bytes, needle))
        .map(|(label, _)| label.to_string())
        .collect()
}

async fn fresh_db(tag: &str) -> IndexedDbStore {
    let mut name_bytes = [0u8; 8];
    getrandom::fill(&mut name_bytes).expect("getrandom");
    let name = format!("meridian-audit-{tag}-{}", hex::encode(name_bytes));
    IndexedDbStore::open(&name).await.expect("open")
}

/// The real assertion: a realistic run — sealed buckets legitimately holding a petname, a message
/// body, a contact's pubkey/`mrd1:` id, and key material (all fine, since those buckets are
/// ciphertext at rest), plus an unsealed `state` record restricted to view geometry and an opaque
/// handle — must leave zero sentinel bytes anywhere in `state`'s raw, on-disk bytes.
#[wasm_bindgen_test]
async fn state_record_never_leaks_petname_body_key_or_contact_identity() {
    let db = fresh_db("clean").await;

    // Sealed buckets legitimately carry the sensitive content — this is what at-rest sealing is
    // for. Not what this test scans (that's the `at_rest`-level guarantee `apps/crypto/tests/at_rest.rs`
    // and `apps/store/src/webcrypto.rs`'s own tests already cover); included here only so a real,
    // realistic account state exists alongside the `state` record under audit.
    let secret_store = meridian_core::store::WebCryptoSecretStore::new();
    let handle = secret_store
        .store("acct", &[3u8; 32])
        .await
        .expect("store seed");
    db.put_sealed(
        &secret_store,
        &handle,
        Bucket::Contacts,
        "peer1",
        serde_json::json!({
            "petname": MARKER_PETNAME,
            "pubkey_hex": MARKER_CONTACT_PUBKEY_HEX,
            "id": MARKER_MRD1_ID,
        }),
    )
    .await
    .expect("put_sealed contacts");
    db.put_sealed(
        &secret_store,
        &handle,
        Bucket::History,
        "msg1",
        serde_json::json!({ "body": MARKER_BODY }),
    )
    .await
    .expect("put_sealed history");
    db.put_sealed(
        &secret_store,
        &handle,
        Bucket::Identity,
        "keys",
        serde_json::json!({ "key_material_hex": hex::encode(MARKER_KEY_MATERIAL) }),
    )
    .await
    .expect("put_sealed identity");

    // The one thing under audit: `state` restricted to view geometry + an opaque handle only —
    // never the petname, body, pubkey, id, or raw key bytes above.
    let mut view = BTreeMap::new();
    view.insert("sidebar_width".to_string(), 24.0);
    view.insert("chat_pane_ratio".to_string(), 0.7);
    let record = StateRecord {
        view,
        open_conversation_handle: Some("opaque-handle-not-identifying-4f9a".to_string()),
    };
    db.put_state("ui", &record).await.expect("put_state");

    let raw = db
        .get_state_raw("ui")
        .await
        .expect("get_state_raw")
        .expect("state record present");

    let violations = scan_for_leaks(&raw, &markers());
    assert!(
        violations.is_empty(),
        "state record leaked: {violations:?} — ADR 0026 binding condition 4 / ADR 0021 condition 2 \
         violation, this is a security defect to fix in the store, never a reason to loosen this scan"
    );
}

/// Non-vacuity check (mirrors 4.27's review-mandated addition): prove the scan primitive itself
/// would catch a real leak, by deliberately injecting one via [`IndexedDbStore::put_state_raw`]
/// (bypassing `StateRecord`'s typed, content-restricted shape on purpose — never how real
/// application code writes to `state`).
#[wasm_bindgen_test]
async fn scan_primitive_catches_an_injected_leak() {
    let db = fresh_db("non-vacuity").await;

    let leaking_bytes = format!(r#"{{"v":1,"data":{{"note":"{MARKER_PETNAME}"}}}}"#).into_bytes();
    db.put_state_raw("ui", &leaking_bytes)
        .await
        .expect("put_state_raw");

    let raw = db
        .get_state_raw("ui")
        .await
        .expect("get_state_raw")
        .expect("state record present");

    let violations = scan_for_leaks(&raw, &markers());
    assert_eq!(
        violations,
        vec!["petname".to_string()],
        "the scan primitive must actually detect an injected leak, not pass vacuously"
    );
}
