//! `meridian_tui::store` — task 4.15's own test target (`cargo nextest run -p meridian-tui --test
//! store`). Sealed round-trip for each sealed file, `state.json`'s structural no-prohibited-fields
//! test, forward migration + `.bak` plumbing against a synthetic schema, and refuse-to-open on a
//! fabricated newer-version fixture for every file type.
//!
//! Each test builds its own `MemorySecretStore` + generated account and drives the `_at`/explicit-
//! path entry points, so no test touches `$MERIDIAN_HOME` or shares state with any other test.

use meridian_core::crypto::at_rest;
use meridian_core::identity::{generate_account, KeyHandle, MemorySecretStore, SecretStore};
use meridian_tui::store::{
    contacts::{ContactRecord, ContactsDocument, PinnedKeyRecord, TrustLabel},
    history::{Direction, HistoryEntry, MessageState},
    migrate::{migrate_forward, MigrationStep, StoreError},
    outbox::{OutboxDocument, OutboxEntry},
    state::{PaneGeometry, ScrollState, StateDocument},
    {bak_path, read_plain_migrating, read_sealed_migrating, write_plain, write_sealed},
};

/// A store + account pair, fresh per test.
fn fresh_account() -> (MemorySecretStore, KeyHandle) {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "tui-store-test.example").expect("generate_account");
    let handle = account.handle().clone();
    (store, handle)
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    // Leak the tempdir so the path stays valid for the rest of the test — fine for a short-lived
    // test process.
    let path = dir.path().join(name);
    std::mem::forget(dir);
    path
}

// ---------------------------------------------------------------------------------------------
// contacts.json
// ---------------------------------------------------------------------------------------------

fn sample_contacts_doc() -> ContactsDocument {
    ContactsDocument {
        v: 1,
        contacts: vec![ContactRecord {
            pubkey: "3f9a".repeat(16),
            id: "mrd1:3f9a...@org-b.test".to_string(),
            hint: "org-b.test".to_string(),
            petname: Some("bob".to_string()),
            trust: TrustLabel::Pinned,
            pinned_key_history: vec![PinnedKeyRecord {
                pubkey: "3f9a".repeat(16),
                first_seen: 1_762_934_400,
                last_seen: 1_763_020_800,
            }],
            device_record_version_seen: None,
            policy_override: None,
            added_at: 1_762_934_400,
            last_activity_at: 1_763_020_800,
            unread: 0,
            conv_handle: Some([0x11; 16]),
        }],
    }
}

#[test]
fn contacts_sealed_round_trip() {
    let (store, handle) = fresh_account();
    let path = tmp_path("contacts.json");
    let doc = sample_contacts_doc();

    meridian_tui::store::contacts::save_at(&path, &doc, &store, &handle).expect("save");
    // On disk, this must not be plaintext JSON.
    let raw = std::fs::read(&path).expect("read raw");
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());

    let reopened =
        meridian_tui::store::contacts::load_or_default_at(&path, &store, &handle).expect("open");
    assert_eq!(reopened, doc);
}

#[test]
fn contacts_missing_file_yields_empty_default_not_an_error() {
    let (store, handle) = fresh_account();
    let path = tmp_path("does-not-exist/contacts.json");
    let doc =
        meridian_tui::store::contacts::load_or_default_at(&path, &store, &handle).expect("default");
    assert_eq!(doc.v, 1);
    assert!(doc.contacts.is_empty());
}

#[test]
fn contacts_sealed_blob_fails_closed_under_wrong_key() {
    let (store, handle) = fresh_account();
    let (other_store, other_handle) = fresh_account();
    let path = tmp_path("contacts.json");

    meridian_tui::store::contacts::save_at(&path, &sample_contacts_doc(), &store, &handle)
        .expect("save");

    let err = meridian_tui::store::contacts::load_or_default_at(&path, &other_store, &other_handle)
        .expect_err("wrong key must fail closed, never fall back to an empty store");
    assert!(matches!(
        err,
        StoreError::Crypto(_) | StoreError::SealFailure { .. }
    ));
}

#[test]
fn contacts_tampered_sealed_blob_fails_closed() {
    let (store, handle) = fresh_account();
    let path = tmp_path("contacts.json");
    meridian_tui::store::contacts::save_at(&path, &sample_contacts_doc(), &store, &handle)
        .expect("save");

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let err = meridian_tui::store::contacts::load_or_default_at(&path, &store, &handle)
        .expect_err("tampered blob must fail closed, never silently reinitialize");
    assert!(matches!(err, StoreError::SealFailure { .. }));
}

#[test]
fn contacts_refuses_a_fabricated_newer_schema_version() {
    let (store, handle) = fresh_account();
    let path = tmp_path("contacts.json");

    let key = store
        .derive_key(&handle, at_rest::STORE_KEY_INFO)
        .expect("derive key");
    let fabricated = serde_json::json!({ "v": 2, "contacts": [] });
    let sealed = at_rest::seal(&key, &serde_json::to_vec(&fabricated).unwrap()).unwrap();
    std::fs::write(&path, sealed).unwrap();

    let err = meridian_tui::store::contacts::load_or_default_at(&path, &store, &handle)
        .expect_err("a newer schema than understood must be a hard, named error");
    match err {
        StoreError::NewerSchema {
            found, understood, ..
        } => {
            assert_eq!(found, 2);
            assert_eq!(understood, 1);
        }
        other => panic!("expected NewerSchema, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// history/<peer>.jsonl
// ---------------------------------------------------------------------------------------------

fn sample_entry(mid: &str, dir: Direction, state: MessageState) -> HistoryEntry {
    HistoryEntry {
        v: 1,
        mid: mid.to_string(),
        dir,
        ts: 1_763_020_800,
        stream: "mrd.chat/1".to_string(),
        body: "pushed the branch".to_string(),
        state,
    }
}

/// A stand-in 64-lowercase-hex peer pubkey, same shape as `contacts.json`'s `pubkey` field, used
/// to exercise `history.rs`'s peer-binding header/verification.
fn peer_hex(byte: u8) -> String {
    hex_byte(byte).repeat(32)
}

fn hex_byte(byte: u8) -> String {
    format!("{byte:02x}")
}

#[test]
fn history_sealed_round_trip_preserves_order() {
    let (store, handle) = fresh_account();
    let path = tmp_path("history/peer.jsonl");
    let peer = peer_hex(0xaa);

    let e1 = sample_entry("8c1f", Direction::Out, MessageState::Delivered);
    let e2 = sample_entry("8c20", Direction::In, MessageState::Received);

    meridian_tui::store::history::append_at(&path, &peer, &e1, &store, &handle).expect("append 1");
    meridian_tui::store::history::append_at(&path, &peer, &e2, &store, &handle).expect("append 2");

    let raw = std::fs::read(&path).expect("read raw");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&raw).is_err(),
        "history file must be sealed on disk, not plaintext JSONL"
    );

    let entries = meridian_tui::store::history::load_or_default_at(&path, &peer, &store, &handle)
        .expect("open");
    assert_eq!(entries, vec![e1, e2]);
}

#[test]
fn history_append_is_a_whole_document_reseal_not_an_in_place_disk_append() {
    // Documented in history.rs: appending N entries reseals the whole transcript each time, so
    // the ciphertext for a 2-entry transcript need not simply extend a 1-entry transcript's
    // ciphertext (a fresh random nonce each reseal already guarantees this) — assert the file
    // actually changed in a way consistent with a full rewrite (different length is enough to
    // demonstrate this isn't a byte-for-byte suffix append).
    let (store, handle) = fresh_account();
    let path = tmp_path("history/peer.jsonl");
    let peer = peer_hex(0xaa);

    meridian_tui::store::history::append_at(
        &path,
        &peer,
        &sample_entry("a1", Direction::Out, MessageState::Sent),
        &store,
        &handle,
    )
    .expect("append 1");
    let after_one = std::fs::read(&path).unwrap();

    meridian_tui::store::history::append_at(
        &path,
        &peer,
        &sample_entry("a2", Direction::Out, MessageState::Sent),
        &store,
        &handle,
    )
    .expect("append 2");
    let after_two = std::fs::read(&path).unwrap();

    // The second ciphertext is not a byte-for-byte extension of the first (different nonce +
    // whole-document reseal), which is the sealed-whole-document design this module documents.
    assert_ne!(
        &after_two[..after_one.len().min(after_two.len())],
        &after_one[..]
    );
}

#[test]
fn history_missing_file_yields_empty_transcript() {
    let (store, handle) = fresh_account();
    let path = tmp_path("does-not-exist/history/peer.jsonl");
    let entries =
        meridian_tui::store::history::load_or_default_at(&path, &peer_hex(0xaa), &store, &handle)
            .expect("default");
    assert!(entries.is_empty());
}

#[test]
fn history_tampered_sealed_blob_fails_closed() {
    let (store, handle) = fresh_account();
    let path = tmp_path("history/peer.jsonl");
    let peer = peer_hex(0xaa);
    meridian_tui::store::history::append_at(
        &path,
        &peer,
        &sample_entry("a1", Direction::Out, MessageState::Sent),
        &store,
        &handle,
    )
    .expect("append");

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let err = meridian_tui::store::history::load_or_default_at(&path, &peer, &store, &handle)
        .expect_err("tampered history must fail closed");
    assert!(matches!(err, StoreError::SealFailure { .. }));
}

#[test]
fn history_refuses_a_fabricated_newer_schema_version() {
    let (store, handle) = fresh_account();
    let path = tmp_path("history/peer.jsonl");
    let peer = peer_hex(0xaa);

    let key = store
        .derive_key(&handle, at_rest::STORE_KEY_INFO)
        .expect("derive key");
    let header = serde_json::json!({ "peer_pubkey": peer });
    let fabricated_line = serde_json::json!({
        "v": 2, "mid": "ffff", "dir": "out", "ts": 1, "stream": "mrd.chat/1",
        "body": "x", "state": "sent",
    });
    let plaintext = format!(
        "{}\n{}\n",
        serde_json::to_string(&header).unwrap(),
        serde_json::to_string(&fabricated_line).unwrap()
    );
    let sealed = at_rest::seal(&key, plaintext.as_bytes()).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, sealed).unwrap();

    let err = meridian_tui::store::history::load_or_default_at(&path, &peer, &store, &handle)
        .expect_err("a newer entry schema than understood must be a hard, named error");
    assert!(matches!(
        err,
        StoreError::NewerSchema {
            found: 2,
            understood: 1,
            ..
        }
    ));
}

#[test]
fn history_swapped_sealed_files_are_rejected_not_silently_misattributed() {
    // Two peers, each with their own sealed transcript. Simulates an attacker (or a bug) with
    // local filesystem *write* access — but not the decrypt key — swapping the two ciphertext
    // files on disk: both still decrypt and deserialize cleanly under the shared derived key, so
    // only the embedded peer-binding header can catch the swap (ADR 0021 review finding 3).
    let (store, handle) = fresh_account();
    let alice = peer_hex(0xaa);
    let bob = peer_hex(0xbb);
    let alice_path = tmp_path("history/alice.jsonl");
    let bob_path = tmp_path("history/bob.jsonl");

    meridian_tui::store::history::append_at(
        &alice_path,
        &alice,
        &sample_entry("a1", Direction::Out, MessageState::Sent),
        &store,
        &handle,
    )
    .expect("append alice");
    meridian_tui::store::history::append_at(
        &bob_path,
        &bob,
        &sample_entry("b1", Direction::In, MessageState::Received),
        &store,
        &handle,
    )
    .expect("append bob");

    // Swap the ciphertext bytes on disk — no key material touched, no re-sealing.
    let alice_bytes = std::fs::read(&alice_path).unwrap();
    let bob_bytes = std::fs::read(&bob_path).unwrap();
    std::fs::write(&alice_path, &bob_bytes).unwrap();
    std::fs::write(&bob_path, &alice_bytes).unwrap();

    // Both files still decrypt fine (same key) — but each now claims to be the other peer, so
    // opening either one under its own expected peer id must be a hard error, never a silent
    // misattributed transcript.
    let err =
        meridian_tui::store::history::load_or_default_at(&alice_path, &alice, &store, &handle)
            .expect_err(
                "swapped file must be rejected, not silently returned as alice's transcript",
            );
    assert!(matches!(err, StoreError::PeerMismatch { .. }), "{err:?}");

    let err = meridian_tui::store::history::load_or_default_at(&bob_path, &bob, &store, &handle)
        .expect_err("swapped file must be rejected, not silently returned as bob's transcript");
    assert!(matches!(err, StoreError::PeerMismatch { .. }), "{err:?}");

    // And opening each file under the peer id it now actually (post-swap) belongs to succeeds —
    // confirms the mismatch above is really about the binding, not a general decrypt failure.
    let entries =
        meridian_tui::store::history::load_or_default_at(&alice_path, &bob, &store, &handle)
            .expect("swapped file opens fine under the peer it now actually claims to be");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].mid, "b1");
}

// ---------------------------------------------------------------------------------------------
// outbox.json
// ---------------------------------------------------------------------------------------------

fn sample_outbox_doc() -> OutboxDocument {
    OutboxDocument {
        v: 1,
        entries: vec![OutboxEntry {
            peer_pubkey: "3f9a".repeat(16),
            mid: "8c1f".to_string(),
            stream: "mrd.chat/1".to_string(),
            body: "pushed the branch".to_string(),
            attempt_count: 1,
            next_retry_at: 1_763_020_900,
            created_at: 1_763_020_800,
        }],
    }
}

#[test]
fn outbox_sealed_round_trip() {
    let (store, handle) = fresh_account();
    let path = tmp_path("outbox.json");
    let doc = sample_outbox_doc();

    meridian_tui::store::outbox::save_at(&path, &doc, &store, &handle).expect("save");
    let raw = std::fs::read(&path).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());

    let reopened =
        meridian_tui::store::outbox::load_or_default_at(&path, &store, &handle).expect("open");
    assert_eq!(reopened, doc);
}

#[test]
fn outbox_refuses_a_fabricated_newer_schema_version() {
    let (store, handle) = fresh_account();
    let path = tmp_path("outbox.json");

    let key = store
        .derive_key(&handle, at_rest::STORE_KEY_INFO)
        .expect("derive key");
    let fabricated = serde_json::json!({ "v": 7, "entries": [] });
    let sealed = at_rest::seal(&key, &serde_json::to_vec(&fabricated).unwrap()).unwrap();
    std::fs::write(&path, sealed).unwrap();

    let err = meridian_tui::store::outbox::load_or_default_at(&path, &store, &handle)
        .expect_err("newer schema must refuse");
    assert!(matches!(
        err,
        StoreError::NewerSchema {
            found: 7,
            understood: 1,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------------------------
// state.json
// ---------------------------------------------------------------------------------------------

#[test]
fn state_json_is_plaintext_not_sealed() {
    let path = tmp_path("state.json");
    let doc = StateDocument {
        v: 1,
        last_conversation: Some([0x3f; 16]),
        panes: PaneGeometry {
            sidebar_width: 30,
            composer_height: 4,
        },
        scroll: ScrollState { offset: 12 },
    };
    meridian_tui::store::state::save_at(&path, &doc).expect("save");

    // Readable as plain JSON directly, with no seal/open step at all.
    let raw = std::fs::read(&path).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&raw).expect("state.json must be plain JSON on disk");
    assert_eq!(value["v"], serde_json::json!(1));
    assert_eq!(value["scroll"]["offset"], serde_json::json!(12));

    let reopened = meridian_tui::store::state::load_or_default_at(&path).expect("open");
    assert_eq!(reopened, doc);
}

#[test]
fn state_json_missing_file_yields_default() {
    let path = tmp_path("does-not-exist/state.json");
    let doc = meridian_tui::store::state::load_or_default_at(&path).expect("default");
    assert_eq!(doc, StateDocument::default());
}

#[test]
fn state_json_refuses_a_fabricated_newer_schema_version() {
    let path = tmp_path("state.json");
    let fabricated = serde_json::json!({
        "v": 99, "last_conversation": null,
        "panes": { "sidebar_width": 1, "composer_height": 1 },
        "scroll": { "offset": 0 },
    });
    std::fs::write(&path, serde_json::to_vec(&fabricated).unwrap()).unwrap();

    let err = meridian_tui::store::state::load_or_default_at(&path)
        .expect_err("a newer schema than understood must be a hard, named error");
    assert!(matches!(
        err,
        StoreError::NewerSchema {
            found: 99,
            understood: 1,
            ..
        }
    ));
}

/// Task deliverable 4's structural test, strengthened per the ADR 0021 condition 2 review fix:
/// serialize a [`StateDocument`], walk every JSON leaf, and assert (a) none of them is a string —
/// the shape that would let a petname, message body, or any other display text be smuggled in —
/// and (b) no byte-array leaf structurally coincides with a *real* contact pubkey (this catches the
/// exact class of leak the original review finding hit: a raw `[u8; 32]` pubkey serializes as a
/// JSON array of numbers, not a `Value::String`, so it passed a string-only check while still
/// leaking contact-identifying content). This is deliberately *not* a check of today's field names
/// (which would only catch a rename, not a new field) — it inspects the actual serialized value
/// tree, so a future `petname: String` field, or a future `[u8; 32]`-shaped field reintroducing a
/// raw pubkey, trips this test the moment it's added, regardless of what it's called.
#[test]
fn state_json_structural_no_string_leaves_or_pubkey_shaped_bytes() {
    // The same pubkey `sample_contacts_doc()` uses, decoded to raw bytes — stands in for "a real
    // contact pubkey" a leaked `state.json` byte-array leaf must never structurally equal.
    let real_contact_pubkey: Vec<u8> = std::iter::repeat_n([0x3f_u8, 0x9a], 16).flatten().collect();
    assert_eq!(real_contact_pubkey.len(), 32);

    let doc = StateDocument {
        v: 1,
        // An opaque 16-byte handle — deliberately a different byte length *and* different bytes
        // from `real_contact_pubkey` above, exactly the ADR 0021 condition 2 fix's shape.
        last_conversation: Some([0xab; 16]),
        panes: PaneGeometry {
            sidebar_width: 40,
            composer_height: 5,
        },
        scroll: ScrollState { offset: 7 },
    };
    let value = serde_json::to_value(&doc).expect("serialize");
    assert_no_prohibited_leaves(&value, &real_contact_pubkey);

    // Also cover the `None` branch (a bare `null`, still not a string).
    let empty = StateDocument::default();
    assert_no_prohibited_leaves(
        &serde_json::to_value(&empty).expect("serialize default"),
        &real_contact_pubkey,
    );
}

/// Walks every leaf of a serialized `state.json` value tree, panicking on either prohibited shape:
/// a string leaf, or a numeric-array leaf that is byte-for-byte a real contact pubkey (or is itself
/// exactly 32 bytes long — a raw Ed25519 pubkey's length, and thus structurally suspect in
/// `state.json` regardless of its actual value, per ADR 0021 condition 2's "no contact-identifying
/// content ... may ever be written to `state.json`").
fn assert_no_prohibited_leaves(value: &serde_json::Value, forbidden_pubkey_bytes: &[u8]) {
    match value {
        serde_json::Value::String(s) => panic!(
            "state.json must never contain a string leaf (petname/message-body/key-material \
             shape) — found {s:?}"
        ),
        serde_json::Value::Array(items) => {
            if let Some(bytes) = as_byte_array(items) {
                assert_ne!(
                    bytes, forbidden_pubkey_bytes,
                    "state.json byte-array leaf is byte-for-byte a real contact pubkey — \
                     contact-identifying content smuggled through a non-string JSON type"
                );
                assert_ne!(
                    bytes.len(),
                    32,
                    "state.json byte-array leaf is 32 bytes long, a raw Ed25519 pubkey's length — \
                     structurally suspect regardless of its value"
                );
            }
            items
                .iter()
                .for_each(|v| assert_no_prohibited_leaves(v, forbidden_pubkey_bytes));
        }
        serde_json::Value::Object(map) => map
            .values()
            .for_each(|v| assert_no_prohibited_leaves(v, forbidden_pubkey_bytes)),
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) | serde_json::Value::Null => {}
    }
}

/// If every element of `items` is a JSON number that fits in a `u8`, returns them as bytes — the
/// shape a `[u8; N]` field serializes to. `None` if `items` isn't uniformly byte-shaped (so this
/// only fires on genuine byte-array leaves, not on, say, `panes`/`scroll`'s plain numeric fields,
/// which aren't JSON arrays at all).
fn as_byte_array(items: &[serde_json::Value]) -> Option<Vec<u8>> {
    items
        .iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Migration harness: refuse-newer-schema (generic) + forward migration + `.bak` plumbing against
// a synthetic schema (see migrate.rs's module doc for why this is synthetic rather than a
// fabricated `v0` of a real document — none of the real schemas here ever had one).
// ---------------------------------------------------------------------------------------------

/// A hypothetical v2 renames `"name"` to `"petname"`.
fn synthetic_v1_to_v2(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        if let Some(name) = obj.remove("name") {
            obj.insert("petname".to_string(), name);
        }
        obj.insert("v".to_string(), serde_json::json!(2));
    }
    value
}

const SYNTHETIC_MIGRATIONS: &[MigrationStep] = &[MigrationStep {
    from: 1,
    upgrade: synthetic_v1_to_v2,
}];

#[test]
fn sealed_forward_migration_writes_bak_then_rewrites_at_current_version() {
    let (store, handle) = fresh_account();
    let path = tmp_path("synthetic.json");

    let key = store
        .derive_key(&handle, at_rest::STORE_KEY_INFO)
        .expect("derive key");
    let v1_doc = serde_json::json!({ "v": 1, "name": "bob" });
    let original_sealed = at_rest::seal(&key, &serde_json::to_vec(&v1_doc).unwrap()).unwrap();
    std::fs::write(&path, &original_sealed).unwrap();

    assert!(
        !bak_path(&path).exists(),
        "no .bak before any migration runs"
    );

    let migrated = read_sealed_migrating(
        &path,
        "synthetic.json",
        &store,
        &handle,
        2,
        SYNTHETIC_MIGRATIONS,
    )
    .expect("v1 -> v2 migration");
    assert_eq!(migrated["v"], serde_json::json!(2));
    assert_eq!(migrated["petname"], serde_json::json!("bob"));

    // `.bak` holds the pre-migration sealed bytes, byte-for-byte.
    let bak_bytes = std::fs::read(bak_path(&path)).expect(".bak must exist after migrating");
    assert_eq!(bak_bytes, original_sealed);

    // The file itself now opens directly at v2, with no further migration needed.
    let reopened = read_sealed_migrating(
        &path,
        "synthetic.json",
        &store,
        &handle,
        2,
        SYNTHETIC_MIGRATIONS,
    )
    .expect("re-open at v2");
    assert_eq!(reopened, migrated);
    // Re-opening at the now-current version must not touch `.bak` again (no second migration
    // ran) — same content as before.
    assert_eq!(std::fs::read(bak_path(&path)).unwrap(), bak_bytes);
}

#[test]
fn plain_forward_migration_writes_bak_then_rewrites_at_current_version() {
    let path = tmp_path("synthetic-plain.json");
    let v1_doc = serde_json::json!({ "v": 1, "name": "alice" });
    std::fs::write(&path, serde_json::to_vec(&v1_doc).unwrap()).unwrap();

    let migrated = read_plain_migrating(&path, "synthetic-plain.json", 2, SYNTHETIC_MIGRATIONS)
        .expect("v1 -> v2 migration");
    assert_eq!(migrated["v"], serde_json::json!(2));
    assert_eq!(migrated["petname"], serde_json::json!("alice"));

    let bak_bytes = std::fs::read(bak_path(&path)).expect(".bak must exist after migrating");
    let bak_value: serde_json::Value = serde_json::from_slice(&bak_bytes).unwrap();
    assert_eq!(bak_value, v1_doc);
}

#[test]
fn already_current_version_is_a_no_op_no_bak_written() {
    let (store, handle) = fresh_account();
    let path = tmp_path("synthetic.json");
    let key = store
        .derive_key(&handle, at_rest::STORE_KEY_INFO)
        .expect("derive key");
    let v2_doc = serde_json::json!({ "v": 2, "petname": "bob" });
    let sealed = at_rest::seal(&key, &serde_json::to_vec(&v2_doc).unwrap()).unwrap();
    std::fs::write(&path, &sealed).unwrap();

    let opened = read_sealed_migrating(
        &path,
        "synthetic.json",
        &store,
        &handle,
        2,
        SYNTHETIC_MIGRATIONS,
    )
    .expect("already at v2");
    assert_eq!(opened, v2_doc);
    assert!(
        !bak_path(&path).exists(),
        "opening a document already at current_version must not write a .bak"
    );
}

#[test]
fn generic_harness_refuses_newer_than_understood_with_a_named_version_error() {
    let value = serde_json::json!({ "v": 5 });
    let err = migrate_forward(value, "generic.json", 1, &[]).expect_err("must refuse");
    match err {
        StoreError::NewerSchema {
            file,
            found,
            understood,
        } => {
            assert_eq!(file, "generic.json");
            assert_eq!(found, 5);
            assert_eq!(understood, 1);
        }
        other => panic!("expected NewerSchema, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// write_sealed / write_plain smoke coverage (used indirectly above via save_at, but exercised
// directly here too since they're the public harness surface `tests/store.rs` is meant to cover).
// ---------------------------------------------------------------------------------------------

#[test]
fn write_sealed_and_write_plain_round_trip_through_the_harness_helpers_directly() {
    let (store, handle) = fresh_account();

    let sealed_path = tmp_path("direct-sealed.json");
    let doc = serde_json::json!({ "v": 1, "x": 42 });
    write_sealed(&sealed_path, &doc, &store, &handle).expect("write_sealed");
    let reopened =
        read_sealed_migrating(&sealed_path, "direct-sealed.json", &store, &handle, 1, &[])
            .expect("read back");
    assert_eq!(reopened, doc);

    let plain_path = tmp_path("direct-plain.json");
    write_plain(&plain_path, &doc).expect("write_plain");
    let reopened_plain =
        read_plain_migrating(&plain_path, "direct-plain.json", 1, &[]).expect("read back");
    assert_eq!(reopened_plain, doc);
    // And it really is plaintext on disk.
    let raw = std::fs::read(&plain_path).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&raw).unwrap(),
        doc
    );
}
