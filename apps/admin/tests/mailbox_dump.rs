//! Task 8.11 acceptance: `mailbox dump`'s core logic against real store backends — an
//! `Arc<dyn Store>` `MemoryStore` (mirrors what `default_store` returns without the `sqlite`
//! feature) and a tempfile-backed `SqliteStore` (mirrors a real deployment, matching the pattern
//! `apps/rendezvous/src/store/sqlite.rs`'s own tests and `apps/rendezvous/tests/mailbox_purge.rs`
//! already use). Drives `meridian_admin::dump_mailbox` directly rather than shelling out to the
//! real binary — the task's own "factor the core logic into a testable function" instruction.

use meridian_admin::dump_mailbox;
use meridian_rendezvous::{MemoryStore, Store};

/// A blob deliberately shaped like real chat plaintext, so a test asserting its ABSENCE from the
/// dump's output is actually testing something (see `plaintext_never_appears_in_output` below).
const FAKE_PLAINTEXT: &[u8] = b"hey, meet at 9pm - do not tell anyone";

#[tokio::test]
async fn empty_mailbox_dumps_as_explicitly_empty() {
    let store = MemoryStore::new();
    let recipient = [3u8; 32];

    let out = dump_mailbox(&store, recipient).await.unwrap();

    assert!(out.contains("0 envelopes"));
    assert!(out.contains("(empty)"));
}

#[tokio::test]
async fn memory_store_dump_reports_sizes_timestamps_and_opaque_markers() {
    let store = MemoryStore::new();
    let recipient = [9u8; 32];

    store
        .mailbox_enqueue(recipient, vec![0u8; 1229], 1_000, 2_000)
        .await
        .unwrap();
    store
        .mailbox_enqueue(recipient, vec![0u8; 4198], 1_500, 2_500)
        .await
        .unwrap();

    let out = dump_mailbox(&store, recipient).await.unwrap();

    assert!(out.contains("2 envelopes"));
    assert!(out.contains("arrived_at=1000"));
    assert!(out.contains("expires_at=2000"));
    assert!(out.contains("arrived_at=1500"));
    assert!(out.contains("expires_at=2500"));
    assert!(out.contains("<opaque, 1229 bytes>"));
    assert!(out.contains("<opaque, 4198 bytes>"));
    assert!(out.contains("1.2 KiB"));
    assert!(out.contains("4.1 KiB"));
}

#[tokio::test]
async fn plaintext_never_appears_in_output() {
    let store = MemoryStore::new();
    let recipient = [4u8; 32];

    store
        .mailbox_enqueue(recipient, FAKE_PLAINTEXT.to_vec(), 10, 20)
        .await
        .unwrap();

    let out = dump_mailbox(&store, recipient).await.unwrap();

    assert!(!out.contains("meet at 9pm"));
    assert!(!out.contains("hey"));
    assert!(out.contains(&format!("<opaque, {} bytes>", FAKE_PLAINTEXT.len())));
}

#[tokio::test]
async fn dump_only_sees_the_named_recipients_own_rows() {
    let store = MemoryStore::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];

    store
        .mailbox_enqueue(alice, vec![1, 2, 3], 0, 1)
        .await
        .unwrap();
    store.mailbox_enqueue(bob, vec![4, 5], 0, 1).await.unwrap();

    let alice_out = dump_mailbox(&store, alice).await.unwrap();
    let bob_out = dump_mailbox(&store, bob).await.unwrap();

    assert!(alice_out.contains("1 envelope"));
    assert!(!alice_out.contains("2 envelope"));
    assert!(bob_out.contains("1 envelope"));
    assert!(alice_out.contains("<opaque, 3 bytes>"));
    assert!(bob_out.contains("<opaque, 2 bytes>"));
}

// `meridian-admin` always enables `meridian-rendezvous`'s `sqlite` feature (see this crate's
// Cargo.toml) — an in-memory-only build would be useless for inspecting a real deployment's data
// — so this test needs no feature gate of its own.
#[tokio::test]
async fn sqlite_store_dump_matches_the_memory_store_shape() {
    use meridian_rendezvous::store::SqliteStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("admin-dump-test.db");
    let url = format!("sqlite://{}", path.display());
    let recipient = [5u8; 32];

    let store = SqliteStore::connect(&url).await.unwrap();
    store
        .mailbox_enqueue(recipient, vec![0u8; 921], 100, 200)
        .await
        .unwrap();

    let out = dump_mailbox(&store, recipient).await.unwrap();

    assert!(out.contains("1 envelope"));
    assert!(out.contains("arrived_at=100"));
    assert!(out.contains("expires_at=200"));
    assert!(out.contains("<opaque, 921 bytes>"));
}
