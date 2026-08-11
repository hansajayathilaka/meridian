//! Core trust module integration (task 4.3): TOFU-pin-on-first-contact, the `mark_verified`
//! transition, and sealed-at-rest persistence — the target named by the task file
//! (`cargo nextest run -p meridian-core --test trust_store`).

use meridian_core::trust::{TrustError, TrustState, TrustStore};
use meridian_identity::{generate_account, MemorySecretStore};

fn pk(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[test]
fn brand_new_contact_is_tofu_pinned_on_first_observation() {
    let mut store = TrustStore::default();
    let key = pk(1);

    // No record yet: the total `trust_state` function reports `New`.
    assert_eq!(store.trust_state(&key), TrustState::New);
    assert!(store.contact(&key).is_none());

    let state = store.observe(key, "org-a.test", 1_000);
    assert_eq!(state, TrustState::Pinned);
    assert_eq!(store.trust_state(&key), TrustState::Pinned);

    let contact = store.contact(&key).expect("contact recorded");
    assert_eq!(contact.pubkey, key);
    assert_eq!(contact.hint, "org-a.test");
    assert_eq!(contact.state, TrustState::Pinned);
    assert_eq!(contact.pinned_key_history.len(), 1);
    assert_eq!(contact.pinned_key_history[0].pubkey, key);
    assert_eq!(contact.pinned_key_history[0].first_seen_unix, 1_000);
    assert_eq!(contact.pinned_key_history[0].last_seen_unix, 1_000);
    assert_eq!(
        contact.id_string().unwrap(),
        meridian_identity::to_id_string(&key, "org-a.test").unwrap()
    );
}

#[test]
fn repeat_observation_of_the_same_key_bumps_last_seen_without_changing_state() {
    let mut store = TrustStore::default();
    let key = pk(2);

    store.observe(key, "org-a.test", 1_000);
    store.mark_verified(&key).expect("known contact");
    assert_eq!(store.trust_state(&key), TrustState::Verified);

    let state = store.observe(key, "org-a.test", 2_000);
    // Observing the same key again never changes an already-decided trust state.
    assert_eq!(state, TrustState::Verified);
    assert_eq!(store.trust_state(&key), TrustState::Verified);

    let contact = store.contact(&key).expect("contact recorded");
    assert_eq!(
        contact.pinned_key_history.len(),
        1,
        "no duplicate history entry"
    );
    assert_eq!(contact.pinned_key_history[0].first_seen_unix, 1_000);
    assert_eq!(
        contact.pinned_key_history[0].last_seen_unix, 2_000,
        "last_seen_unix must advance on repeat observation"
    );
}

#[test]
fn observing_updates_the_advisory_hint() {
    let mut store = TrustStore::default();
    let key = pk(4);
    store.observe(key, "old.test", 1_000);
    store.observe(key, "new.test", 1_001);
    assert_eq!(store.contact(&key).unwrap().hint, "new.test");
}

#[test]
fn repeat_tofu_observation_without_verification_stays_pinned() {
    let mut store = TrustStore::default();
    let key = pk(5);

    let first = store.observe(key, "org-a.test", 1_000);
    assert_eq!(first, TrustState::Pinned);

    let second = store.observe(key, "org-a.test", 1_500);
    assert_eq!(second, TrustState::Pinned);
    assert_eq!(store.trust_state(&key), TrustState::Pinned);

    let contact = store.contact(&key).unwrap();
    assert_eq!(
        contact.pinned_key_history.len(),
        1,
        "repeat observation of the same key must not duplicate history"
    );
    assert_eq!(contact.pinned_key_history[0].last_seen_unix, 1_500);
}

#[test]
fn oversized_hint_is_truncated_not_rejected() {
    let mut store = TrustStore::default();
    let key = pk(6);
    let huge_hint = "a".repeat(10_000);

    store.observe(key, &huge_hint, 1_000);

    let contact = store.contact(&key).unwrap();
    assert_eq!(contact.hint.len(), meridian_core::trust::MAX_HINT_LEN);
    assert!(huge_hint.starts_with(&contact.hint));
}

#[test]
fn mark_verified_transitions_pinned_to_verified() {
    let mut store = TrustStore::default();
    let key = pk(3);
    store.observe(key, "org-a.test", 1_000);
    assert_eq!(store.trust_state(&key), TrustState::Pinned);

    store.mark_verified(&key).expect("known contact verifies");
    assert_eq!(store.trust_state(&key), TrustState::Verified);
    assert_eq!(store.contact(&key).unwrap().state, TrustState::Verified);
}

#[test]
fn mark_verified_on_unknown_contact_errs() {
    let mut store = TrustStore::default();
    let err = store.mark_verified(&pk(9)).unwrap_err();
    assert!(matches!(err, TrustError::UnknownContact));
}

#[test]
fn sealed_round_trip_preserves_every_contact_and_history_entry() {
    let secret_store = MemorySecretStore::new();
    let account = generate_account(&secret_store, "trust.rs.self").unwrap();

    let mut trust = TrustStore::default();
    let alice = pk(10);
    let bob = pk(20);
    trust.observe(alice, "org-a.test", 1_000);
    trust.observe(bob, "org-b.test", 2_000);
    trust.mark_verified(&alice).unwrap();

    let sealed = trust
        .seal_at_rest(&secret_store, account.handle())
        .expect("seal");
    let reopened =
        TrustStore::open_at_rest(&secret_store, account.handle(), &sealed).expect("open");

    assert_eq!(reopened.trust_state(&alice), TrustState::Verified);
    assert_eq!(reopened.trust_state(&bob), TrustState::Pinned);

    let alice_contact = reopened.contact(&alice).unwrap();
    assert_eq!(alice_contact.hint, "org-a.test");
    assert_eq!(alice_contact.pinned_key_history.len(), 1);
    assert_eq!(alice_contact.pinned_key_history[0].first_seen_unix, 1_000);

    let bob_contact = reopened.contact(&bob).unwrap();
    assert_eq!(bob_contact.hint, "org-b.test");
    assert_eq!(bob_contact.state, TrustState::Pinned);

    // Every observed contact round-trips, not just a subset.
    assert_eq!(reopened.contacts().count(), 2);
}

#[test]
fn sealed_blob_fails_closed_under_the_wrong_key() {
    let secret_store = MemorySecretStore::new();
    let account = generate_account(&secret_store, "trust.rs.self").unwrap();
    let other_store = MemorySecretStore::new();
    let other_account = generate_account(&other_store, "trust.rs.other").unwrap();

    let mut trust = TrustStore::default();
    trust.observe(pk(1), "org-a.test", 1_000);
    let sealed = trust
        .seal_at_rest(&secret_store, account.handle())
        .expect("seal");

    // A wrong-key open must be a hard error, never a silent empty-store fallback (ADR 0021
    // condition 5b).
    let err = TrustStore::open_at_rest(&other_store, other_account.handle(), &sealed)
        .expect_err("wrong key must fail closed, not reinitialize");
    assert!(matches!(err, TrustError::Crypto(_)));
}

#[test]
fn tampered_sealed_blob_fails_closed() {
    let secret_store = MemorySecretStore::new();
    let account = generate_account(&secret_store, "trust.rs.self").unwrap();

    let mut trust = TrustStore::default();
    trust.observe(pk(1), "org-a.test", 1_000);
    let mut sealed = trust
        .seal_at_rest(&secret_store, account.handle())
        .expect("seal");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xff;

    let err = TrustStore::open_at_rest(&secret_store, account.handle(), &sealed)
        .expect_err("tampered blob must fail closed");
    assert!(matches!(err, TrustError::Crypto(_)));
}

#[test]
fn empty_store_seals_and_opens_round_trip() {
    let secret_store = MemorySecretStore::new();
    let account = generate_account(&secret_store, "trust.rs.self").unwrap();

    let trust = TrustStore::default();
    let sealed = trust
        .seal_at_rest(&secret_store, account.handle())
        .expect("seal empty store");
    let reopened =
        TrustStore::open_at_rest(&secret_store, account.handle(), &sealed).expect("open");
    assert_eq!(reopened.contacts().count(), 0);
}
