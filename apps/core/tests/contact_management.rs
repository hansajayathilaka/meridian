//! Core contact-management integration (task 4.6): petname/user-block orthogonality against
//! task 4.4's key-change gate, migration survival, and unknown-contact error paths. Petname's
//! own never-from-wire invariant is covered by `apps/cli/src/contact.rs`'s
//! `observe_alone_never_populates_petname` unit test and
//! `apps/cli/tests/contact_mgmt.rs`'s CLI-subprocess integration test — this file covers the
//! core-level orthogonality claims flagged by 4.6's security review as needing a regression test
//! of their own, since the next refactor of `can_send`/`observe_key_change` is exactly the kind
//! of change that could silently reintroduce coupling between the two block mechanisms.

use meridian_core::trust::{SendGate, TrustError, TrustState, TrustStore};

fn pk(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[test]
fn user_block_and_key_change_block_are_fully_orthogonal() {
    let mut store = TrustStore::default();
    let old_key = pk(1);
    let new_key = pk(2);

    store.observe(old_key, "org-a.test", 1_000);
    store.mark_verified(&old_key).unwrap();

    // A key-change event blocks the contact (task 4.4's invariant).
    let state = store
        .observe_key_change(&old_key, new_key, "org-a.test", 2_000)
        .unwrap();
    assert_eq!(state, TrustState::Blocked);
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));

    // A user block layers on top -- still blocked, for either reason.
    store.set_user_blocked(&new_key, true).unwrap();
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));

    // Re-verifying clears the KEY-CHANGE block, per task 4.4 -- but the user's own block is a
    // wholly separate decision and must NOT be cleared by it.
    store.mark_verified(&new_key).unwrap();
    assert_eq!(store.trust_state(&new_key), TrustState::Verified);
    assert!(
        matches!(store.can_send(&new_key), SendGate::Blocked(_)),
        "mark_verified must never clear a user-initiated block"
    );

    // Only clearing the user block (an explicit, separate action) lifts the send gate.
    store.set_user_blocked(&new_key, false).unwrap();
    assert_eq!(store.can_send(&new_key), SendGate::Ok);
}

#[test]
fn clearing_a_user_block_never_touches_an_unrelated_key_change_block() {
    let mut store = TrustStore::default();
    let old_key = pk(3);
    let new_key = pk(4);

    store.observe(old_key, "org-b.test", 1_000);
    store.mark_verified(&old_key).unwrap();
    store
        .observe_key_change(&old_key, new_key, "org-b.test", 2_000)
        .unwrap();
    assert_eq!(store.trust_state(&new_key), TrustState::Blocked);

    // Toggle a user block on and back off. The underlying key-change Blocked state -- and the
    // resulting send gate -- must be completely unaffected by this in either direction.
    store.set_user_blocked(&new_key, true).unwrap();
    assert_eq!(store.trust_state(&new_key), TrustState::Blocked);
    store.set_user_blocked(&new_key, false).unwrap();
    assert_eq!(
        store.trust_state(&new_key),
        TrustState::Blocked,
        "clearing a user block must not clear an unrelated key-change block"
    );
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));

    // Only mark_verified -- an actual out-of-band re-verification -- clears it.
    store.mark_verified(&new_key).unwrap();
    assert_eq!(store.can_send(&new_key), SendGate::Ok);
}

#[test]
fn petname_and_user_blocked_survive_a_key_change_migration() {
    let mut store = TrustStore::default();
    let old_key = pk(5);
    let new_key = pk(6);

    store.observe(old_key, "org-c.test", 1_000);
    store
        .set_petname(&old_key, Some("bob".to_string()))
        .unwrap();
    store.set_user_blocked(&old_key, true).unwrap();

    store
        .observe_key_change(&old_key, new_key, "org-c.test", 2_000)
        .unwrap();

    // The migrated contact (now keyed by new_key) must retain both local-only attributes --
    // neither is wire-observed, so a key change (itself a wire-triggered event) must not reset
    // them.
    let contact = store.contact(&new_key).expect("migrated contact exists");
    assert_eq!(contact.petname.as_deref(), Some("bob"));
    assert!(contact.user_blocked);
    assert!(store.contact(&old_key).is_none(), "old key entry removed");
}

#[test]
fn set_petname_on_unknown_contact_errs() {
    let mut store = TrustStore::default();
    let err = store
        .set_petname(&pk(9), Some("ghost".to_string()))
        .unwrap_err();
    assert!(matches!(err, TrustError::UnknownContact));
}

#[test]
fn set_user_blocked_on_unknown_contact_errs() {
    let mut store = TrustStore::default();
    let err = store.set_user_blocked(&pk(9), true).unwrap_err();
    assert!(matches!(err, TrustError::UnknownContact));
}
