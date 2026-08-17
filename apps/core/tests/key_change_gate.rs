//! Key-change block/warn gate (task 4.4): `TrustStore::observe_key_change`,
//! `TrustStore::can_send`/`SendGate`, and the org-configurable pinned→block escalation — the
//! target named by the task file (`cargo nextest run -p meridian-core --test key_change_gate`).
//!
//! The most important test here is `verified_contact_key_change_blocks_sends_with_no_bypass`:
//! docs/security/verification-ux.md is explicit that a gate with a silent bypass makes any UI's
//! warning theater, so this actively tries every state-mutating method on `TrustStore` looking for
//! one that quietly clears `Blocked` without going through a genuine `mark_verified` re-verification,
//! and asserts none of them do.

use meridian_core::trust::{SendGate, TrustError, TrustState, TrustStore};

fn pk(tag: u8) -> [u8; 32] {
    [tag; 32]
}

/// The canonical wording (verification-ux.md) must, in substance: name the benign explanation,
/// name the interception possibility, say sends are paused/blocked, and offer verification — never
/// collapse into pure reassurance. Shared by both the block and warn assertions below.
fn assert_canonical_substance(reason: &str) {
    let lower = reason.to_lowercase();
    assert!(
        lower.contains("safety number"),
        "must name what changed: {reason}"
    );
    assert!(
        lower.contains("reinstalled") || lower.contains("switched devices"),
        "must state the benign explanation: {reason}"
    );
    assert!(
        lower.contains("intercept"),
        "must state the interception possibility (hard prohibition #2) — must not soften into \
         pure reassurance: {reason}"
    );
    assert!(
        lower.contains("verify"),
        "must offer a Verify action: {reason}"
    );
    assert!(
        !lower.contains("new phone")
            && !lower.contains("just reinstalled")
            && !lower.contains("nothing to worry"),
        "must not imply the change is definitely benign: {reason}"
    );
}

#[test]
fn verified_contact_key_change_blocks_sends_with_no_bypass() {
    let mut store = TrustStore::default();
    let old_key = pk(1);
    let new_key = pk(2);

    store.observe(old_key, "org-a.test", 1_000);
    store.mark_verified(&old_key).unwrap();
    assert_eq!(store.can_send(&old_key), SendGate::Ok);

    let state = store
        .observe_key_change(&old_key, new_key, "org-a.test", 2_000)
        .expect("known contact, genuine change");
    assert_eq!(state, TrustState::Blocked);
    assert_eq!(store.trust_state(&new_key), TrustState::Blocked);
    // The old key is no longer "the" contact record — the map key follows the *current* identity
    // key, per `Contact::pubkey`'s doc.
    assert_eq!(store.trust_state(&old_key), TrustState::New);

    let gate = store.can_send(&new_key);
    let reason = match &gate {
        SendGate::Blocked(reason) => reason.clone(),
        other => panic!("expected Blocked, got {other:?}"),
    };
    assert_canonical_substance(&reason);
    assert!(
        reason.to_lowercase().contains("block"),
        "must say sends are blocked, not just paused: {reason}"
    );

    // --- Adversarial: try every plausible bypass; none may clear `Blocked`. ---

    // 1. Acknowledge (the pinned-case escape hatch) must be refused outright.
    let err = store
        .acknowledge_key_change(&new_key)
        .expect_err("acknowledging a Blocked (verified) key change must be a hard error");
    assert!(matches!(err, TrustError::NotAcknowledgeable));
    assert_eq!(store.can_send(&new_key), SendGate::Blocked(reason.clone()));

    // 2. A plain repeat `observe` of the now-current key must not relax anything.
    store.observe(new_key, "org-a.test", 2_100);
    assert_eq!(store.can_send(&new_key), SendGate::Blocked(reason.clone()));
    assert_eq!(store.trust_state(&new_key), TrustState::Blocked);

    // 3. Calling `observe_key_change` again with the *same* (already-current) key as both
    //    `previous` and `new` — the "not actually a change" branch — must not relax anything.
    let state = store
        .observe_key_change(&new_key, new_key, "org-a.test", 2_200)
        .unwrap();
    assert_eq!(state, TrustState::Blocked);
    assert_eq!(store.can_send(&new_key), SendGate::Blocked(reason.clone()));

    // 4. Yet another claimed key change while already blocked must not "reset" to a weaker state.
    let third_key = pk(3);
    let state = store
        .observe_key_change(&new_key, third_key, "org-a.test", 2_300)
        .unwrap();
    assert_eq!(state, TrustState::Blocked);
    assert_eq!(
        store.can_send(&third_key),
        SendGate::Blocked(reason.clone())
    );

    // 5. There is no "trust anyway" / dismiss method on `TrustStore` at all — the only public
    //    surface capable of reaching `Verified` from here is `mark_verified`, and it requires the
    //    caller to have actually done an out-of-band re-verification (this crate cannot and does
    //    not check that itself — that is the human-facing half of the invariant — but it is at
    //    least the *only* code path, never a side effect of any of the above).
    store.mark_verified(&third_key).expect("genuine re-verify");
    assert_eq!(store.can_send(&third_key), SendGate::Ok);
    assert_eq!(store.trust_state(&third_key), TrustState::Verified);
}

#[test]
fn pinned_contact_key_change_warns_then_acknowledge_re_pins() {
    let mut store = TrustStore::default();
    let old_key = pk(10);
    let new_key = pk(11);

    store.observe(old_key, "org-b.test", 1_000);
    assert_eq!(store.trust_state(&old_key), TrustState::Pinned);

    let state = store
        .observe_key_change(&old_key, new_key, "org-b.test", 2_000)
        .unwrap();
    assert_eq!(state, TrustState::PinnedKeyChanged);

    let gate = store.can_send(&new_key);
    let reason = match &gate {
        SendGate::Warn(reason) => reason.clone(),
        other => panic!("expected Warn, got {other:?}"),
    };
    assert_canonical_substance(&reason);
    assert!(
        reason.to_lowercase().contains("pause"),
        "must say sends are paused: {reason}"
    );

    // Not yet acknowledged: sends stay gated (never silently pass a Warn either).
    assert_eq!(store.can_send(&new_key), SendGate::Warn(reason));

    // Decline path: nothing here to call (the CLI/TUI simply doesn't call `acknowledge_key_change`
    // and drops the message) — assert the state really is unchanged by mere inaction.
    assert_eq!(store.trust_state(&new_key), TrustState::PinnedKeyChanged);

    // Acknowledge: re-pins, without any safety-number verification having happened.
    store
        .acknowledge_key_change(&new_key)
        .expect("pinned key change is acknowledgeable");
    assert_eq!(store.trust_state(&new_key), TrustState::Pinned);
    assert_eq!(store.can_send(&new_key), SendGate::Ok);

    // Acknowledging again (nothing pending) is a hard error, not a silent no-op success.
    let err = store.acknowledge_key_change(&new_key).unwrap_err();
    assert!(matches!(err, TrustError::NotAcknowledgeable));
}

#[test]
fn org_config_escalation_pinned_key_change_blocks() {
    let mut store = TrustStore::default();
    assert!(!store.escalate_pinned_key_change(), "default is warn-only");

    let old_key = pk(20);
    let new_key = pk(21);
    store.observe(old_key, "org-c.test", 1_000);
    store.set_escalate_pinned_key_change(true);
    assert!(store.escalate_pinned_key_change());

    let state = store
        .observe_key_change(&old_key, new_key, "org-c.test", 2_000)
        .unwrap();
    assert_eq!(
        state,
        TrustState::Blocked,
        "escalated org policy must produce the same hard block as a verified contact's key change"
    );
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));

    // Escalation also means acknowledge (the pinned-only escape hatch) no longer applies.
    let err = store.acknowledge_key_change(&new_key).unwrap_err();
    assert!(matches!(err, TrustError::NotAcknowledgeable));

    // Turning escalation back off does not retroactively downgrade an already-blocked contact —
    // only `mark_verified` moves it.
    store.set_escalate_pinned_key_change(false);
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));
}

#[test]
fn escalation_tightens_an_in_flight_pinned_key_change_on_the_next_observed_change() {
    let mut store = TrustStore::default();
    let k1 = pk(30);
    let k2 = pk(31);
    let k3 = pk(32);

    store.observe(k1, "org-d.test", 1_000);
    let state = store
        .observe_key_change(&k1, k2, "org-d.test", 2_000)
        .unwrap();
    assert_eq!(state, TrustState::PinnedKeyChanged);

    // Escalation flips on mid-incident; a further claimed key change tightens rather than staying
    // at the (now more permissive) warn state.
    store.set_escalate_pinned_key_change(true);
    let state = store
        .observe_key_change(&k2, k3, "org-d.test", 3_000)
        .unwrap();
    assert_eq!(state, TrustState::Blocked);
}

/// Regression: escalation must apply to an *already-in-flight* `PinnedKeyChanged` warning, not
/// just to key changes observed after escalation turns on. Without this, an org flipping
/// escalation on as an incident response could be silently defeated by a plain `acknowledge`
/// call in the gap before any new key change is observed.
#[test]
fn escalation_flipped_on_while_a_warning_is_already_outstanding_blocks_on_acknowledge_attempt() {
    let mut store = TrustStore::default();
    let old_key = pk(33);
    let new_key = pk(34);

    store.observe(old_key, "org-e.test", 1_000);
    let state = store
        .observe_key_change(&old_key, new_key, "org-e.test", 2_000)
        .unwrap();
    assert_eq!(state, TrustState::PinnedKeyChanged);

    // Escalation turns on *after* the warning already exists, with no further observed key
    // change in between.
    store.set_escalate_pinned_key_change(true);

    // A plain acknowledge attempt must not silently re-pin the (possibly attacker-substituted)
    // key just because it raced ahead of the next `observe_key_change` call.
    let err = store.acknowledge_key_change(&new_key).unwrap_err();
    assert!(matches!(err, TrustError::NotAcknowledgeable));
    assert_eq!(
        store.trust_state(&new_key),
        TrustState::Blocked,
        "the acknowledge attempt itself must force-escalate to Blocked, not leave it at Warn"
    );
    assert!(matches!(store.can_send(&new_key), SendGate::Blocked(_)));

    // And, as always, only mark_verified can clear it from here.
    let err = store.acknowledge_key_change(&new_key).unwrap_err();
    assert!(matches!(err, TrustError::NotAcknowledgeable));
    store.mark_verified(&new_key).expect("known contact");
    assert_eq!(store.trust_state(&new_key), TrustState::Verified);
}

#[test]
fn unknown_previous_key_errs() {
    let mut store = TrustStore::default();
    let err = store
        .observe_key_change(&pk(99), pk(100), "org-a.test", 1_000)
        .unwrap_err();
    assert!(matches!(err, TrustError::UnknownContact));
}

#[test]
fn claimed_key_change_onto_a_different_known_contact_is_refused_not_merged() {
    let mut store = TrustStore::default();
    let alice = pk(1);
    let bob = pk(2);
    store.observe(alice, "org-a.test", 1_000);
    store.observe(bob, "org-a.test", 1_000);
    store.mark_verified(&bob).unwrap();

    // Claiming alice's contact now presents bob's (already-verified, independently-known) key
    // must not silently fold the two records together.
    let err = store
        .observe_key_change(&alice, bob, "org-a.test", 2_000)
        .unwrap_err();
    assert!(matches!(err, TrustError::ConflictingContact));
    // Bob's own trust state must be completely untouched.
    assert_eq!(store.trust_state(&bob), TrustState::Verified);
    assert_eq!(store.trust_state(&alice), TrustState::Pinned);
}

#[test]
fn resupplying_the_same_previous_and_new_key_is_not_a_change() {
    let mut store = TrustStore::default();
    let key = pk(5);
    store.observe(key, "org-a.test", 1_000);
    store.mark_verified(&key).unwrap();

    let state = store
        .observe_key_change(&key, key, "org-a.test", 2_000)
        .unwrap();
    assert_eq!(state, TrustState::Verified, "not a genuine change");
    assert_eq!(store.can_send(&key), SendGate::Ok);
}

#[test]
fn key_change_preserves_full_pinned_key_history_across_the_migration() {
    let mut store = TrustStore::default();
    let old_key = pk(40);
    let new_key = pk(41);
    store.observe(old_key, "org-e.test", 1_000);

    store
        .observe_key_change(&old_key, new_key, "org-e.test", 2_000)
        .unwrap();

    let contact = store.contact(&new_key).expect("migrated contact");
    assert_eq!(contact.pubkey, new_key);
    assert_eq!(
        contact.pinned_key_history.len(),
        2,
        "old + new key retained"
    );
    assert_eq!(contact.pinned_key_history[0].pubkey, old_key);
    assert_eq!(contact.pinned_key_history[1].pubkey, new_key);
    assert_eq!(contact.pinned_key_history[1].first_seen_unix, 2_000);
}

#[test]
fn blocked_and_escalation_state_round_trip_through_seal_at_rest() {
    use meridian_identity::{generate_account, MemorySecretStore};

    let secret_store = MemorySecretStore::new();
    let account = generate_account(&secret_store, "trust.rs.key-change-persist").unwrap();

    let mut store = TrustStore::default();
    let old_key = pk(50);
    let new_key = pk(51);
    store.observe(old_key, "org-f.test", 1_000);
    store.mark_verified(&old_key).unwrap();
    store.set_escalate_pinned_key_change(true);
    store
        .observe_key_change(&old_key, new_key, "org-f.test", 2_000)
        .unwrap();
    assert_eq!(store.trust_state(&new_key), TrustState::Blocked);

    let sealed = store.seal_at_rest(&secret_store, account.handle()).unwrap();
    let reopened = TrustStore::open_at_rest(&secret_store, account.handle(), &sealed).unwrap();

    assert_eq!(reopened.trust_state(&new_key), TrustState::Blocked);
    assert!(reopened.escalate_pinned_key_change());
    assert!(matches!(reopened.can_send(&new_key), SendGate::Blocked(_)));
}
