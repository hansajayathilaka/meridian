//! Task 4.9 — desync detection → guarded fresh-X3DH re-handshake (`cargo nextest run -p
//! meridian-core --test desync_recovery`, this file's own target name per the task file).
//!
//! Exercises both halves task 1.18 described and deferred (`docs/tasks/phase-1/1.18-desync-
//! recovery-decision.md`):
//! - the **"safe half" bug fix** — `ChatState::open_bytes`'s discriminator now correctly accepts a
//!   fresh, cryptographically-verified re-initiation even when the counterpart still holds a
//!   **stale** session for the same identity key (previously this classified as `Desync`
//!   *permanently*, since nothing ever re-attempted establishment);
//! - the **"dangerous half"** — this task's new receiver-side orchestration
//!   (`ChatState::recovery_recommended` / `desync::attempt_recovery`), guarded by *repeated, not
//!   single* `Desync` ([`DESYNC_RECOVERY_THRESHOLD`]) and by `trust::TrustStore::can_send` (task
//!   4.4's block/warn gate) before any session is ever touched.
//!
//! Follows `apps/core/tests/chat_manager.rs`'s `Party` pattern and its task-1.18 test's technique
//! for constructing a genuine desync (mangle a byte inside `enc_header`, then re-sign so the
//! envelope is authentic and reaches the ratchet rather than being caught by the signature check).

use meridian_core::chat::{
    ChatError, ChatState, DESYNC_RECOVERY_THRESHOLD, PREV_GENERATION_GRACE_SECS,
};
use meridian_core::desync::{attempt_recovery, RecoveryOutcome};
use meridian_core::trust::{SendGate, TrustState, TrustStore};
use meridian_envelope::{ChatContent, MessageEnvelope};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::{generate_bundle, GeneratedBundle};

const TEST_NOW_UNIX: u64 = 1_700_000_000;

struct Party {
    store: MemorySecretStore,
    account: AccountId,
    state: ChatState,
}

impl Party {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).unwrap();
        Self {
            store,
            account,
            state: ChatState::default(),
        }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
    fn publish_at(&mut self, now_unix: u64) -> GeneratedBundle {
        let ik = self.ik();
        let gen = generate_bundle(&self.store, self.account.handle(), ik, 5).unwrap();
        let otks: Vec<([u8; 32], [u8; 32])> = gen
            .bundle
            .otks
            .iter()
            .zip(gen.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        self.state
            .vault
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, now_unix);
        gen
    }
    fn publish(&mut self) -> GeneratedBundle {
        self.publish_at(TEST_NOW_UNIX)
    }
    fn start(&mut self, peer: &[u8; 32], spk: &[u8; 32], opk: Option<[u8; 32]>) {
        let ik = self.ik();
        self.state
            .start_initiator_session(&self.store, self.account.handle(), &ik, peer, spk, opk)
            .unwrap();
    }
    fn send(&mut self, peer: &[u8; 32], id: u8, body: &str) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                &ChatContent::Text {
                    id: [id; 16],
                    body: body.into(),
                },
            )
            .unwrap()
    }
    /// Mirrors `chat_manager.rs::Party::recv`: a first contact transparently auto-accepts, since
    /// this file exercises session/recovery correctness, not the task-2.10 request-queue UX.
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let ik = self.ik();
        match self
            .state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
        {
            Err(ChatError::MessageRequest) => Ok(self
                .state
                .accept_request(from)
                .expect("just gated by open_inbound")
                .intro),
            other => other,
        }
    }
    fn recv_err(&mut self, from: &[u8; 32], blob: &[u8]) -> Option<ChatError> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
            .err()
    }
    /// Re-sign a (possibly modified) envelope under this party's identity key, so it is authentic
    /// rather than merely forged.
    fn resign(&self, mut env: MessageEnvelope) -> Vec<u8> {
        let sig = meridian_identity::sign(&self.store, self.account.handle(), &env.signing_bytes())
            .unwrap();
        env.sig = *sig.as_bytes();
        env.to_blob().unwrap()
    }
}

/// Deterministic CBOR of the whole chat state, for byte-identical before/after comparisons (same
/// trick as `chat_manager.rs`/`preamble_mutation.rs` — `seal_at_rest`'s AEAD nonce is random).
fn state_bytes(state: &ChatState) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(state, &mut out).unwrap();
    out
}

/// Same as [`state_bytes`], but with the `desync_counts` map stripped out first — mirrors
/// `chat_manager.rs`'s `state_bytes_excluding_desync_counts` (task 4.9) exactly, for the same
/// reason: a rejected `Desync` classification is *expected* to change that one bookkeeping field
/// (that is its entire purpose), so it is excluded here to keep the byte-identical comparison
/// meaningful for everything else — most importantly `sessions` and the new
/// `responder_session_ek` freshness-tracking field this review fixup adds, both of which MUST stay
/// byte-identical across a correctly-rejected replay.
fn state_bytes_excluding_desync_counts(state: &ChatState) -> Vec<u8> {
    use ciborium::value::Value;
    let bytes = state_bytes(state);
    let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
    if let Value::Map(entries) = &mut value {
        entries.retain(|(k, _)| !matches!(k, Value::Text(t) if t == "desync_counts"));
    }
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

/// Corrupt an authentic envelope's ratchet header (byte inside `enc_header`, past the 2-byte length
/// prefix) and re-sign it under `signer` — the exact technique `chat_manager.rs`'s task-1.18 test
/// uses to construct a genuine, signature-valid-but-undecryptable `Desync` condition.
fn mangle_and_resign(signer: &Party, blob: &[u8]) -> Vec<u8> {
    let mut env = MessageEnvelope::from_blob(blob).unwrap();
    env.ct[2] ^= 0xFF;
    signer.resign(env)
}

// -- deliverable 3, bullet 1: end-to-end, both directions --------------------------------------

/// The flagship scenario: Alice's session with Bob *looks* healthy from her own side, but every
/// inbound envelope from Bob fails to decrypt (an attacker replaying/corrupting traffic, or Bob
/// having genuinely lost his own state — indistinguishable from Alice's vantage point). Once
/// `DESYNC_RECOVERY_THRESHOLD` consecutive failures are reached, `desync::attempt_recovery` forces
/// a fresh initiator session (`ChatState::replace_session_as_initiator`); Bob — who still holds his
/// original, otherwise-healthy session for Alice, now stale relative to her new one — accepts the
/// fresh re-initiation via `open_bytes`'s task-4.9 discriminator fix, and messages flow again in
/// both directions.
#[test]
fn repeated_desync_triggers_guarded_recovery_and_restores_the_session_end_to_end() {
    let mut alice = Party::new("e2e.a");
    let mut bob = Party::new("e2e.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap(); // both sides confirmed now

    // Drive DESYNC_RECOVERY_THRESHOLD consecutive Desyncs on Alice's inbound path.
    for i in 0..DESYNC_RECOVERY_THRESHOLD {
        assert!(
            !alice.state.recovery_recommended(&bob_ik),
            "must not fire before the threshold"
        );
        let noise = bob.send(&alice_ik, (100 + i) as u8, "noise");
        let mangled = mangle_and_resign(&bob, &noise);
        assert!(
            matches!(alice.recv_err(&bob_ik, &mangled), Some(ChatError::Desync)),
            "iteration {i} must classify as Desync"
        );
    }
    assert_eq!(alice.state.desync_count(&bob_ik), DESYNC_RECOVERY_THRESHOLD);
    assert!(alice.state.recovery_recommended(&bob_ik));

    // Alice's trust record for Bob is healthy (an ordinary TOFU-pinned contact) — the gate reads Ok.
    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "e2e.b", TEST_NOW_UNIX);
    assert_eq!(trust.can_send(&bob_ik), SendGate::Ok);

    // Bob republishes a fresh bundle — the CLI-side equivalent of `fetch_with_retry` finding a
    // live, current bundle (this crate stays I/O-free; the caller supplies the already-fetched,
    // already-verified bundle).
    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);

    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &bob_ik, // bundle_owner_ik == peer_ik: the ordinary, non-key-change case
        &bob_gen2.bundle.spk,
        bob_gen2.bundle.otks.first().copied(),
        "e2e.b",
        TEST_NOW_UNIX + 2,
    )
    .unwrap();
    assert_eq!(outcome, RecoveryOutcome::Recovered);
    assert_eq!(
        alice.state.desync_count(&bob_ik),
        0,
        "an attempted recovery must reset the counter regardless of outcome"
    );

    // Bob's OWN session was never touched by any of this — from his perspective he simply receives
    // a fresh prekey envelope from an already-known identity while holding a (now-stale) session.
    let reinit = alice.send(&bob_ik, 20, "recovered!");
    let got = bob
        .recv(&alice_ik, &reinit)
        .expect("Bob must accept the fresh re-initiation despite holding a stale session");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [20u8; 16],
            body: "recovered!".into()
        }
    );

    // And the channel is genuinely live in both directions again.
    let ack = bob.send(&alice_ik, 21, "welcome back");
    let got2 = alice.recv(&bob_ik, &ack).unwrap();
    assert_eq!(
        got2,
        ChatContent::Text {
            id: [21u8; 16],
            body: "welcome back".into()
        }
    );
}

/// Isolates the "safe half" bug fix on its own, independent of the threshold/`attempt_recovery`
/// machinery: Alice loses her session state outright (a wiped store / restored backup — task
/// 1.18's original scenario) and re-initiates via the already-working `start_initiator_session`;
/// Bob, still holding the stale session, must accept it on the very **first** such envelope — no
/// threshold applies here, since this is `open_bytes` recognizing a cryptographically-proven
/// legitimate re-initiation, not Bob's own side deciding to reset anything.
#[test]
fn open_bytes_accepts_a_fresh_reinitiation_despite_a_stale_session_on_the_first_attempt() {
    let mut alice = Party::new("safe.a");
    let mut bob = Party::new("safe.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hello");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi alice");
    alice.recv(&bob_ik, &reply).unwrap();

    // Alice loses her session state outright.
    alice.state = ChatState::default();
    assert!(!alice.state.has_session(&bob_ik));

    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);
    assert_ne!(
        bob_gen1.bundle.spk, bob_gen2.bundle.spk,
        "must be a genuinely fresh generation"
    );
    alice.start(&bob_ik, &bob_gen2.bundle.spk, Some(bob_gen2.bundle.otks[0]));
    let reinit = alice.send(&bob_ik, 3, "it's me again");

    let got = bob
        .recv(&alice_ik, &reinit)
        .expect("the re-initiation must be accepted, not permanently stuck as Desync");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [3u8; 16],
            body: "it's me again".into()
        }
    );
    assert_eq!(
        bob.state.desync_count(&alice_ik),
        0,
        "acceptance on the first attempt must never even register as a Desync"
    );

    let ack = bob.send(&alice_ik, 4, "welcome back");
    let got2 = alice.recv(&bob_ik, &ack).unwrap();
    assert_eq!(
        got2,
        ChatContent::Text {
            id: [4u8; 16],
            body: "welcome back".into()
        }
    );
}

// -- deliverable 3, bullet 2: single Desync must not trigger recovery --------------------------

#[test]
fn a_single_desync_does_not_recommend_recovery() {
    let mut alice = Party::new("single.a");
    let mut bob = Party::new("single.b");
    let bob_gen = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start(&bob_ik, &bob_gen.bundle.spk, Some(bob_gen.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap();

    let noise = bob.send(&alice_ik, 3, "noise");
    let mangled = mangle_and_resign(&bob, &noise);
    assert!(matches!(
        alice.recv_err(&bob_ik, &mangled),
        Some(ChatError::Desync)
    ));

    assert_eq!(alice.state.desync_count(&bob_ik), 1);
    assert!(
        !alice.state.recovery_recommended(&bob_ik),
        "a single replayed/corrupted envelope must never be enough to trigger automatic recovery \
         on its own — this is precisely the oracle task 1.18 exists to prevent"
    );
    // Sanity: the threshold itself must not be 1 — checked at compile time, since
    // `DESYNC_RECOVERY_THRESHOLD` is a `const` (clippy: assertions on a constant belong in a
    // `const` block, not a runtime `assert!`).
    const _: () = assert!(DESYNC_RECOVERY_THRESHOLD > 1);
}

/// The threshold is a hard boundary, not merely "eventually": every count below it must read
/// `false`, and reaching it exactly must read `true`.
#[test]
fn recovery_recommended_only_crosses_at_exactly_the_threshold() {
    let mut alice = Party::new("boundary.a");
    let mut bob = Party::new("boundary.b");
    let bob_gen = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start(&bob_ik, &bob_gen.bundle.spk, Some(bob_gen.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap();

    for i in 0..DESYNC_RECOVERY_THRESHOLD {
        assert!(
            !alice.state.recovery_recommended(&bob_ik),
            "must read false before the {i}th Desync of this run"
        );
        let noise = bob.send(&alice_ik, (10 + i) as u8, "noise");
        let mangled = mangle_and_resign(&bob, &noise);
        assert!(matches!(
            alice.recv_err(&bob_ik, &mangled),
            Some(ChatError::Desync)
        ));
    }
    assert_eq!(alice.state.desync_count(&bob_ik), DESYNC_RECOVERY_THRESHOLD);
    assert!(alice.state.recovery_recommended(&bob_ik));

    // A subsequent healthy decrypt resets the counter back to zero.
    let healthy = bob.send(&alice_ik, 99, "back to normal");
    alice.recv(&bob_ik, &healthy).unwrap();
    assert_eq!(alice.state.desync_count(&bob_ik), 0);
    assert!(!alice.state.recovery_recommended(&bob_ik));
}

// -- deliverable 3, bullet 3: a substituted key is never silently accepted ----------------------

/// The canonical wording (`docs/security/verification-ux.md`) must, in substance: name the safety
/// number, name the benign explanation, name the interception possibility, and offer verification
/// — never collapse into pure reassurance. Mirrors `key_change_gate.rs`'s own
/// `assert_canonical_substance` (task 4.4's own coverage of `trust.rs`'s wording functions
/// directly); duplicated here in miniature, rather than factored into a shared test-support crate,
/// since this is the only other call site and the check is a handful of `contains` assertions —
/// not worth the extra Cargo wiring for one reuse (task 4.10 judgment call).
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
        "must state the interception possibility, never soften into pure reassurance: {reason}"
    );
    assert!(
        lower.contains("verify"),
        "must offer a Verify action: {reason}"
    );
}

#[test]
fn attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it() {
    let mut alice = Party::new("subst.a");
    let mut bob = Party::new("subst.b");
    let mut mallory = Party::new("subst.m");
    let bob_gen = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let mallory_ik = mallory.ik();
    let mallory_gen = mallory.publish_at(TEST_NOW_UNIX);

    alice.start(&bob_ik, &bob_gen.bundle.spk, Some(bob_gen.bundle.otks[0]));
    let _ = alice.send(&bob_ik, 1, "hi"); // just needs an existing session to "recover"

    // Case 1: Bob is a merely-*pinned* (TOFU) contact — a surfaced key change must warn, not
    // silently accept, and must not install any session under the substituted key.
    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "subst.b", TEST_NOW_UNIX);

    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &mallory_ik, // bundle genuinely verified under a DIFFERENT key than peer_ik
        &mallory_gen.bundle.spk,
        mallory_gen.bundle.otks.first().copied(),
        "subst.b",
        TEST_NOW_UNIX + 1,
    )
    .unwrap();
    let reason = match &outcome {
        RecoveryOutcome::Gated(SendGate::Warn(reason)) => reason.clone(),
        other => panic!("got: {other:?}"),
    };
    assert_canonical_substance(&reason);
    assert!(
        reason.to_lowercase().contains("pause"),
        "a pinned-contact substitution must say sends are PAUSED (Warn), not blocked outright: \
         {reason}"
    );
    assert_eq!(trust.trust_state(&mallory_ik), TrustState::PinnedKeyChanged);
    assert!(
        !alice.state.has_session(&mallory_ik),
        "no session may be installed under the substituted key while gated"
    );

    // Case 2: Bob is a *verified* contact — the same surfaced substitution hard-blocks, no bypass
    // "because a recovery flow was already in progress". Mirrors
    // `key_change_gate.rs::verified_contact_key_change_blocks_sends_with_no_bypass`'s
    // reason-string substance assertions, driven this time through `attempt_recovery` itself
    // rather than directly against `TrustStore`.
    let mut trust2 = TrustStore::default();
    trust2.observe(bob_ik, "subst.b", TEST_NOW_UNIX);
    trust2.mark_verified(&bob_ik).unwrap();

    let outcome2 = attempt_recovery(
        &mut alice.state,
        &mut trust2,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &mallory_ik,
        &mallory_gen.bundle.spk,
        mallory_gen.bundle.otks.get(1).copied(),
        "subst.b",
        TEST_NOW_UNIX + 2,
    )
    .unwrap();
    let reason2 = match &outcome2 {
        RecoveryOutcome::Gated(SendGate::Blocked(reason)) => reason.clone(),
        other => panic!(
            "a surfaced key-change substitution against a VERIFIED contact must hard-block \
             (SendGate::Blocked), never merely warn or — worse — silently recover just because a \
             recovery flow was already in progress. got: {other:?}"
        ),
    };
    assert_canonical_substance(&reason2);
    assert!(
        reason2.to_lowercase().contains("block"),
        "a verified-contact substitution must say sends are BLOCKED, not merely paused: {reason2}"
    );
    assert_eq!(trust2.trust_state(&mallory_ik), TrustState::Blocked);
    assert!(
        !alice.state.has_session(&mallory_ik),
        "no session may be installed under the substituted key while blocked"
    );

    // Adversarial: the pinned-case escape hatch (`acknowledge_key_change`) must not silently clear
    // a Blocked (verified-contact) key change either — mirrors `key_change_gate.rs`'s own bypass
    // sweep, checked here on the SAME `TrustStore` `attempt_recovery` just gated, not a fresh one.
    let err = trust2
        .acknowledge_key_change(&mallory_ik)
        .expect_err("acknowledging a Blocked (verified) key change must be a hard error");
    assert!(matches!(
        err,
        meridian_core::trust::TrustError::NotAcknowledgeable
    ));
    assert_eq!(trust2.can_send(&mallory_ik), SendGate::Blocked(reason2));
}

// -- deliverable 3, bullet 4: signature check still runs before the new branch ------------------

#[test]
fn mutated_preamble_is_rejected_by_signature_before_the_recovery_fallback_ever_runs() {
    let mut alice = Party::new("mutate.a");
    let mut bob = Party::new("mutate.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();

    // Alice re-initiates fresh — Bob now holds a stale session for her, exactly the scenario the
    // task-4.9 fallback branch exists for.
    alice.state = ChatState::default();
    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);
    alice.start(&bob_ik, &bob_gen2.bundle.spk, Some(bob_gen2.bundle.otks[0]));
    let reinit = alice.send(&bob_ik, 2, "it's me");

    // An on-path attacker mutates the preamble WITHOUT re-signing (the capability of someone with
    // the bytes but not Alice's identity key) — must be rejected by the signature check, which
    // still runs unconditionally before either session-establishment branch (first-contact or the
    // new recovery fallback) is ever reached.
    let mut env = MessageEnvelope::from_blob(&reinit).unwrap();
    env.prekey.as_mut().unwrap().used_opk = None; // downgrade to OTK-free X3DH — a preamble mutation
    let mutated = env.to_blob().unwrap();

    let before = state_bytes(&bob.state);
    match bob.recv_err(&alice_ik, &mutated) {
        Some(ChatError::BadSignature) => {}
        other => panic!(
            "a mutated preamble must be rejected by the ENVELOPE SIGNATURE specifically, before \
             either the first-contact or task-4.9 recovery-fallback session-establishment branch \
             runs. Got: {other:?}"
        ),
    }
    assert_eq!(
        before,
        state_bytes(&bob.state),
        "a signature failure must touch nothing at all — including the new desync_counts \
         bookkeeping, which only the UndecryptableHeader branch touches"
    );
    assert_eq!(bob.state.desync_count(&alice_ik), 0);

    // The genuine (unmutated) re-initiation still works afterwards — proving the rejection above
    // broke nothing.
    let got = bob.recv(&alice_ik, &reinit).unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "it's me".into()
        }
    );
}

// -- deliverable 3, bullet 5: refused while Warn/Blocked, resumes once Ok ----------------------

#[test]
fn attempt_recovery_is_refused_while_gated_and_succeeds_once_the_gate_clears() {
    let mut alice = Party::new("gate.a");
    let mut bob = Party::new("gate.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();

    // Bob's contact is currently `PinnedKeyChanged` (Warn) from an unrelated, already-in-flight key
    // change — the exact state that must pause an automatic re-handshake rather than layering one
    // on top of an already-flagged trust concern.
    let mut trust = TrustStore::default();
    let stand_in_prior_key = [0x11u8; 32];
    trust.observe(stand_in_prior_key, "gate.b", TEST_NOW_UNIX);
    trust
        .observe_key_change(&stand_in_prior_key, bob_ik, "gate.b", TEST_NOW_UNIX + 1)
        .unwrap();
    assert!(matches!(trust.can_send(&bob_ik), SendGate::Warn(_)));

    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 2);
    let session_before = state_bytes(&alice.state);

    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &bob_ik,
        &bob_gen2.bundle.spk,
        bob_gen2.bundle.otks.first().copied(),
        "gate.b",
        TEST_NOW_UNIX + 3,
    )
    .unwrap();
    assert!(
        matches!(outcome, RecoveryOutcome::Gated(SendGate::Warn(_))),
        "got: {outcome:?}"
    );
    assert_eq!(
        session_before,
        state_bytes(&alice.state),
        "a gated (refused) recovery attempt must not touch the existing session at all"
    );

    // Clear the warning (the ordinary 4.4 acknowledge path — not a bypass this task adds) and
    // retry: the same call must now succeed.
    trust.acknowledge_key_change(&bob_ik).unwrap();
    assert_eq!(trust.can_send(&bob_ik), SendGate::Ok);

    let outcome2 = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &bob_ik,
        &bob_gen2.bundle.spk,
        bob_gen2.bundle.otks.first().copied(),
        "gate.b",
        TEST_NOW_UNIX + 4,
    )
    .unwrap();
    assert_eq!(outcome2, RecoveryOutcome::Recovered);

    // And it actually works end to end: Bob (still holding his original session for Alice) accepts
    // the fresh re-initiation.
    let reinit = alice.send(&bob_ik, 5, "recovered after ack");
    let got = bob.recv(&alice_ik, &reinit).unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [5u8; 16],
            body: "recovered after ack".into()
        }
    );
}

// -- review fixup (blocking finding): the freshness gate on open_bytes's fallback --------------
//
// Both the architect and security-reviewer independently found that the pre-fixup `open_bytes`
// fallback checked only *authenticity* (the envelope's signature) before attempting fresh
// establishment, never *freshness*. Because OTK-free X3DH (`used_opk: None`, legal and used here)
// is fully deterministic in its public inputs, replaying a peer's own original opening envelope
// byte-for-byte — once the receiver's ratchet has genuinely advanced past it — reconstructs a
// byte-identical initial session and decrypts the also-replayed ciphertext successfully every
// time, silently rolling a live, forward-secret-advanced session back to its own initial state
// through the ordinary `Ok` return path. This test constructs that exact attack and asserts it is
// now rejected as `ChatError::Desync`, with Bob's session for Alice left byte-identically
// unchanged — i.e. that the fix actually closes the gap, not merely that some error comes back.

/// Replaying Alice's own original, unmodified opening envelope against Bob's now-advanced session
/// must be rejected as `Desync`, never accepted as a "fresh re-initiation" — even though the
/// signature verifies (it's an untouched, genuinely-Alice-signed envelope) and even though OTK-free
/// X3DH would let it reconstruct the exact original session deterministically.
#[test]
fn replaying_the_original_opening_envelope_after_ratchet_advancement_is_rejected_not_accepted() {
    let mut alice = Party::new("replay.a");
    let mut bob = Party::new("replay.b");
    let bob_gen = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // OTK-free X3DH: the exploitable case, since the SPK is never consumed on use (unlike an OTK,
    // which single-use would otherwise close this off after the very first establishment attempt).
    alice.start(&bob_ik, &bob_gen.bundle.spk, None);

    // opener -> reply -> one more message from Alice: exactly enough for Bob's header keys (used to
    // decrypt Alice's messages) to rotate past what her original opening envelope was encrypted
    // under, per this test module's doc comment above.
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap(); // Bob establishes a RESPONDER session for Alice here
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap(); // Alice confirmed; her ratchet steps to a new header key
    let third = alice.send(&bob_ik, 3, "one more, now ratcheted forward");
    let got_third = bob
        .recv(&alice_ik, &third)
        .expect("Bob must accept this ordinary, genuinely-fresh continuation message");
    assert_eq!(
        got_third,
        ChatContent::Text {
            id: [3u8; 16],
            body: "one more, now ratcheted forward".into()
        }
    );

    assert_eq!(bob.state.desync_count(&alice_ik), 0, "healthy so far");
    let before = state_bytes_excluding_desync_counts(&bob.state);

    // The attack: replay Alice's ORIGINAL, unmodified opening envelope byte-for-byte — not
    // corrupted, not mutated, exactly what she sent the very first time and what an on-path relay
    // could have simply recorded and replayed later.
    let replay_result = bob.recv_err(&alice_ik, &opening);
    assert!(
        matches!(replay_result, Some(ChatError::Desync)),
        "a replayed original opening envelope must be classified as an ordinary Desync — never \
         accepted as a fresh re-initiation — got: {replay_result:?}"
    );
    // The only thing allowed to change is the ordinary Desync bookkeeping (its entire purpose) —
    // asserted explicitly here, then excluded below so the rest of the comparison stays meaningful.
    assert_eq!(bob.state.desync_count(&alice_ik), 1);

    // The load-bearing assertion: Bob's session for Alice — and critically, the
    // `responder_session_ek` freshness record this fixup adds — is untouched, byte-for-byte, by
    // the replay attempt: no session-reset / PCS-rollback occurred. If the fix only changed which
    // error came back without actually refusing the fallback's session-replacement, this would
    // fail (the replayed opener would successfully reconstruct and install Alice's original,
    // rewound session state in place of the live, ratchet-advanced one).
    assert_eq!(
        before,
        state_bytes_excluding_desync_counts(&bob.state),
        "replaying the original opening envelope must leave the (already ratchet-advanced) \
         session completely untouched — a successful replay-triggered session replacement here \
         would be exactly the session-reset/PCS-rollback oracle this fix exists to close"
    );

    // And the live session is still genuinely usable afterwards — the replay attempt didn't even
    // leave it in some half-broken state.
    let fourth = alice.send(&bob_ik, 4, "still fine after the replay attempt");
    let got_fourth = bob.recv(&alice_ik, &fourth).unwrap();
    assert_eq!(
        got_fourth,
        ChatContent::Text {
            id: [4u8; 16],
            body: "still fine after the replay attempt".into()
        }
    );
}

// -- review fixup (item 1): replace_session_as_initiator's build-then-swap ordering -------------

/// A local failure inside [`ChatState::replace_session_as_initiator`]'s `Session::initiate` call
/// must leave the peer with their existing (stale-but-working) session untouched, not with no
/// session at all. `[0x02u8; 32]` is not a valid compressed Ed25519 point (confirmed via
/// `ed25519_dalek::VerifyingKey::from_bytes`), so passing it as `peer_ik` makes
/// `ed25519_pub_to_x25519` — the very first fallible step inside `x3dh::initiate` — fail cleanly,
/// cheaply, and deterministically, without needing any I/O or RNG-failure injection.
#[test]
fn replace_session_as_initiator_leaves_the_stale_session_intact_on_a_local_failure() {
    let mut alice = Party::new("swap.a");
    let mut bob = Party::new("swap.b");
    let bob_gen = bob.publish_at(TEST_NOW_UNIX);
    let bob_ik = bob.ik();

    // An invalid "peer" identity key standing in for `bob_ik` for this call only — never actually
    // used to route or authenticate anything real; it just needs to make `Session::initiate` fail.
    let invalid_peer_ik = [0x02u8; 32];

    // Establish a genuinely live, working session first — this is the "stale but working" session
    // that must survive the failed replacement attempt below.
    alice.start(&bob_ik, &bob_gen.bundle.spk, Some(bob_gen.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice.ik(), &opening).unwrap();
    assert!(alice.state.has_session(&bob_ik));
    let before = state_bytes(&alice.state);

    let alice_ik = alice.ik();
    let err = alice
        .state
        .replace_session_as_initiator(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &invalid_peer_ik,
            &bob_gen.bundle.spk,
            None,
        )
        .expect_err("an invalid peer identity key must fail Session::initiate cleanly");
    assert!(
        matches!(err, ChatError::Crypto(_)),
        "expected a clean CryptoError from x3dh::initiate's ed25519_pub_to_x25519 step, got: {err:?}"
    );

    // No session was ever installed for the invalid key (construction never succeeded).
    assert!(!alice.state.has_session(&invalid_peer_ik));

    // And — the actual point of this test — Bob's real, pre-existing session is completely
    // untouched: `replace_session_as_initiator`'s build-then-swap ordering never removed it, since
    // it targets a different peer key and construction for THAT call failed before any swap.
    assert_eq!(
        before,
        state_bytes(&alice.state),
        "a failed replace_session_as_initiator call for one peer must not touch any other peer's \
         session state"
    );
    assert!(alice.state.has_session(&bob_ik));

    // The pre-existing session is still fully live and usable.
    let ack = bob.send(&alice.ik(), 2, "still there");
    let got = alice.recv(&bob_ik, &ack).unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "still there".into()
        }
    );
}

// -- review fixup (item 2): the UnknownContact degrade path never auto-completes ----------------

/// If `attempt_recovery`'s bundle fetch surfaces a key change for a `peer_ik` with **no** prior
/// contact record at all (a should-not-happen-in-practice case both reviews flagged as untested),
/// the function must return [`RecoveryOutcome::UnknownIdentitySurfaced`] and touch neither `trust`
/// nor `chat` — never silently TOFU-pin the surfaced key and proceed to install a live session in
/// the same call.
#[test]
fn attempt_recovery_surfaces_an_unknown_identity_without_auto_completing() {
    let mut alice = Party::new("unknown.a");
    let ghost = Party::new("unknown.ghost"); // stands in for `peer_ik`: never observed by `trust`
    let mut mallory = Party::new("unknown.m"); // the bundle's actual (surfaced) signer
    let ghost_ik = ghost.ik();
    let mallory_ik = mallory.ik();
    let mallory_gen = mallory.publish_at(TEST_NOW_UNIX);

    // `chat` needs a session for `ghost_ik` to exist for this to be a realistic "recovery" call
    // (mirrors every other test in this file), but `trust` is deliberately never told about
    // `ghost_ik` at all — reproducing the "no prior contact record" precondition.
    alice.start(&ghost_ik, &[9u8; 32], None);
    let mut trust = TrustStore::default();
    assert_eq!(trust.trust_state(&ghost_ik), TrustState::New);

    let chat_before = state_bytes(&alice.state);
    let alice_ik = alice.ik();

    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &ghost_ik,
        &mallory_ik, // bundle genuinely verified under a key with NO prior record for ghost_ik
        &mallory_gen.bundle.spk,
        mallory_gen.bundle.otks.first().copied(),
        "unknown.ghost",
        TEST_NOW_UNIX + 1,
    )
    .unwrap();

    assert_eq!(
        outcome,
        RecoveryOutcome::UnknownIdentitySurfaced(mallory_ik),
        "an unknown-identity degrade must be surfaced distinctly, carrying the surfaced key"
    );
    // Never silently TOFU-pinned...
    assert_eq!(
        trust.trust_state(&mallory_ik),
        TrustState::New,
        "the surfaced key must NOT be silently observed/TOFU-pinned by attempt_recovery itself"
    );
    assert_eq!(trust.trust_state(&ghost_ik), TrustState::New);
    // ...and never silently completed into a live session either.
    assert!(!alice.state.has_session(&mallory_ik));
    assert_eq!(
        chat_before,
        state_bytes(&alice.state),
        "chat state must be completely untouched aside from the (already-asserted-elsewhere) \
         recovery-attempted counter reset"
    );
}

// -- review fixup (round 2, blocking finding): multi-generation replay through the history gap ---
//
// The first fixup's `responder_session_ek` was a single scalar per peer, overwritten on every new
// responder establishment. Both the architect and security-reviewer independently traced an
// exploitable gap: force a *second* genuine responder establishment for the same peer (attacker-
// forceable by driving the peer's own repeated-Desync recovery threshold against their *own* inbound
// path) and the freshness record for the *first* establishment's `ek_pub` is silently lost, so
// replaying the captured original opening envelope (OTK-free X3DH — never single-use-consumed, and
// the signed prekey it references never rotates mid-session, since the CLI publishes a bundle only
// once per invocation) is accepted again, rolling the session back to its very first ratchet state.
// This test constructs that exact two-establishment attack directly (the most direct construction of
// "Bob's `open_bytes` fallback accepts Alice's second genuine re-initiation", per this review
// fixup's own text) and asserts the replay of the FIRST envelope is still rejected once a SECOND,
// entirely genuine establishment has happened in between — which the pre-fix scalar design gets
// wrong.

/// Replaying the FIRST of two genuine openers must still be rejected after a second, entirely
/// genuine re-establishment for the same peer — even though the second establishment necessarily
/// changed which `ek_pub` the currently-held session was built from.
#[test]
fn replaying_the_first_of_two_genuine_openers_is_still_rejected_after_the_second() {
    let mut alice = Party::new("multigen.a");
    let mut bob = Party::new("multigen.b");
    let bob_gen = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // First genuine opener: OTK-free X3DH — the exploitable case, since the SPK is never consumed
    // on use (unlike a single-use OTK, which would close this off after one establishment attempt).
    alice.start(&bob_ik, &bob_gen.bundle.spk, None);
    let opening_1 = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening_1)
        .expect("Bob's first-ever responder establishment for Alice");

    // Second, entirely genuine re-establishment for the SAME peer, against the SAME still-current
    // SPK generation — no republish in between, exactly the "a real client may not republish for
    // the lifetime of a long-running session" fact this exploit turns on. Alice loses her own
    // session state (the ordinary "safe half" scenario — a restored backup / wiped store) and
    // re-initiates fresh; `Session::initiate` always draws a brand-new random ephemeral, so this is
    // guaranteed to be a genuinely different `ek_pub` from the first.
    alice.state = ChatState::default();
    alice.start(&bob_ik, &bob_gen.bundle.spk, None);
    let opening_2 = alice.send(&bob_ik, 2, "it's me again");
    let got_2 = bob
        .recv(&alice_ik, &opening_2)
        .expect("Bob's second, genuine responder re-establishment for the same peer");
    assert_eq!(
        got_2,
        ChatContent::Text {
            id: [2u8; 16],
            body: "it's me again".into()
        }
    );

    // The live channel works normally after the second establishment.
    let ack = bob.send(&alice_ik, 3, "hi again");
    alice.recv(&bob_ik, &ack).unwrap();

    let before = state_bytes_excluding_desync_counts(&bob.state);

    // THE ATTACK: replay Alice's ORIGINAL (first) opening envelope, captured byte-for-byte, now
    // that Bob's live session has moved on to the second establishment. This is exactly what the
    // pre-fix scalar `responder_session_ek` could no longer catch, since its one slot had already
    // been overwritten by the second establishment's `ek_pub`.
    let replay_result = bob.recv_err(&alice_ik, &opening_1);
    assert!(
        matches!(replay_result, Some(ChatError::Desync)),
        "a replay of the FIRST genuine opener, after a SECOND genuine establishment has happened \
         in between, must still be rejected as Desync — got: {replay_result:?}"
    );
    assert_eq!(bob.state.desync_count(&alice_ik), 1);
    assert_eq!(
        before,
        state_bytes_excluding_desync_counts(&bob.state),
        "the replay must leave the (second-establishment) session completely untouched — a \
         successful session-replacement here would silently roll the session back to its very \
         first ratchet state, exactly the multi-generation replay gap this test exists to close"
    );

    // The live session is still usable afterwards.
    let fourth = alice.send(&bob_ik, 4, "still fine");
    let got_fourth = bob.recv(&alice_ik, &fourth).unwrap();
    assert_eq!(
        got_fourth,
        ChatContent::Text {
            id: [4u8; 16],
            body: "still fine".into()
        }
    );
}

/// Companion to the multi-generation replay test above: once the SPK generation a stale `ek_pub`
/// entry referenced has genuinely *expired* (task 1.31's grace window fully passing — not merely
/// superseded by a second establishment), the pruned entry stops blocking a replay through the
/// freshness gate — but the replay still fails, safely, through the independent `UnknownPrekey`
/// path `establish_responder_session` already takes for any prekey referencing material the vault no
/// longer holds. Confirms pruning doesn't regress that already-safe fallback.
#[test]
fn replay_after_the_referenced_spk_generation_genuinely_expires_still_fails_safely() {
    let mut alice = Party::new("expire.a");
    let mut bob = Party::new("expire.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // First genuine opener, OTK-free, against generation 1.
    alice.start(&bob_ik, &bob_gen1.bundle.spk, None);
    let opening_1 = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening_1).unwrap();

    // Bob republishes — generation 1 becomes the retained "previous" generation, on a bounded grace
    // window (task 1.31).
    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);
    assert_ne!(
        bob_gen1.bundle.spk, bob_gen2.bundle.spk,
        "must be a genuinely fresh generation"
    );

    // Second, genuine re-establishment — against the NEW generation (an ordinary reconnect, not a
    // 1.31 grace-window race).
    alice.state = ChatState::default();
    alice.start(&bob_ik, &bob_gen2.bundle.spk, None);
    let opening_2 = alice.send(&bob_ik, 2, "it's me again");
    bob.recv(&alice_ik, &opening_2).unwrap();

    // Generation 1's grace window fully passes; Bob's inbound path retires it exactly as the CLI
    // does before every inbound open (task 1.31) — see `ChatState::expire_previous_generation`
    // (task 4.9 second-round fixup: this now also prunes the now-unreachable `ek_pub` entry).
    bob.state
        .expire_previous_generation(TEST_NOW_UNIX + 1 + PREV_GENERATION_GRACE_SECS);

    let before = state_bytes_excluding_desync_counts(&bob.state);

    // Replay the ORIGINAL opener, now referencing a genuinely expired generation. The freshness
    // gate can no longer catch it (its entry was pruned) — but it must still fail, safely, via
    // `establish_responder_session`'s own `UnknownPrekey` (the vault no longer holds generation 1's
    // secret at all), which `open_bytes`'s fallback already treats as an ordinary failed recovery
    // attempt (falls through to `Desync`, state untouched) — a different, already-safe failure mode,
    // not a regression.
    let replay_result = bob.recv_err(&alice_ik, &opening_1);
    assert!(
        matches!(replay_result, Some(ChatError::Desync)),
        "a replay referencing a genuinely expired SPK generation must still fail closed — got: \
         {replay_result:?}"
    );
    assert_eq!(
        before,
        state_bytes_excluding_desync_counts(&bob.state),
        "the replay must still leave the live session completely untouched even once its freshness \
         entry has been pruned"
    );

    // The live session is still usable afterwards.
    let ack = bob.send(&alice_ik, 3, "still there");
    let got = alice.recv(&bob_ik, &ack).unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [3u8; 16],
            body: "still there".into()
        }
    );
}

// -- review fixup (test-engineer, required by the FIRST review round, never actually added) -------
//
// DESYNC_RECOVERY_THRESHOLD's doc comment and ChatError::Desync's doc comment both claim an attacker
// who can force Desync on demand is bounded to at most one recovery attempt per
// DESYNC_RECOVERY_THRESHOLD forced failures — not one per failure. No test proved it. These two
// tests drive two full bursts each (one ending in `Recovered`, one in `Gated`), confirming the
// counter resets exactly once per burst and genuinely requires a FULL second burst — not merely one
// more failure — to re-arm.

/// Drive `n` consecutive, genuinely-mangled `Desync`s from `bob` (sending to `alice_ik`) against
/// `alice`'s inbound path for `bob_ik`, asserting each one classifies as `Desync`. Mirrors this
/// file's own `mangle_and_resign`-based technique, factored out since both burst tests below need it
/// twice.
fn drive_desync_burst(
    alice: &mut Party,
    bob: &mut Party,
    alice_ik: &[u8; 32],
    bob_ik: &[u8; 32],
    next_id: &mut u8,
    n: u32,
) {
    for _ in 0..n {
        let noise = bob.send(alice_ik, *next_id, "noise");
        *next_id = next_id.wrapping_add(1);
        let mangled = mangle_and_resign(bob, &noise);
        assert!(matches!(
            alice.recv_err(bob_ik, &mangled),
            Some(ChatError::Desync)
        ));
    }
}

#[test]
fn recovery_recommended_requires_a_full_new_burst_after_a_successful_recovery_resets_it() {
    let mut alice = Party::new("oracle.a");
    let mut bob = Party::new("oracle.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap();

    let mut next_id: u8 = 100;

    // Burst 1: exactly DESYNC_RECOVERY_THRESHOLD consecutive Desyncs.
    drive_desync_burst(
        &mut alice,
        &mut bob,
        &alice_ik,
        &bob_ik,
        &mut next_id,
        DESYNC_RECOVERY_THRESHOLD,
    );
    assert!(alice.state.recovery_recommended(&bob_ik));

    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "oracle.b", TEST_NOW_UNIX);
    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);
    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &bob_ik,
        &bob_gen2.bundle.spk,
        bob_gen2.bundle.otks.first().copied(),
        "oracle.b",
        TEST_NOW_UNIX + 2,
    )
    .unwrap();
    assert_eq!(outcome, RecoveryOutcome::Recovered);
    assert!(
        !alice.state.recovery_recommended(&bob_ik),
        "an attempted (and here, successful) recovery must reset the counter immediately"
    );

    // DESYNC_RECOVERY_THRESHOLD - 1 further Desyncs: the actual load-bearing assertion — proves one
    // burst short of a full second threshold is NOT enough to re-arm.
    drive_desync_burst(
        &mut alice,
        &mut bob,
        &alice_ik,
        &bob_ik,
        &mut next_id,
        DESYNC_RECOVERY_THRESHOLD - 1,
    );
    assert!(
        !alice.state.recovery_recommended(&bob_ik),
        "one burst short of a full second threshold must not be enough to re-arm recovery — the \
         actual N-replay-oracle bound: at most one recovery attempt per DESYNC_RECOVERY_THRESHOLD \
         forced failures, never one per failure"
    );

    // Exactly one more Desync completes a second full burst.
    drive_desync_burst(&mut alice, &mut bob, &alice_ik, &bob_ik, &mut next_id, 1);
    assert!(
        alice.state.recovery_recommended(&bob_ik),
        "a full second burst must re-arm recovery"
    );
}

#[test]
fn recovery_recommended_requires_a_full_new_burst_after_a_gated_refusal_resets_it_too() {
    let mut alice = Party::new("oracle-gated.a");
    let mut bob = Party::new("oracle-gated.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap();

    // Bob is gated: an unresolved key-change warning, exactly like
    // `attempt_recovery_is_refused_while_gated_and_succeeds_once_the_gate_clears`.
    let mut trust = TrustStore::default();
    let stand_in_prior_key = [0x22u8; 32];
    trust.observe(stand_in_prior_key, "oracle-gated.b", TEST_NOW_UNIX);
    trust
        .observe_key_change(
            &stand_in_prior_key,
            bob_ik,
            "oracle-gated.b",
            TEST_NOW_UNIX + 1,
        )
        .unwrap();
    assert!(matches!(trust.can_send(&bob_ik), SendGate::Warn(_)));

    let mut next_id: u8 = 100;
    drive_desync_burst(
        &mut alice,
        &mut bob,
        &alice_ik,
        &bob_ik,
        &mut next_id,
        DESYNC_RECOVERY_THRESHOLD,
    );
    assert!(alice.state.recovery_recommended(&bob_ik));

    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 2);
    let outcome = attempt_recovery(
        &mut alice.state,
        &mut trust,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        &bob_ik,
        &bob_gen2.bundle.spk,
        bob_gen2.bundle.otks.first().copied(),
        "oracle-gated.b",
        TEST_NOW_UNIX + 3,
    )
    .unwrap();
    assert!(
        matches!(outcome, RecoveryOutcome::Gated(SendGate::Warn(_))),
        "got: {outcome:?}"
    );
    assert!(
        !alice.state.recovery_recommended(&bob_ik),
        "a gated (refused) attempt must reset the counter exactly like a successful one"
    );

    // Same load-bearing property, on the refusal path this time: a full second burst is still
    // required to re-arm.
    drive_desync_burst(
        &mut alice,
        &mut bob,
        &alice_ik,
        &bob_ik,
        &mut next_id,
        DESYNC_RECOVERY_THRESHOLD - 1,
    );
    assert!(!alice.state.recovery_recommended(&bob_ik));

    drive_desync_burst(&mut alice, &mut bob, &alice_ik, &bob_ik, &mut next_id, 1);
    assert!(alice.state.recovery_recommended(&bob_ik));
}

// -- review fixup (test-engineer): responder_session_ek survives seal_at_rest/open_at_rest --------

/// `responder_session_ek`'s *content*, not merely its presence, must survive the sealed-at-rest
/// round trip (mirrors `chat_manager.rs`'s `state_survives_sealed_restart`): establish a responder
/// session (populating the field), seal, reopen, and confirm a replay of the original opening
/// envelope is still rejected post-reopen — proving the freshness record itself, not just the
/// session, made the round trip.
#[test]
fn responder_session_ek_freshness_protection_survives_sealed_restart() {
    let mut alice = Party::new("persist.a");
    let mut bob = Party::new("persist.b");
    let bob_gen = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // OTK-free X3DH: the exploitable case if the freshness record were lost.
    alice.start(&bob_ik, &bob_gen.bundle.spk, None);
    let opening = alice.send(&bob_ik, 1, "hi");
    bob.recv(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi back");
    alice.recv(&bob_ik, &reply).unwrap();
    let third = alice.send(&bob_ik, 3, "ratcheted forward");
    bob.recv(&alice_ik, &third).unwrap();

    // Seal Bob's state, drop it, and reload it from the sealed bytes.
    let sealed = bob
        .state
        .seal_at_rest(&bob.store, bob.account.handle())
        .unwrap();
    bob.state = ChatState::open_at_rest(&bob.store, bob.account.handle(), &sealed).unwrap();

    let before = state_bytes_excluding_desync_counts(&bob.state);

    // Replay the original opening envelope AFTER the reopen: still rejected — proving the
    // freshness record's content, not merely the session, survived the round trip.
    let replay_result = bob.recv_err(&alice_ik, &opening);
    assert!(
        matches!(replay_result, Some(ChatError::Desync)),
        "the freshness protection must survive seal_at_rest/open_at_rest — got: {replay_result:?}"
    );
    assert_eq!(
        before,
        state_bytes_excluding_desync_counts(&bob.state),
        "the replay must leave the reopened session untouched"
    );

    // The live session is still usable after the reopen.
    let fourth = alice.send(&bob_ik, 4, "still fine after reopen");
    let got = bob.recv(&alice_ik, &fourth).unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [4u8; 16],
            body: "still fine after reopen".into()
        }
    );
}
