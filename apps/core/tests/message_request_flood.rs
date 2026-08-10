//! Task 3.10 (review finding F5) — bounding the message-request gate against a stranger flood.
//!
//! OTK-free X3DH is legal (`used_opk: None`), so a first-contact envelope costs its sender
//! nothing but a fresh identity key: nothing upstream of [`ChatState::open_inbound`] rate-limits
//! how many distinct strangers can each land a `Session` + `MessageRequest` in the sealed-at-rest
//! `ChatState`. Before task 3.10, that queue (and every orphaned `Session` behind it) grew
//! monotonically — an at-rest storage-amplification DoS. This file proves:
//!
//! 1. `N + K` distinct fresh identity keys each sending one first-contact envelope leaves
//!    `ChatState` bounded at [`meridian_core::chat::MAX_PENDING_REQUESTS`], with the oldest `K`
//!    evicted and **no orphaned `Session`s** left behind for the evicted senders.
//! 2. An oversized `intro` is capped, never dropped — the `ChatError::MessageRequest` /
//!    "there's a queued entry" invariant every caller relies on still holds.
//! 3. A real, **accepted** (decided) request survives eviction pressure even after the flood
//!    that follows it — eviction never reaches back and discards a decision the user already
//!    made, only genuinely undecided requests are eligible.
//!
//! Same no-network, direct-`ChatState`-driving style as `apps/core/tests/message_request_gate.rs`.

use meridian_core::chat::{ChatError, ChatState, MAX_INTRO_LEN, MAX_PENDING_REQUESTS};
use meridian_envelope::ChatContent;
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;

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
    /// Publish a bundle with **no** one-time prekeys — every flood sender below completes X3DH
    /// with `used_opk: None`, exactly the OTK-free path that makes the flood free for the
    /// attacker (task background).
    fn publish_otk_free(&mut self) -> [u8; 32] {
        let ik = self.ik();
        let gen = generate_bundle(&self.store, self.account.handle(), ik, 0).unwrap();
        self.state
            .vault
            .set_bundle(gen.bundle.spk, *gen.spk_secret, [], 1_700_000_000);
        gen.bundle.spk
    }
    /// Build one first-contact opening envelope addressed to `peer`, OTK-free.
    fn opening_envelope_to(&mut self, peer: &[u8; 32], peer_spk: &[u8; 32], body: &str) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                peer_spk,
                None,
            )
            .unwrap();
        self.state
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                &ChatContent::Text {
                    id: [1u8; 16],
                    body: body.into(),
                },
            )
            .unwrap()
    }
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
    }
}

/// One flood sender's identity key + opening envelope, built fresh (never reused across sends —
/// a real attacker mints a new identity key per stranger).
fn flood_envelope(
    hint: &str,
    bob_ik: &[u8; 32],
    bob_spk: &[u8; 32],
    body: &str,
) -> ([u8; 32], Vec<u8>) {
    let mut sender = Party::new(hint);
    let sender_ik = sender.ik();
    let blob = sender.opening_envelope_to(bob_ik, bob_spk, body);
    (sender_ik, blob)
}

// -- 1. N+K distinct strangers leave ChatState bounded, no orphaned sessions -------------------

#[test]
fn flood_of_distinct_identities_leaves_pending_requests_bounded_no_orphaned_sessions() {
    let mut bob = Party::new("flood.bob");
    let bob_ik = bob.ik();
    let bob_spk = bob.publish_otk_free();

    const K: usize = 8; // strictly more than the cap, so eviction must actually fire K times.
    let total = MAX_PENDING_REQUESTS + K;

    // Each flood sender is a genuinely fresh identity key (never reused), mirroring an attacker
    // minting one keypair per stranger for free (OTK-free X3DH).
    let mut sender_iks = Vec::with_capacity(total);
    for i in 0..total {
        let hint = format!("flood.stranger.{i}");
        let (sender_ik, blob) = flood_envelope(&hint, &bob_ik, &bob_spk, "hi, a stranger");
        let outcome = bob.recv(&sender_ik, &blob);
        assert!(
            matches!(outcome, Err(ChatError::MessageRequest)),
            "every fresh first contact must still be gated: got {outcome:?} at i={i}"
        );
        sender_iks.push(sender_ik);
    }

    // Bounded, never N+K: this is the assertion that fails outright against the pre-3.10,
    // unbounded code (where this would be `total`, not `MAX_PENDING_REQUESTS`).
    assert_eq!(
        bob.state.pending_requests().count(),
        MAX_PENDING_REQUESTS,
        "pending_requests must be capped at MAX_PENDING_REQUESTS regardless of flood size"
    );

    // The oldest K senders (arrival order == the loop above, since each is a fresh identity used
    // exactly once) must have been evicted — from *both* the request queue and the session map.
    // No orphaned `Session`s: eviction must always take the session with it.
    for (i, ik) in sender_iks.iter().enumerate().take(K) {
        assert!(
            bob.state.pending_request(ik).is_none(),
            "sender {i} (oldest) must have been evicted from pending_requests"
        );
        assert!(
            !bob.state.has_session(ik),
            "sender {i} (oldest) must not leave an orphaned Session behind after eviction"
        );
    }

    // The most recent MAX_PENDING_REQUESTS senders must still be fully present: request + session.
    for (i, ik) in sender_iks.iter().enumerate().skip(K) {
        assert!(
            bob.state.pending_request(ik).is_some(),
            "sender {i} (recent) must still have a pending request"
        );
        assert!(
            bob.state.has_session(ik),
            "sender {i} (recent) must still have its session"
        );
    }
}

// -- 2. an oversized intro is capped, never dropped ---------------------------------------------

#[test]
fn oversized_intro_is_truncated_not_dropped() {
    let mut bob = Party::new("flood.cap.bob");
    let bob_ik = bob.ik();
    let bob_spk = bob.publish_otk_free();

    // Comfortably over MAX_INTRO_LEN so the truncation path definitely fires.
    let oversized_body = "A".repeat(MAX_INTRO_LEN * 4);
    let (sender_ik, blob) =
        flood_envelope("flood.cap.stranger", &bob_ik, &bob_spk, &oversized_body);

    let outcome = bob.recv(&sender_ik, &blob);
    assert!(
        matches!(outcome, Err(ChatError::MessageRequest)),
        "an oversized-intro first contact must still be gated (never silently dropped): got \
         {outcome:?}"
    );

    // The invariant every caller (`apps/cli`) relies on: `MessageRequest` always means "there is
    // a queued entry to look up" — an oversized intro must be capped, not discarded outright.
    let req = bob.state.pending_request(&sender_ik).expect(
        "ChatError::MessageRequest must always correspond to a queued entry, even when \
                 the intro was oversized and had to be capped",
    );

    match &req.intro {
        ChatContent::Text { body, .. } => {
            assert!(
                body.len() <= MAX_INTRO_LEN,
                "capped intro body must be at most MAX_INTRO_LEN bytes, got {}",
                body.len()
            );
            assert!(
                oversized_body.starts_with(body.as_str()),
                "the capped body must be a genuine prefix of the original, not fabricated content"
            );
        }
        other => panic!("expected a capped Text intro, got {other:?}"),
    }
}

/// A short, ordinary intro is never touched — capping is a bound, not a blanket truncation.
#[test]
fn short_intro_is_untouched() {
    let mut bob = Party::new("flood.cap.short.bob");
    let bob_ik = bob.ik();
    let bob_spk = bob.publish_otk_free();

    let (sender_ik, blob) = flood_envelope("flood.cap.short.stranger", &bob_ik, &bob_spk, "hi bob");
    assert!(matches!(
        bob.recv(&sender_ik, &blob),
        Err(ChatError::MessageRequest)
    ));

    let req = bob.state.pending_request(&sender_ik).unwrap();
    assert_eq!(
        req.intro,
        ChatContent::Text {
            id: [1u8; 16],
            body: "hi bob".into()
        }
    );
}

// -- 3. an accepted request survives eviction pressure even after the flood ---------------------

#[test]
fn accepted_request_survives_eviction_pressure_after_the_flood() {
    let mut bob = Party::new("flood.accept.bob");
    let mut alice = Party::new("flood.accept.alice");
    let bob_ik = bob.ik();
    let alice_ik = alice.ik();
    let bob_spk = bob.publish_otk_free();

    // Alice is a genuine first contact, gated then accepted — a real, decided relationship.
    let opening = alice.opening_envelope_to(&bob_ik, &bob_spk, "hi bob, it's alice");
    assert!(matches!(
        bob.recv(&alice_ik, &opening),
        Err(ChatError::MessageRequest)
    ));
    let accepted = bob
        .state
        .accept_request(&alice_ik)
        .expect("alice's request must be queued before it can be accepted");
    assert_eq!(
        accepted.intro,
        ChatContent::Text {
            id: [1u8; 16],
            body: "hi bob, it's alice".into()
        }
    );
    assert!(bob.state.pending_request(&alice_ik).is_none());
    assert!(bob.state.has_session(&alice_ik));

    // Now flood past the cap — every one of these is a fresh, undecided stranger, exactly the
    // population eviction is allowed to touch. `+ 32` (not `* 2`) is deliberate: it's already
    // enough to force `MAX_PENDING_REQUESTS` evictions (more than the entire queue's worth), and
    // keeps this test's asymmetric-crypto cost from doubling for no additional coverage.
    let total = MAX_PENDING_REQUESTS + 32;
    for i in 0..total {
        let hint = format!("flood.accept.stranger.{i}");
        let (sender_ik, blob) = flood_envelope(&hint, &bob_ik, &bob_spk, "hi, a stranger");
        assert!(matches!(
            bob.recv(&sender_ik, &blob),
            Err(ChatError::MessageRequest)
        ));
    }
    assert_eq!(bob.state.pending_requests().count(), MAX_PENDING_REQUESTS);

    // Alice's decision — already made before any of the flood arrived — must be untouched: no
    // resurrected pending request, session still live, and the ratchet still works both ways.
    assert!(
        bob.state.pending_request(&alice_ik).is_none(),
        "an already-accepted request must never reappear in pending_requests"
    );
    assert!(
        bob.state.has_session(&alice_ik),
        "an already-accepted contact's session must survive arbitrary flood/eviction pressure"
    );

    let second = alice
        .state
        .seal_outbound(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &bob_ik,
            &ChatContent::Text {
                id: [2u8; 16],
                body: "are you still there?".into(),
            },
        )
        .unwrap();
    let got = bob
        .recv(&alice_ik, &second)
        .expect("an accepted contact must keep delivering normally after the flood");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "are you still there?".into()
        }
    );
}
