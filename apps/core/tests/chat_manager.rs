//! Core chat-session-manager integration: a full relayed exchange (X3DH prekey message → reply →
//! receipt) driven entirely through opaque blobs, plus tamper rejection and sealed persistence.
//! No network: the "relay" is just handing blob bytes between two [`ChatState`]s.

use meridian_core::chat::{ChatError, ChatState, PREV_GENERATION_GRACE_SECS};
use meridian_envelope::{ChatContent, MessageEnvelope};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::{generate_bundle, GeneratedBundle};

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
    /// Publish a bundle: record the prekey secrets in the vault and return the public bundle.
    fn publish(&mut self) -> GeneratedBundle {
        self.publish_at(TEST_NOW_UNIX)
    }

    /// [`publish`](Self::publish) at an explicit wall clock, for the task-1.31 generation-rotation
    /// tests. `set_bundle` takes time as a parameter (rather than reading a clock) so
    /// `meridian-core` stays wasm-safe; that also makes the grace window testable without sleeping.
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
    fn start(&mut self, peer: &[u8; 32], spk: &[u8; 32], opk: Option<[u8; 32]>) {
        let ik = self.ik();
        self.state
            .start_initiator_session(&self.store, self.account.handle(), &ik, peer, spk, opk)
            .unwrap();
    }
    fn send(&mut self, peer: &[u8; 32], content: &ChatContent) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .seal_outbound(&self.store, self.account.handle(), &ik, peer, content)
            .unwrap()
    }
    /// This file exercises session/ratchet correctness, not the task-2.10 request-queue UX (see
    /// `apps/core/tests/message_request_gate.rs` for that): a first contact is transparently
    /// auto-accepted here so "the opening envelope opens" reads exactly as it did before the gate
    /// existed.
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatErr> {
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
            other => other.map_err(|_| ChatErr),
        }
    }
    /// Retire a superseded prekey generation whose grace window has passed, exactly as the CLI's
    /// inbound path does before opening a delivered blob (task 1.31).
    fn vault_expire(&mut self, now_unix: u64) {
        self.state.vault.expire_previous_generation(now_unix);
    }
    /// Like [`recv`](Self::recv) but surfaces the real error, for tests that assert on which
    /// rejection happened rather than merely that one did.
    fn recv_err(&mut self, from: &[u8; 32], blob: &[u8]) -> Option<meridian_core::chat::ChatError> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
            .err()
    }
    /// Re-sign a (possibly modified) envelope under this party's identity key, so it is authentic
    /// rather than merely forged — the signature/sender checks pass and the ratchet is reached.
    fn resign(&self, mut env: MessageEnvelope) -> Vec<u8> {
        let sig = meridian_identity::sign(&self.store, self.account.handle(), &env.signing_bytes())
            .unwrap();
        env.sig = *sig.as_bytes();
        env.to_blob().unwrap()
    }
}

struct ChatErr;

/// Fixed base wall clock for the tests that don't care about time.
const TEST_NOW_UNIX: u64 = 1_700_000_000;

#[test]
fn full_relayed_exchange_with_receipt() {
    let mut alice = Party::new("chat.a");
    let mut bob = Party::new("chat.b");

    // Bob registers + publishes; Alice fetches (here: uses the verified bundle directly).
    let bob_bundle = bob.publish();
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    alice.start(
        &bob_ik,
        &bob_bundle.bundle.spk,
        Some(bob_bundle.bundle.otks[0]),
    );

    // Alice → Bob (opening prekey message).
    let msg_id = [42u8; 16];
    let blob = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: msg_id,
            body: "hello bob".into(),
        },
    );
    let got = bob.recv(&alice_ik, &blob).ok().unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: msg_id,
            body: "hello bob".into()
        }
    );

    // Bob → Alice delivery receipt.
    let receipt_blob = bob.send(&alice_ik, &ChatContent::Receipt { ack: msg_id });
    let got = alice.recv(&bob_ik, &receipt_blob).ok().unwrap();
    assert_eq!(got, ChatContent::Receipt { ack: msg_id });

    // Both sides agree on the safety number.
    assert_eq!(
        alice.state.safety_number(&alice_ik, &bob_ik),
        bob.state.safety_number(&bob_ik, &alice_ik)
    );
}

#[test]
fn tampered_sender_and_signature_are_rejected() {
    let mut alice = Party::new("chat.a");
    let mut bob = Party::new("chat.b");
    let bob_bundle = bob.publish();
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    alice.start(
        &bob_ik,
        &bob_bundle.bundle.spk,
        Some(bob_bundle.bundle.otks[0]),
    );

    let blob = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [1u8; 16],
            body: "hi".into(),
        },
    );

    // A blob claiming a different routing origin than the signed sender is rejected.
    let wrong_from = [0xABu8; 32];
    assert!(bob.recv(&wrong_from, &blob).is_err());

    // Flipping a ciphertext byte breaks the signature → rejected before any decryption.
    let mut env = MessageEnvelope::from_blob(&blob).unwrap();
    env.ct[0] ^= 0x01;
    let tampered = env.to_blob().unwrap();
    assert!(bob.recv(&alice_ik, &tampered).is_err());
}

#[test]
fn state_survives_sealed_restart() {
    let mut alice = Party::new("chat.a");
    let mut bob = Party::new("chat.b");
    let bob_bundle = bob.publish();
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    alice.start(
        &bob_ik,
        &bob_bundle.bundle.spk,
        Some(bob_bundle.bundle.otks[0]),
    );

    let blob = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [1u8; 16],
            body: "before".into(),
        },
    );
    bob.recv(&alice_ik, &blob).ok().unwrap();

    // Seal Bob's state, drop it, reload from the sealed bytes, and keep chatting (no re-handshake).
    let sealed = bob
        .state
        .seal_at_rest(&bob.store, bob.account.handle())
        .unwrap();
    bob.state = ChatState::open_at_rest(&bob.store, bob.account.handle(), &sealed).unwrap();

    let blob2 = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [2u8; 16],
            body: "after".into(),
        },
    );
    let got = bob.recv(&alice_ik, &blob2).ok().unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "after".into()
        }
    );
}

// -- task 1.31: prekey-bundle republish/fetch race on reconnect --------------
//
// Every `session connect` / `chat` invocation republishes a fresh bundle for BOTH roles, but nothing
// synchronizes a peer's fetch against that publish landing. Before 1.31 `PrekeyVault::set_bundle` was
// a single-slot overwrite, so an initiator whose fetch landed on the generation that was current a
// moment ago referenced OTK/SPK ids the responder no longer held secrets for — a hard
// `ChatError::UnknownPrekey` ("no matching prekey secret for incoming session"), not a retry. The fix
// retains exactly ONE superseded generation for a bounded grace window; these tests pin both bounds
// (one generation, and `PREV_GENERATION_GRACE_SECS`) so neither can silently become unbounded.

/// Build an initiator session on `from` against an explicit (spk, opk) pair, then seal an opening
/// prekey envelope. Mirrors what a real initiator does after fetching a bundle.
fn prekey_envelope_against(
    from: &mut Party,
    peer_ik: &[u8; 32],
    spk: &[u8; 32],
    opk: Option<[u8; 32]>,
    id: u8,
) -> Vec<u8> {
    from.start(peer_ik, spk, opk);
    from.send(
        peer_ik,
        &ChatContent::Text {
            id: [id; 16],
            body: "raced".into(),
        },
    )
}

/// The regression itself: an envelope built against the *just-superseded* generation still opens.
///
/// Against the pre-1.31 single-slot `set_bundle` this fails with `UnknownPrekey`: `bob.publish()`
/// below replaced `spk_public`/`spk_secret` and cleared `otks` wholesale, so the gen-N `used_spk`
/// Alice referenced had no secret left in Bob's vault at all.
#[test]
fn envelope_against_just_superseded_generation_still_opens() {
    let mut alice = Party::new("race.a");
    let mut bob = Party::new("race.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());

    // Bob publishes generation N; Alice fetches it and builds her opening envelope.
    let gen_n = bob.publish_at(TEST_NOW_UNIX);
    let blob = prekey_envelope_against(
        &mut alice,
        &bob_ik,
        &gen_n.bundle.spk,
        gen_n.bundle.otks.first().copied(),
        1,
    );

    // Bob reconnects and republishes generation N+1 *before* Alice's envelope arrives.
    let gen_n1 = bob.publish_at(TEST_NOW_UNIX + 1);
    assert_ne!(
        gen_n.bundle.spk, gen_n1.bundle.spk,
        "republish must produce a genuinely different generation for this test to mean anything"
    );

    // The in-flight gen-N envelope must still establish the responder session.
    let got = bob
        .recv(&alice_ik, &blob)
        .ok()
        .expect("an envelope against the just-superseded generation must still open (1.31)");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [1u8; 16],
            body: "raced".into()
        }
    );
}

/// Time bound: past the grace window the superseded generation is gone and fails **closed**.
///
/// Bob's state is snapshotted via the at-rest seal (the same trick
/// `state_survives_sealed_restart` uses) so the inside-window and past-window cases both start from
/// the identical vault — the first `recv` consumes the one-time prekey, which would otherwise
/// contaminate the second.
#[test]
fn superseded_generation_is_rejected_once_the_grace_window_passes() {
    let mut alice = Party::new("expire.a");
    let mut bob = Party::new("expire.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());

    let gen_n = bob.publish_at(TEST_NOW_UNIX);
    let blob = prekey_envelope_against(
        &mut alice,
        &bob_ik,
        &gen_n.bundle.spk,
        gen_n.bundle.otks.first().copied(),
        2,
    );
    // Rotation happens here, so gen N expires at (TEST_NOW_UNIX + 1) + PREV_GENERATION_GRACE_SECS.
    bob.publish_at(TEST_NOW_UNIX + 1);
    let rotated_at = TEST_NOW_UNIX + 1;
    let snapshot = bob
        .state
        .seal_at_rest(&bob.store, bob.account.handle())
        .unwrap();

    // Just inside the window it still works…
    bob.vault_expire(rotated_at + PREV_GENERATION_GRACE_SECS - 1);
    assert!(
        bob.recv(&alice_ik, &blob).is_ok(),
        "inside the grace window the superseded generation must still be accepted"
    );

    // …and past it, it is rejected rather than silently accepted.
    bob.state = ChatState::open_at_rest(&bob.store, bob.account.handle(), &snapshot).unwrap();
    bob.vault_expire(rotated_at + PREV_GENERATION_GRACE_SECS);
    assert!(
        bob.recv(&alice_ik, &blob).is_err(),
        "past the grace window the superseded generation must fail closed"
    );
}

/// Generation bound: only ONE prior generation is retained, so two republishes retire gen N.
#[test]
fn only_one_prior_generation_is_retained() {
    let mut alice = Party::new("gen.a");
    let mut bob = Party::new("gen.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());

    let gen_n = bob.publish_at(TEST_NOW_UNIX);
    let blob = prekey_envelope_against(
        &mut alice,
        &bob_ik,
        &gen_n.bundle.spk,
        gen_n.bundle.otks.first().copied(),
        3,
    );

    // N -> N+1 (gen N becomes "previous"), then N+1 -> N+2 (gen N is dropped entirely).
    bob.publish_at(TEST_NOW_UNIX + 1);
    bob.publish_at(TEST_NOW_UNIX + 2);

    assert!(
        bob.recv(&alice_ik, &blob).is_err(),
        "gen N must be gone after two republishes — retention is capped at one prior generation"
    );
}

/// One-time prekeys stay single-use *across* generations: the same OTK can never open two sessions,
/// whether it is found in the current generation or the retained previous one.
#[test]
fn one_time_prekey_is_single_use_across_generations() {
    let mut alice = Party::new("otk.a");
    let mut carol = Party::new("otk.c");
    let mut bob = Party::new("otk.b");
    let (bob_ik, alice_ik, carol_ik) = (bob.ik(), alice.ik(), carol.ik());

    // Both Alice and Carol fetch gen N and (pathologically) reference the SAME one-time prekey.
    let gen_n = bob.publish_at(TEST_NOW_UNIX);
    let shared_otk = gen_n.bundle.otks.first().copied();
    assert!(shared_otk.is_some(), "test needs a one-time prekey");
    let alice_blob = prekey_envelope_against(&mut alice, &bob_ik, &gen_n.bundle.spk, shared_otk, 4);
    let carol_blob = prekey_envelope_against(&mut carol, &bob_ik, &gen_n.bundle.spk, shared_otk, 5);

    // Rotate, so the OTK now lives only in the retained previous generation.
    bob.publish_at(TEST_NOW_UNIX + 1);

    // First use succeeds (from the previous generation — the 1.31 allowance)…
    assert!(
        bob.recv(&alice_ik, &alice_blob).is_ok(),
        "first use of the superseded generation's OTK must succeed"
    );
    // …and the second use of that same OTK must not, even though it came from a different peer.
    assert!(
        bob.recv(&carol_ik, &carol_blob).is_err(),
        "a one-time prekey must be consumed exactly once across BOTH generations"
    );
}

// -- task 1.18: desync must NOT be an attacker-triggerable session reset -----
//
// `messaging-envelope-v1.md` §3 specifies recovery as "the peer that lost state re-initiates X3DH".
// It has been misread as "the receiver detects desync and renegotiates" — which would hand an active
// attacker (threat-model A2) a session-reset, skipped-key-destruction, and prekey-depletion oracle:
// junk traffic would discard a healthy ratchet and its retained skipped-message keys, and force a
// re-handshake (and a bundle fetch) at a moment of the attacker's choosing. This test pins the
// specified behaviour so that oracle cannot be introduced by a well-meaning future edit.

/// Deterministic CBOR of the whole chat state, for a byte-identical before/after comparison.
/// (`seal_at_rest` is unusable here — its AEAD nonce is random, so two seals of identical state
/// differ.)
fn state_bytes(state: &ChatState) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(state, &mut out).unwrap();
    out
}

/// An undecryptable envelope is rejected as `Desync` and leaves the session **byte-identically**
/// unchanged — no reset, no re-key, no discarded skipped-message keys.
#[test]
fn undecryptable_envelope_is_rejected_without_touching_the_session() {
    let mut alice = Party::new("desync.a");
    let mut bob = Party::new("desync.b");
    let bob_bundle = bob.publish();
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    alice.start(
        &bob_ik,
        &bob_bundle.bundle.spk,
        Some(bob_bundle.bundle.otks[0]),
    );

    // Establish a healthy, live session.
    let opening = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [1u8; 16],
            body: "hello".into(),
        },
    );
    bob.recv(&alice_ik, &opening).ok().unwrap();

    // Alice sends two more; hold the FIRST back so Bob retains a skipped-message key for it.
    // Destroying that key is one of the things a reset-on-desync oracle would achieve.
    let held = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [2u8; 16],
            body: "held back".into(),
        },
    );
    let later = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [3u8; 16],
            body: "arrives first".into(),
        },
    );
    bob.recv(&alice_ik, &later).ok().unwrap(); // out of order -> skipped key retained for `held`

    let before = state_bytes(&bob.state);

    // An *authentic* envelope from Alice whose ratchet header opens under neither of Bob's header
    // keys: mangle a byte inside the encrypted header, then re-sign as Alice so it passes the
    // signature and sender checks and reaches the ratchet. This is precisely the input a naive
    // "N undecryptable envelopes => re-handshake" rule would react to.
    let mut env = MessageEnvelope::from_blob(&alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [4u8; 16],
            body: "will be mangled".into(),
        },
    ))
    .unwrap();
    env.ct[2] ^= 0xFF; // inside enc_header (past the 2-byte length prefix)
    let mangled = alice.resign(env);

    match bob.recv_err(&alice_ik, &mangled) {
        Some(e) => assert!(
            matches!(e, meridian_core::chat::ChatError::Desync),
            "an undecryptable header must classify as Desync, got: {e:?}"
        ),
        None => panic!("an undecryptable envelope must be rejected, not accepted"),
    }

    assert_eq!(
        before,
        state_bytes(&bob.state),
        "a rejected undecryptable envelope must leave the session byte-identically unchanged — no \
         reset, no re-key, no discarded skipped-message keys (task 1.18)"
    );

    // And the session is genuinely still live: the held-back message still opens from its retained
    // skipped key.
    let got = bob.recv(&alice_ik, &held).ok().unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "held back".into()
        }
    );
}
