//! Core chat-session-manager integration: a full relayed exchange (X3DH prekey message → reply →
//! receipt) driven entirely through opaque blobs, plus tamper rejection and sealed persistence.
//! No network: the "relay" is just handing blob bytes between two [`ChatState`]s.
//!
//! # task 6.6 additions (ADR 0016 "Test obligations": C3 and R1, both OPEN(v2))
//!
//! Two adversarial cells live at the bottom of this file, new for envelope v2:
//!   - [`sign_flipped_sender_pub_is_rejected`] — C3: the v2 AAD must carry the RAW Ed25519
//!     encodings of both identity keys, never the Montgomery-normalized (X25519) form, or a
//!     sign-flipped `sender_pub` would be silently accepted once the per-message signature (which
//!     caught this trivially under v1) is gone.
//!   - [`kci_forged_first_contact_from_stolen_spk_secret_succeeds_r1_accepted_residual`] — R1: an
//!     enumerated, ADR-accepted residual (NOT a defect), documented by a PASSING assertion per
//!     `docs/testing/strategy.md`'s "0 silent successes outside the enumerated accepted residuals"
//!     rule.

use meridian_core::chat::{ChatError, ChatState, PREV_GENERATION_GRACE_SECS};
use meridian_envelope::{ChatContent, MessageEnvelope};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::{generate_bundle, GeneratedBundle};
use meridian_store::{KeyHandle, SecretStore, SignOrDh, StoreError};

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
        self.state.expire_previous_generation(now_unix);
    }
    /// Like [`recv`](Self::recv) but surfaces the real error, for tests that assert on which
    /// rejection happened rather than merely that one did.
    fn recv_err(&mut self, from: &[u8; 32], blob: &[u8]) -> Option<meridian_core::chat::ChatError> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
            .err()
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
fn tampered_sender_and_ciphertext_are_rejected() {
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

    // A blob claiming a different routing origin than the envelope's own sender is rejected
    // (`ChatError::SenderMismatch` — unchanged by envelope v2, checked before any crypto work).
    let wrong_from = [0xABu8; 32];
    assert!(bob.recv(&wrong_from, &blob).is_err());

    // Flipping a ciphertext byte breaks the ratchet AEAD tag (v2, ADR 0016 C2/C3 — there is no
    // longer a signature; authentication is the AEAD's job) → rejected, never decrypted.
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

/// Same as [`state_bytes`], but with the `desync_counts` map stripped out first (task 4.9): that
/// field is new bookkeeping this task adds specifically so it *can* change on a `Desync`
/// classification — that is its entire purpose (`ChatState::recovery_recommended`'s repeated-Desync
/// counter) — so it is deliberately excluded from this test's byte-identical comparison rather than
/// weakening what the comparison actually proves. Every other part of the "a rejected undecryptable
/// envelope touches nothing else" invariant this test guards (`sessions`, `vault`,
/// `pending_requests`, `request_order`) is still compared byte-for-byte.
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

    let before = state_bytes_excluding_desync_counts(&bob.state);

    // An envelope from Alice whose ratchet header opens under neither of Bob's header keys: mangle
    // a byte inside the encrypted header. Envelope v2 has no signature to re-apply — the envelope's
    // `sender_pub` and routing `from` already match, so this reaches the ratchet unchanged. This is
    // precisely the input a naive "N undecryptable envelopes => re-handshake" rule would react to.
    // Note this envelope still carries Alice's (unconfirmed-initiator) prekey preamble — Bob never
    // replied in this test — so this also exercises task 4.9's `open_bytes` fallback path: it is
    // attempted (provisionally, task 6.3/ADR 0016 C2), but must fail (the preamble's one-time
    // prekey was already consumed by the opening message above, so even the non-destructive
    // `peek_otk_secret` lookup finds nothing), which is exactly what keeps the byte-identical
    // assertion below meaningful for this task too, not just for 1.18's original (pre-4.9) code
    // path.
    let mut env = MessageEnvelope::from_blob(&alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [4u8; 16],
            body: "will be mangled".into(),
        },
    ))
    .unwrap();
    env.ct[2] ^= 0xFF; // inside enc_header (past the 2-byte length prefix)
    let mangled = env.to_blob().unwrap();

    match bob.recv_err(&alice_ik, &mangled) {
        Some(e) => assert!(
            matches!(e, meridian_core::chat::ChatError::Desync),
            "an undecryptable header must classify as Desync, got: {e:?}"
        ),
        None => panic!("an undecryptable envelope must be rejected, not accepted"),
    }

    // (task 4.9) The repeated-Desync counter DOES change — that is its entire purpose — but nothing
    // else does: this is a single occurrence, well below `DESYNC_RECOVERY_THRESHOLD`, so
    // `recovery_recommended` must still read `false`.
    assert_eq!(bob.state.desync_count(&alice_ik), 1);
    assert!(!bob.state.recovery_recommended(&alice_ik));

    assert_eq!(
        before,
        state_bytes_excluding_desync_counts(&bob.state),
        "a rejected undecryptable envelope must leave the session byte-identically unchanged — no \
         reset, no re-key, no discarded skipped-message keys (task 1.18) — aside from the new, \
         separately-asserted task-4.9 desync counter"
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

// -- task 6.6 / ADR 0016 C3: sign-flipped sender_pub -------------------------

/// C3 (task 6.6, was OPEN(v2)): the v2 AAD is `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`
/// with `AD` the **raw Ed25519 encodings** of both identity keys, never the Montgomery-normalized
/// (X25519) form — `apps/crypto/src/x3dh.rs::derive`'s doc comment records exactly why: the
/// Ed25519→X25519 birational map is defined from the curve's y-coordinate only, so it drops the
/// sign of x entirely. Concretely: a compressed Ed25519 point's top bit encodes the sign of x; for
/// any valid point with y-coordinate `y`, `x` and `-x` are BOTH valid roots of the same `x² = c`
/// equation, so flipping that bit is always a genuinely different, validly-encoded public key `A'`
/// with the identical `y` and therefore the identical Montgomery `u`.
///
/// This test proves the raw-encoding requirement is load-bearing, not decorative. Every X3DH leg
/// that touches Alice's identity key (`DH1 = DH(IK_A, SPK_B)`, computed on the responder side as
/// `dh(spk_secret, ed25519_pub_to_x25519(peer_ik))`) is computed from the *converted* form, which
/// is sign-blind — so `root`/`hka`/`nhkb` come out **bit-identical** whichever sign Alice's claimed
/// identity key carries. If the AAD were built from that same X25519-normalized form (or from
/// anything less than the full raw Ed25519 bytes), a sign-flipped `sender_pub` would collide with
/// the genuine one in the AAD too, and — with no per-message signature left to catch it — this
/// envelope would decrypt successfully under an identity Alice never asserted. Only the raw-bytes
/// AAD makes the flip change the AAD (and therefore the AEAD tag) even though the derived keys
/// don't move.
#[test]
fn sign_flipped_sender_pub_is_rejected() {
    let mut alice = Party::new("signflip.a");
    let mut bob = Party::new("signflip.b");
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
            id: [9u8; 16],
            body: "hi".into(),
        },
    );

    // Negate Alice's claimed identity key: flip the sign bit (the top bit of the last byte of the
    // compressed Edwards encoding). Never a malformed-key rejection — see this test's doc comment
    // for why the flipped bytes are always a valid, different Ed25519 point.
    let mut flipped_ik = alice_ik;
    flipped_ik[31] ^= 0x80;
    assert_ne!(
        flipped_ik, alice_ik,
        "the flip must actually change the key"
    );

    let mut env = MessageEnvelope::from_blob(&blob).unwrap();
    env.sender_pub = flipped_ik;
    let attack = env.to_blob().unwrap();

    // `from` is set to match the mutated `sender_pub` deliberately: this isolates the property
    // under test to C3's AAD encoding, rather than incidentally tripping the unrelated
    // `SenderMismatch` check (which fires purely on `sender_pub != from`, before any crypto runs).
    match bob.recv_err(&flipped_ik, &attack) {
        Some(ChatError::Crypto(_)) => {}
        Some(other) => panic!(
            "a sign-flipped sender_pub must be rejected by the ratchet AEAD (ADR 0016 C3 — the \
             AAD carries the raw Ed25519 encoding, so the flip changes the AAD even though \
             root/hka/nhkb are bit-identical to the unflipped key), not by something else. \
             Got: {other:?}"
        ),
        None => panic!(
            "SECURITY FAILURE: a sign-flipped sender_pub was ACCEPTED — this is exactly the gap \
             C3 exists to close once the per-message signature is gone"
        ),
    }

    // The flip broke nothing but itself: the genuine, unmutated envelope still opens.
    let got = bob.recv(&alice_ik, &blob).ok().unwrap();
    assert_eq!(
        got,
        ChatContent::Text {
            id: [9u8; 16],
            body: "hi".into()
        }
    );
}

// -- task 6.6 / ADR 0016 R1: key-compromise impersonation (KCI), accepted residual --

/// A [`SecretStore`] that answers exactly the ONE Diffie-Hellman query ADR 0016 R1's attacker can
/// legitimately answer, and honestly refuses every other — modelling the attacker's real
/// capability rather than a convenient shortcut.
///
/// R1's threat model: an attacker who has obtained a responder's **signed-prekey secret** (never
/// an identity key, of either party) can forge a first-contact session claiming to be from any
/// sender. The X3DH leg this rests on is `DH1 = DH(IK_sender, SPK_responder)`. Diffie-Hellman is
/// commutative, so this is equally computable as `DH(SPK_responder_priv, IK_sender_pub)` — exactly
/// the stolen SPK secret combined with the (public, freely available) claimed sender's identity
/// key. That is the only leg this store can answer; it is deliberately wired to the *shape* of
/// that one query (`x3dh::initiate`'s `store_dh(store, handle, peer_spk)`, whose `input` is the
/// responder's SPK public key) and refuses everything else — in particular
/// `x3dh::respond`'s `store_dh(store, handle, ek_a)` query (`input` is an ephemeral public key),
/// which would require the *responder's own identity key* to answer correctly, and which this
/// attacker structurally cannot compute from a stolen SPK secret alone.
struct StolenSpkStore {
    /// The one secret this attacker holds: the responder's signed-prekey PRIVATE key.
    stolen_spk_secret: [u8; 32],
    /// The (public) identity key of whoever this attacker is claiming to be. Used only as a DH
    /// input, never as signing/private key material — this attacker never touches that party's
    /// private key or store.
    forged_sender_ik: [u8; 32],
    /// The only `input` this store will answer for: the responder's real signed-prekey PUBLIC key,
    /// the shape of `x3dh::initiate`'s DH1 query.
    expected_input: [u8; 32],
}

impl SecretStore for StolenSpkStore {
    fn store(&self, _label: &str, _secret: &[u8]) -> meridian_store::Result<KeyHandle> {
        unreachable!("this attacker never registers a real account; it only ever performs one DH")
    }

    fn use_key(
        &self,
        _h: &KeyHandle,
        op: SignOrDh,
        input: &[u8],
    ) -> meridian_store::Result<Vec<u8>> {
        match op {
            SignOrDh::Dh if input == self.expected_input.as_slice() => {
                // DH1 = DH(SPK_responder_priv, IK_sender_pub) — the ADR 0016 R1 leg, computable
                // from the stolen SPK secret and the (public) claimed sender's identity key alone.
                let ik_x =
                    meridian_crypto::test_support::ed25519_pub_to_x25519(&self.forged_sender_ik)
                        .expect("test fixture identity key is a valid Ed25519 point");
                Ok(meridian_crypto::test_support::dh(&self.stolen_spk_secret, &ik_x).to_vec())
            }
            SignOrDh::Dh => Err(StoreError::UnsupportedOp(
                "this attacker holds only a signed-prekey secret and cannot answer any DH query \
                 except DH1 against the identity it is forging (ADR 0016 R1)",
            )),
            SignOrDh::Sign => Err(StoreError::UnsupportedOp(
                "envelope v2 needs no per-message signature; this attacker never signs anything",
            )),
        }
    }

    fn nonextractable(&self) -> bool {
        false
    }

    fn derive_key(&self, _h: &KeyHandle, _info: &[u8]) -> meridian_store::Result<[u8; 32]> {
        unreachable!("this attacker never seals anything at rest")
    }
}

/// ADR 0016 R1 (task 6.6) — **an enumerated, accepted residual, not a defect.** Dropping the
/// per-message identity signature makes first-contact authentication rest entirely on X3DH's
/// `DH1 = DH(IK_A, SPK_B)`. Because DH is commutative, that value is equally computable from
/// `(SPK_B_priv, IK_A_pub)` as from `(IK_A_priv, SPK_B_pub)` — so an attacker who has obtained
/// only a responder's signed-prekey SECRET (never that responder's identity key, and never the
/// impersonated sender's identity key or store) can forge a complete first-contact session
/// claiming to be from any sender, and the responder will accept and decrypt it exactly as if it
/// were genuine.
///
/// ADR 0016 accepts this residual explicitly (compensating controls: enforced SPK rotation +
/// keystore-grade SPK handling, C1) — it is **already enumerated**, not newly discovered or
/// negotiable here. Per `docs/testing/strategy.md`'s "0 silent successes outside the enumerated
/// accepted residuals" rule, this test's job is to make the residual visible and pinned by a
/// PASSING assertion, never to imply it is a live bug or something this task is choosing to
/// accept on its own authority.
///
/// It also pins the residual's documented BOUNDARY, so the claim is neither over- nor
/// understated: the same attacker canNOT decrypt the genuine sender's own real first message
/// (that leg, `DH2 = DH(EK_A, IK_B)`, needs the RESPONDER's real identity key, which this attacker
/// never has) — modelled below by [`StolenSpkStore`] honestly refusing that query rather than
/// fabricating a plausible-looking wrong answer. And safety-number verification — a pure function
/// of the two public identity keys — does not distinguish the forged session from a genuine one,
/// because both identity keys really are genuine.
#[test]
fn kci_forged_first_contact_from_stolen_spk_secret_succeeds_r1_accepted_residual() {
    let mut alice = Party::new("kci.alice");
    let mut bob = Party::new("kci.bob");
    let bob_bundle = bob.publish();
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let stolen_spk_secret = *bob_bundle.spk_secret;

    // -- Forge: Mallory, holding ONLY Bob's stolen SPK secret, builds a first-contact session
    // claiming to be Alice, using nothing but that secret and Alice's PUBLIC identity key. She
    // never touches `alice.store` or any of Alice's private material.
    let mallory_store = StolenSpkStore {
        stolen_spk_secret,
        forged_sender_ik: alice_ik,
        expected_input: bob_bundle.bundle.spk,
    };
    let mallory_handle = KeyHandle::from_label("mallory-stolen-spk");

    let mut forged = ChatState::default();
    forged
        .start_initiator_session(
            &mallory_store,
            &mallory_handle,
            &alice_ik,
            &bob_ik,
            &bob_bundle.bundle.spk,
            None, // no OTK compromised — only the SPK secret, per R1's threat model
        )
        .expect("Mallory can complete X3DH using only the stolen SPK secret (ADR 0016 R1)");
    let forged_blob = forged
        .seal_outbound(
            &mallory_store,
            &mallory_handle,
            &alice_ik,
            &bob_ik,
            &ChatContent::Text {
                id: [0xEEu8; 16],
                body: "forged by mallory, not alice".into(),
            },
        )
        .unwrap();

    // Bob accepts and decrypts it, believing it genuinely came from Alice — the residual, pinned
    // by a PASSING assertion (the one enumerated exception to "0 silent successes",
    // docs/testing/strategy.md), not a silent success: it is enumerated as accepted in ADR 0016 R1
    // itself.
    match bob.recv(&alice_ik, &forged_blob) {
        Ok(ChatContent::Text { body, .. }) => {
            assert_eq!(body, "forged by mallory, not alice")
        }
        Ok(other) => {
            panic!("forged first-contact message decrypted to unexpected content: {other:?}")
        }
        Err(_) => panic!(
            "ADR 0016 R1 says this forgery SUCCEEDS (an accepted residual, not a defect) — if it \
             now fails, either the residual has been unexpectedly closed (update ADR 0016 first, \
             with security-reviewer sign-off, before weakening this assertion) or this test's \
             attacker model has bit-rotted."
        ),
    }

    // -- Boundary: this attacker cannot read Alice's OWN genuine first message. Give
    // "Mallory-as-Bob" a vault entry for the (also stolen) SPK secret only, no OTKs and no
    // identity key — the most she could ever legitimately construct — and confirm she still
    // cannot complete the handshake for a message Alice actually sends.
    alice.start(&bob_ik, &bob_bundle.bundle.spk, None); // no OTK: isolates the failure to the DH2 leg
    let genuine_blob = alice.send(
        &bob_ik,
        &ChatContent::Text {
            id: [0xAAu8; 16],
            body: "alice's real first message".into(),
        },
    );
    let mut mallory_reads_alice = ChatState::default();
    mallory_reads_alice.vault.set_bundle(
        bob_bundle.bundle.spk,
        stolen_spk_secret,
        vec![],
        TEST_NOW_UNIX,
    );
    let outcome = mallory_reads_alice.open_inbound(
        &mallory_store,
        &mallory_handle,
        &bob_ik, // Mallory would have to play Bob's role to even attempt this
        &alice_ik,
        &genuine_blob,
    );
    assert!(
        outcome.is_err(),
        "the attacker must NOT be able to read Alice's genuine first message with only the \
         stolen SPK secret — that would be full compromise, not the bounded R1 residual ADR 0016 \
         accepts. Got: {outcome:?}"
    );

    // -- Safety numbers do not catch the forgery either: it is a pure function of the two
    // (genuine) public identity keys, unaffected by which session — forged or real — exists.
    assert_eq!(
        bob.state.safety_number(&bob_ik, &alice_ik).unwrap(),
        meridian_crypto::safety_number(&bob_ik, &alice_ik),
        "the safety number a user would be shown is identical whether the underlying session is \
         genuine or Mallory's forgery — ADR 0016 R1's explicit point that verification does not \
         detect this"
    );
}
