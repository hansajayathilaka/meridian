//! Task 2.10 — the first-contact **message-request gate** (system-design.md §3.5).
//!
//! A first envelope from a sender [`ChatState`] has never seen before must land in a segregated
//! "message request" state — not be delivered as an ordinary message — until the user explicitly
//! accepts it; a second envelope from that same still-pending sender must be refused, not merged
//! into the held request; accepting must flow normally afterward; the gate must survive the
//! at-rest seal/open round trip (it lives inside `ChatState`, sealed by the same mechanism as the
//! prekey vault and sessions); and rejecting must not create any sender-observable signal.
//!
//! This file drives [`ChatState::open_inbound`]/[`ChatState::accept_request`]/
//! [`ChatState::reject_request`] directly (no network), the same style as
//! `apps/core/tests/chat_manager.rs`.

use meridian_core::chat::{ChatError, ChatState};
use meridian_envelope::ChatContent;
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
    fn publish(&mut self) -> GeneratedBundle {
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
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, TEST_NOW_UNIX);
        gen
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
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
    }
}

/// Alice → Bob's opening prekey envelope, ready to hand to `bob.recv`.
fn opening_envelope() -> (Party, Party, [u8; 32], [u8; 32], Vec<u8>) {
    let mut alice = Party::new("gate.a");
    let mut bob = Party::new("gate.b");
    let bundle = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[0]));
    let blob = alice.send(&bob_ik, 1, "hi bob, it's alice");
    (alice, bob, alice_ik, bob_ik, blob)
}

// -- 1. first contact is gated, not delivered --------------------------------------------------

#[test]
fn first_contact_lands_in_pending_requests_not_delivered() {
    let (_alice, mut bob, alice_ik, bob_ik, blob) = opening_envelope();

    // Not yet a message from anyone bob knows.
    assert!(bob.state.pending_request(&alice_ik).is_none());

    let outcome = bob.recv(&alice_ik, &blob);
    assert!(
        matches!(outcome, Err(ChatError::MessageRequest)),
        "a first-contact envelope must be gated, not delivered: got {outcome:?}"
    );

    // The crypto session IS established (X3DH ran, envelope verified) — the gate is display-only,
    // not authentication (see `MessageRequest`'s doc comment). This is also what proves the OTK
    // was already spent by the time the gate runs (task 2.10's OTK-consumption invariant).
    assert!(
        bob.state.has_session(&alice_ik),
        "the responder session must already exist once gated — the gate runs downstream of \
         session establishment, never in place of it"
    );

    // The held request carries the sender's key, a safety number, and the intro content.
    let req = bob
        .state
        .pending_request(&alice_ik)
        .expect("first contact must be queued as a pending request");
    assert_eq!(req.sender_ik, alice_ik);
    assert!(!req.safety_number.is_empty());
    assert_eq!(
        req.intro,
        ChatContent::Text {
            id: [1u8; 16],
            body: "hi bob, it's alice".into()
        }
    );
    assert_eq!(bob.ik(), bob_ik); // sanity: didn't mix up the two identities above
}

// -- 2. a second envelope pre-accept is refused, not merged/queued --------------------------

#[test]
fn second_envelope_pre_accept_is_refused_not_merged() {
    let (mut alice, mut bob, alice_ik, bob_ik, opening) = opening_envelope();

    assert!(matches!(
        bob.recv(&alice_ik, &opening),
        Err(ChatError::MessageRequest)
    ));
    let original_intro = bob.state.pending_request(&alice_ik).unwrap().intro.clone();

    // Alice sends a second message before Bob has decided anything.
    let second = alice.send(&bob_ik, 2, "are you there?");
    let outcome = bob.recv(&alice_ik, &second);
    assert!(
        matches!(outcome, Err(ChatError::RequestPending)),
        "a second envelope from a still-gated sender must be refused, got {outcome:?}"
    );

    // The held request is untouched: still exactly one, still the FIRST message's content — the
    // second was refused outright, never merged/queued into it.
    assert_eq!(bob.state.pending_requests().count(), 1);
    assert_eq!(
        bob.state.pending_request(&alice_ik).unwrap().intro,
        original_intro,
        "the pending request must still hold only the original intro, not the second message"
    );
}

// -- 3. post-accept flows normally -----------------------------------------------------------

#[test]
fn accept_delivers_the_intro_and_subsequent_envelopes_flow_normally() {
    let (mut alice, mut bob, alice_ik, bob_ik, opening) = opening_envelope();
    assert!(matches!(
        bob.recv(&alice_ik, &opening),
        Err(ChatError::MessageRequest)
    ));

    let accepted = bob
        .state
        .accept_request(&alice_ik)
        .expect("a pending request must exist to accept");
    assert_eq!(
        accepted.intro,
        ChatContent::Text {
            id: [1u8; 16],
            body: "hi bob, it's alice".into()
        }
    );
    assert!(
        bob.state.pending_request(&alice_ik).is_none(),
        "accepting must remove the request from the gate"
    );

    // A second envelope now delivers as an ordinary message — no longer refused.
    let second = alice.send(&bob_ik, 2, "are you there?");
    let got = bob
        .recv(&alice_ik, &second)
        .expect("post-accept envelopes must deliver normally");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [2u8; 16],
            body: "are you there?".into()
        }
    );

    // And Bob can reply — the session is fully live in both directions.
    let reply = bob.send(&alice_ik, 3, "yes, hi alice");
    let got = alice
        .recv(&bob_ik, &reply)
        .expect("alice's own initiator session was never gated to begin with");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [3u8; 16],
            body: "yes, hi alice".into()
        }
    );
}

// -- 4. the gate survives the at-rest seal/open round trip ------------------------------------

#[test]
fn pending_requests_survive_the_sealed_at_rest_round_trip() {
    let (_alice, mut bob, alice_ik, _bob_ik, opening) = opening_envelope();
    assert!(matches!(
        bob.recv(&alice_ik, &opening),
        Err(ChatError::MessageRequest)
    ));
    assert!(bob.state.pending_request(&alice_ik).is_some());

    let sealed = bob
        .state
        .seal_at_rest(&bob.store, bob.account.handle())
        .expect("seal");
    let reopened =
        ChatState::open_at_rest(&bob.store, bob.account.handle(), &sealed).expect("open");

    let req = reopened
        .pending_request(&alice_ik)
        .expect("the pending request must survive the seal/open round trip");
    assert_eq!(req.sender_ik, alice_ik);
    assert_eq!(
        req.intro,
        ChatContent::Text {
            id: [1u8; 16],
            body: "hi bob, it's alice".into()
        }
    );
    assert!(
        reopened.has_session(&alice_ik),
        "the session behind the pending request must also survive"
    );
}

/// A `ChatState` sealed before task 2.10 (no `pending_requests` field in its CBOR) must still open
/// — `#[serde(default)]`, the same precedent `PrekeyVault::previous` set in task 1.31.
#[test]
fn a_chat_state_sealed_before_this_task_still_opens() {
    let party = Party::new("gate.legacy");
    // A default `ChatState`, CBOR-encoded WITHOUT ever touching `pending_requests`, stands in for
    // a state sealed by a pre-2.10 binary (same field, same default, just never populated).
    let legacy = ChatState::default();
    let sealed = legacy
        .seal_at_rest(&party.store, party.account.handle())
        .unwrap();
    let reopened = ChatState::open_at_rest(&party.store, party.account.handle(), &sealed)
        .expect("a state with an empty/absent pending_requests map must still open");
    assert_eq!(reopened.pending_requests().count(), 0);
}

// -- 5. rejection does not leak whether the key is known ---------------------------------------

#[test]
fn reject_produces_no_wire_signal_and_no_distinguishing_local_trace() {
    let (_alice, mut bob, alice_ik, _bob_ik, opening) = opening_envelope();
    assert!(matches!(
        bob.recv(&alice_ik, &opening),
        Err(ChatError::MessageRequest)
    ));
    assert!(bob.state.pending_request(&alice_ik).is_some());

    // `reject_request` takes no `SecretStore`/`KeyHandle`/transport — it cannot sign or seal an
    // envelope even in principle, so by construction it cannot put anything on the wire. This
    // asserts the *local* effect: the request and the session behind it are gone.
    assert!(bob.state.reject_request(&alice_ik));
    assert!(bob.state.pending_request(&alice_ik).is_none());
    assert!(
        !bob.state.has_session(&alice_ik),
        "reject must drop the (already-established) session, not just the request"
    );

    // Rejecting a key Bob has genuinely never heard from at all is a no-op that leaves the exact
    // same local trace as rejecting a real (now-discarded) request: both end with no pending
    // request and no session for that key. There is no third, distinguishable outcome a sender
    // could probe for.
    let stranger_ik = [0x77u8; 32];
    assert!(!bob.state.reject_request(&stranger_ik));
    assert!(bob.state.pending_request(&stranger_ik).is_none());
    assert!(!bob.state.has_session(&stranger_ik));
    assert_eq!(
        (
            bob.state.pending_request(&alice_ik).is_some(),
            bob.state.has_session(&alice_ik)
        ),
        (
            bob.state.pending_request(&stranger_ik).is_some(),
            bob.state.has_session(&stranger_ik)
        ),
        "post-rejection, a real (discarded) contact and a never-contacted stranger must be \
         indistinguishable in local state"
    );
}

/// A rejected sender who retries is treated as a brand-new first contact (their key material is
/// zeroized, not blacklisted): the *cheapest* honest behavior available without adding a permanent,
/// separately-observable "blocked" state (which task 2.10 does not ask for — see the doc comment
/// on `ChatState::reject_request`).
#[test]
fn a_rejected_sender_who_retries_with_a_fresh_handshake_is_gated_again() {
    let mut alice = Party::new("gate-retry.a");
    let mut bob = Party::new("gate-retry.b");
    let bundle = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[0]));
    let first = alice.send(&bob_ik, 1, "hello?");
    assert!(matches!(
        bob.recv(&alice_ik, &first),
        Err(ChatError::MessageRequest)
    ));
    bob.state.reject_request(&alice_ik);

    // Alice starts an entirely new session (a real client would re-fetch Bob's — still current —
    // bundle and re-run X3DH against a fresh one-time prekey, since her old one is spent).
    alice.state = ChatState::default();
    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[1]));
    let retry = alice.send(&bob_ik, 2, "hello again?");

    let outcome = bob.recv(&alice_ik, &retry);
    assert!(
        matches!(outcome, Err(ChatError::MessageRequest)),
        "a rejected sender's fresh retry must be gated again as a new first contact, not \
         silently dropped or auto-accepted: got {outcome:?}"
    );
}
