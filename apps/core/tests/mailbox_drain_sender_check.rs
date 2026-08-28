//! Task 8.8 (ADR 0024) — `ChatState::open_bytes`'s `envelope.sender_pub != from`
//! (`ChatError::SenderMismatch`) check, restructured so a mailbox-drained [`Deliver`] (task 8.7)
//! carrying the `[0u8; 32]` `from` placeholder is not rejected outright.
//!
//! Two cells, both required by this task's own Risks/notes ("get the `mailbox_id.is_some()` gate
//! wrong ... in either direction ... needs its own explicit test, not just the happy path"):
//!   - [`mailbox_drained_deliver_with_placeholder_from_decrypts_successfully`] — the case the
//!     restructuring must newly ACCEPT: `open_inbound_from_mailbox` with `from ==
//!     MAILBOX_DRAIN_FROM_PLACEHOLDER` must still decrypt via `envelope.sender_pub` alone.
//!   - [`live_deliver_with_forged_from_still_hits_sender_mismatch`] — the case it must NOT
//!     accidentally weaken: an ordinary `open_inbound` call (`mailbox_id: None`, the live/
//!     federated-live path) with a genuinely forged `from` must still be rejected exactly as
//!     before, proving the live-path defense-in-depth check is unweakened by this task.

use meridian_core::chat::{ChatError, ChatState};
use meridian_envelope::ChatContent;
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_proto::MAILBOX_DRAIN_FROM_PLACEHOLDER;
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

    fn publish(&mut self, otk_count: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let ik = self.ik();
        let gen = generate_bundle(&self.store, self.account.handle(), ik, otk_count).unwrap();
        let otks: Vec<([u8; 32], [u8; 32])> = gen
            .bundle
            .otks
            .iter()
            .zip(gen.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        self.state
            .vault
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, 1_700_000_000);
        (gen.bundle.spk, gen.bundle.otks)
    }

    fn start(&mut self, peer: &[u8; 32], peer_spk: &[u8; 32], peer_opk: Option<[u8; 32]>) {
        let ik = self.ik();
        self.state
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                peer_spk,
                peer_opk,
            )
            .unwrap();
    }

    fn seal(&mut self, peer: &[u8; 32], body: &str) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                &ChatContent::Text {
                    id: [7u8; 16],
                    body: body.into(),
                },
            )
            .unwrap()
    }
}

/// Accept-side happy path: the exact wire condition task 8.7 produces (`Deliver.mailbox_id:
/// Some(_)`, `Deliver.from: MAILBOX_DRAIN_FROM_PLACEHOLDER`) must decrypt cleanly through
/// `open_inbound_from_mailbox`, authenticated by `envelope.sender_pub` + the ratchet AEAD alone.
#[test]
fn mailbox_drained_deliver_with_placeholder_from_decrypts_successfully() {
    let mut alice = Party::new("mailbox-sender-check.a");
    let mut bob = Party::new("mailbox-sender-check.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let (bob_spk, bob_otks) = bob.publish(2);

    alice.start(&bob_ik, &bob_spk, Some(bob_otks[0]));
    let blob = alice.seal(&bob_ik, "queued while you were away");

    // The server never asserts a real sender for a mailbox-drained push — it hands back the fixed
    // placeholder, not `alice_ik`. This is a first-contact envelope (task 2.10's request gate),
    // so a successful decrypt-and-establish surfaces as `Err(MessageRequest)`, exactly like the
    // ordinary relay path — never a hard rejection.
    let outcome = bob.state.open_inbound_from_mailbox(
        &bob.store,
        bob.account.handle(),
        &bob_ik,
        &MAILBOX_DRAIN_FROM_PLACEHOLDER,
        &blob,
    );
    assert!(
        matches!(outcome, Err(ChatError::MessageRequest)),
        "a mailbox-drained first-contact envelope must decrypt via envelope.sender_pub + the \
         ratchet AEAD alone and land in the message-request queue — never rejected purely \
         because `from` is the placeholder. Got: {outcome:?}"
    );
    // The session really was installed under the SENDER's key, not the placeholder — decrypt
    // (and X3DH establishment) genuinely happened, it was only gated for delivery/display.
    assert!(bob.state.has_session(&alice_ik));
    let req = bob
        .state
        .accept_request(&alice_ik)
        .expect("open_inbound_from_mailbox must have queued a pending request for alice_ik");
    assert_eq!(
        req.intro,
        ChatContent::Text {
            id: [7u8; 16],
            body: "queued while you were away".into(),
        }
    );
}

/// Regression, the direction this restructuring must NOT weaken: an ordinary live (or
/// federated-live) delivery — `open_inbound`, never `open_inbound_from_mailbox` — with a `from`
/// that does not match the envelope's real `sender_pub` must still be rejected with
/// `ChatError::SenderMismatch`, exactly as before task 8.8.
#[test]
fn live_deliver_with_forged_from_still_hits_sender_mismatch() {
    let mut alice = Party::new("mailbox-sender-check.live.a");
    let mut bob = Party::new("mailbox-sender-check.live.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let (bob_spk, bob_otks) = bob.publish(2);

    alice.start(&bob_ik, &bob_spk, Some(bob_otks[0]));
    let blob = alice.seal(&bob_ik, "live message");

    // A hostile/broken routing layer claims a different `from` than the envelope's real
    // `sender_pub` — must be rejected before any crypto work, exactly as always.
    let forged_from = [0xEEu8; 32];
    assert_ne!(
        forged_from, alice_ik,
        "the forgery must actually differ from the real sender"
    );
    let result = bob.state.open_inbound(
        &bob.store,
        bob.account.handle(),
        &bob_ik,
        &forged_from,
        &blob,
    );
    assert!(
        matches!(result, Err(ChatError::SenderMismatch)),
        "a live delivery with a forged `from` must still be ChatError::SenderMismatch — the \
         restructuring for mailbox-drained pushes (task 8.8, ADR 0024) must never weaken this \
         path. Got: {result:?}"
    );

    // And the placeholder itself is rejected too on the LIVE path — `open_inbound_from_mailbox`
    // is the only entry point ADR 0024 exempts, never `open_inbound` regardless of the `from`
    // value supplied.
    let result_placeholder = bob.state.open_inbound(
        &bob.store,
        bob.account.handle(),
        &bob_ik,
        &MAILBOX_DRAIN_FROM_PLACEHOLDER,
        &blob,
    );
    assert!(
        matches!(result_placeholder, Err(ChatError::SenderMismatch)),
        "the mailbox-drain placeholder must not be treated as a magic bypass on the ordinary \
         `open_inbound` entry point — only `open_inbound_from_mailbox` may skip the sender check. \
         Got: {result_placeholder:?}"
    );
}
