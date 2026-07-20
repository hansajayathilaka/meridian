//! Core chat-session-manager integration: a full relayed exchange (X3DH prekey message → reply →
//! receipt) driven entirely through opaque blobs, plus tamper rejection and sealed persistence.
//! No network: the "relay" is just handing blob bytes between two [`ChatState`]s.

use meridian_core::chat::ChatState;
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
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks);
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
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatErr> {
        let ik = self.ik();
        self.state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
            .map_err(|_| ChatErr)
    }
}

struct ChatErr;

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
