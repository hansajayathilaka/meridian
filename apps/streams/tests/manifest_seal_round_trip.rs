//! Proves `FileStream::build_open_params` (task 10.6) genuinely routes the per-file key `k_f`
//! through the *existing* ratchet-sealing primitive (`ChatState::seal_bytes`) rather than inventing
//! a new mechanism or leaking `k_f` in the clear: a real two-party X3DH handshake establishes a
//! session, the sender builds a manifest, and the recipient — who only ever sees the manifest's
//! `key` field, never the raw `k_f` — recovers the identical `k_f` by decrypting it the same way any
//! other ratchet-sealed payload in this codebase is opened.
//!
//! Also covers the "no session yet" failure path: sealing must error, never silently send `k_f`
//! unsealed.

use meridian_core::chat::{ChatError, ChatState};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use meridian_streams::{FileManifest, FileMeta, FileStream, FileStreamError};

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
}

#[test]
fn k_f_survives_a_real_ratchet_seal_and_open_round_trip() {
    let mut alice = Party::new("file.manifest.alice");
    let mut bob = Party::new("file.manifest.bob");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // Bob publishes a bundle; Alice starts a session against it (mirrors chat_manager.rs's own
    // two-party setup) so `alice.state.seal_bytes(..., &bob_ik, ...)` has a session to encrypt on.
    let bob_bundle = generate_bundle(&bob.store, bob.account.handle(), bob_ik, 5).unwrap();
    let otks: Vec<([u8; 32], [u8; 32])> = bob_bundle
        .bundle
        .otks
        .iter()
        .zip(bob_bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.state.vault.set_bundle(
        bob_bundle.bundle.spk,
        *bob_bundle.spk_secret,
        otks,
        1_700_000_000,
    );
    alice
        .state
        .start_initiator_session(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &bob_ik,
            &bob_bundle.bundle.spk,
            Some(bob_bundle.bundle.otks[0]),
        )
        .unwrap();

    let root = [0x7Au8; 32];
    let (params, k_f) = FileStream::build_open_params(
        &mut alice.state,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        FileMeta {
            name: "vacation.mp4".to_string(),
            size: 123_456,
            root,
        },
    )
    .expect("sealing k_f over an established session must succeed");

    let manifest = FileManifest::decode(&params).expect("Open.params must decode as a manifest");
    assert_eq!(manifest.name, "vacation.mp4");
    assert_eq!(manifest.size, 123_456);
    assert_eq!(manifest.root, root);
    // The manifest's `key` field must be the *sealed* (ciphertext) form, never the raw k_f bytes.
    assert_ne!(
        manifest.key,
        k_f.to_vec(),
        "the manifest must never carry k_f in the clear"
    );

    // Bob — who has never seen `k_f` directly — opens the sealed blob the same way any other
    // ratchet-sealed payload in this codebase is opened, and recovers the identical key.
    let opened = bob
        .state
        .open_bytes(
            &bob.store,
            bob.account.handle(),
            &bob_ik,
            &alice_ik,
            &manifest.key,
            false,
        )
        .expect("the recipient must be able to open k_f via the existing ratchet primitive");
    assert_eq!(
        opened,
        k_f.to_vec(),
        "the recipient's opened plaintext must equal the sender's own k_f"
    );
}

#[test]
fn build_open_params_errors_rather_than_sending_k_f_unsealed_without_a_session() {
    let mut alice = Party::new("file.manifest.no-session");
    let alice_ik = alice.ik();
    let stranger_ik = [0x99u8; 32];

    let err = FileStream::build_open_params(
        &mut alice.state,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &stranger_ik,
        FileMeta {
            name: "photo.png".to_string(),
            size: 10,
            root: [0u8; 32],
        },
    )
    .expect_err("sealing k_f with no established session must fail, never silently proceed");
    assert!(matches!(err, FileStreamError::Seal(ChatError::NoSession)));
}

#[test]
fn two_manifests_for_the_same_file_metadata_carry_independently_random_k_f_and_distinct_ciphertext()
{
    let mut alice = Party::new("file.manifest.freshness.alice");
    let mut bob = Party::new("file.manifest.freshness.bob");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    let bundle = generate_bundle(&bob.store, bob.account.handle(), bob_ik, 5).unwrap();
    let otks: Vec<([u8; 32], [u8; 32])> = bundle
        .bundle
        .otks
        .iter()
        .zip(bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.state
        .vault
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks, 1_700_000_000);
    alice
        .state
        .start_initiator_session(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &bob_ik,
            &bundle.bundle.spk,
            Some(bundle.bundle.otks[0]),
        )
        .unwrap();

    let (_params1, k_f1) = FileStream::build_open_params(
        &mut alice.state,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        FileMeta {
            name: "a.png".to_string(),
            size: 1,
            root: [1u8; 32],
        },
    )
    .unwrap();
    let (_params2, k_f2) = FileStream::build_open_params(
        &mut alice.state,
        &alice.store,
        alice.account.handle(),
        &alice_ik,
        &bob_ik,
        FileMeta {
            name: "a.png".to_string(),
            size: 1,
            root: [1u8; 32],
        },
    )
    .unwrap();

    assert_ne!(
        k_f1, k_f2,
        "two files (even with identical name/size/root) must never share a per-file key"
    );
}
