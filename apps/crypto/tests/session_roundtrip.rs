//! End-to-end X3DH + Double Ratchet exercises: the T03 acceptance properties at the crypto layer.
//!
//! Covers a two-party conversation, out-of-order delivery (skipped keys), forward secrecy
//! (a snapshot at message N cannot decrypt <N), post-compromise security (a stolen snapshot cannot
//! follow the session past one DH-ratchet round trip), and session persistence across a restart.

use meridian_crypto::{PrekeyMaterial, Session};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use x25519_dalek::{PublicKey, StaticSecret};

struct Party {
    store: MemorySecretStore,
    account: AccountId,
}

impl Party {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).expect("account");
        Self { store, account }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
}

fn x25519_pair() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let s = StaticSecret::from(seed);
    (s.to_bytes(), PublicKey::from(&s).to_bytes())
}

/// Build Alice→Bob: returns Alice's session, Bob's session, and Bob's prekey secrets so we can
/// re-establish if needed.
fn establish() -> (Session, Session) {
    let alice = Party::new("chat.a");
    let bob = Party::new("chat.b");
    let (spk_secret, spk_pub) = x25519_pair();
    let (opk_secret, opk_pub) = x25519_pair();

    let (sess_a, material) = Session::initiate(
        &alice.store,
        alice.account.handle(),
        &alice.ik(),
        &bob.ik(),
        &spk_pub,
        Some(opk_pub),
    )
    .expect("initiate");

    // Bob receives the prekey material and completes X3DH as responder.
    let sess_b = Session::respond(
        &bob.store,
        bob.account.handle(),
        &bob.ik(),
        &alice.ik(),
        &material,
        &spk_secret,
        Some(opk_secret),
    )
    .expect("respond");

    // Sanity: both derived the same safety number, and the prekey material round-trips as CBOR.
    assert_eq!(
        sess_a.safety_number(&alice.ik()),
        sess_b.safety_number(&bob.ik())
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&material, &mut buf).unwrap();
    let decoded: PrekeyMaterial = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(decoded, material);

    (sess_a, sess_b)
}

#[test]
fn bidirectional_conversation_with_receipts() {
    let (mut a, mut b) = establish();

    // Alice's first message must be decryptable by Bob (carries the initial ratchet step).
    let c0 = a.encrypt(b"hello bob").unwrap();
    assert_eq!(b.decrypt(&c0).unwrap(), b"hello bob");

    // Bob can now reply (his sending chain is established after the first receive).
    let r0 = b.encrypt(b"hi alice (delivery receipt)").unwrap();
    assert_eq!(a.decrypt(&r0).unwrap(), b"hi alice (delivery receipt)");

    // Several back-and-forth turns exercise repeated DH ratchets.
    for i in 0..5u8 {
        let ca = a.encrypt(&[i; 8]).unwrap();
        assert_eq!(b.decrypt(&ca).unwrap(), vec![i; 8]);
        let cb = b.encrypt(&[i.wrapping_add(100); 8]).unwrap();
        assert_eq!(a.decrypt(&cb).unwrap(), vec![i.wrapping_add(100); 8]);
    }
}

#[test]
fn out_of_order_delivery_decrypts() {
    let (mut a, mut b) = establish();
    // Prime Bob's receiving chain with the first message (establishes his ratchet).
    let c0 = a.encrypt(b"m0").unwrap();
    assert_eq!(b.decrypt(&c0).unwrap(), b"m0");

    // Alice sends three more; the server shuffles them.
    let c1 = a.encrypt(b"m1").unwrap();
    let c2 = a.encrypt(b"m2").unwrap();
    let c3 = a.encrypt(b"m3").unwrap();

    // Deliver 3, 1, 2 — skipped-message keys must cover the gaps.
    assert_eq!(b.decrypt(&c3).unwrap(), b"m3");
    assert_eq!(b.decrypt(&c1).unwrap(), b"m1");
    assert_eq!(b.decrypt(&c2).unwrap(), b"m2");
}

#[test]
fn forward_secrecy_snapshot_cannot_decrypt_past() {
    let (mut a, mut b) = establish();
    let c0 = a.encrypt(b"secret-0").unwrap();
    let c1 = a.encrypt(b"secret-1").unwrap();

    assert_eq!(b.decrypt(&c0).unwrap(), b"secret-0");
    assert_eq!(b.decrypt(&c1).unwrap(), b"secret-1");

    // Snapshot Bob's state *after* consuming c0/c1, then try to re-decrypt c0. The message key was
    // derived and dropped, so the snapshot cannot recover message 0 — forward secrecy.
    let mut snapshot = Vec::new();
    ciborium::into_writer(&b, &mut snapshot).unwrap();
    let mut restored: Session = ciborium::from_reader(&snapshot[..]).unwrap();
    assert!(
        restored.decrypt(&c0).is_err(),
        "a post-N snapshot must not decrypt message <N"
    );
}

#[test]
fn post_compromise_security_heals_after_round_trip() {
    let (mut a, mut b) = establish();
    let c0 = a.encrypt(b"m0").unwrap();
    b.decrypt(&c0).unwrap();

    // Attacker steals Bob's full ratchet state here (Bob currently holds ratchet key b1).
    let mut stolen: Vec<u8> = Vec::new();
    ciborium::into_writer(&b, &mut stolen).unwrap();

    // Healing requires Bob to rotate in a *fresh* ratchet key the attacker never saw, and Alice to
    // adopt it — i.e. one full DH-ratchet round trip. Bob injects a fresh key only when he next
    // receives Alice's new ratchet key, so drive one round trip in each direction:
    let rb = b.encrypt(b"bob-1").unwrap(); // still on the compromised key b1
    a.decrypt(&rb).unwrap(); // Alice ratchets, generates A2
    let ra = a.encrypt(b"alice-1").unwrap();
    b.decrypt(&ra).unwrap(); // Bob ratchets to A2, generates fresh b2 (attacker lacks it)
    let rb2 = b.encrypt(b"bob-2").unwrap(); // carries B2
    a.decrypt(&rb2).unwrap(); // Alice adopts B2 → her root now mixes the fresh b2

    // Alice's next message rides a chain the attacker can no longer reconstruct.
    let c_future = a.encrypt(b"post-heal secret").unwrap();

    let mut thief: Session = ciborium::from_reader(&stolen[..]).unwrap();
    assert!(
        thief.decrypt(&c_future).is_err(),
        "stolen state must not decrypt messages sent after the healing round trip"
    );
    // The legitimate peer stays in sync.
    assert_eq!(b.decrypt(&c_future).unwrap(), b"post-heal secret");
}

#[test]
fn session_survives_persistence_restart() {
    let (mut a, mut b) = establish();
    let c0 = a.encrypt(b"before restart").unwrap();
    b.decrypt(&c0).unwrap();

    // Persist Bob's session (as the encrypted store would), drop it, reload, and keep chatting.
    let mut sealed = Vec::new();
    ciborium::into_writer(&b, &mut sealed).unwrap();
    drop(b);
    let mut b2: Session = ciborium::from_reader(&sealed[..]).unwrap();

    let c1 = a.encrypt(b"after restart").unwrap();
    assert_eq!(b2.decrypt(&c1).unwrap(), b"after restart");
    let r = b2.encrypt(b"still here").unwrap();
    assert_eq!(a.decrypt(&r).unwrap(), b"still here");
}
