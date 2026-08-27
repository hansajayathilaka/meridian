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

/// Seal `plaintext` on `s`, returning the framed ciphertext together with the exact preamble bytes
/// [`Session::encrypt`] bound into its AAD (ADR 0016 C3) — the `(ct, preamble)` pair a real caller
/// would get from `encrypt()` plus a `MessageEnvelope`'s own `prekey` field. This file drives
/// `Session` directly, with no `MessageEnvelope`/wire layer to carry the preamble across, so it is
/// threaded explicitly instead. Captured via [`Session::outbound_preamble_bytes`] *before* `encrypt`
/// runs — harmless either way, since `encrypt` never mutates the prekey/confirmed state that method
/// reads, only `decrypt` does.
fn seal(s: &mut Session, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let preamble = s.outbound_preamble_bytes();
    let ct = s.encrypt(plaintext).unwrap();
    (ct, preamble)
}

#[test]
fn bidirectional_conversation_with_receipts() {
    let (mut a, mut b) = establish();

    // Alice's first message must be decryptable by Bob (carries the initial ratchet step, and the
    // real X3DH prekey preamble — she is still unconfirmed).
    let (c0, c0_pre) = seal(&mut a, b"hello bob");
    assert_eq!(b.decrypt(&c0, &c0_pre).unwrap(), b"hello bob");

    // Bob can now reply (his sending chain is established after the first receive).
    let (r0, r0_pre) = seal(&mut b, b"hi alice (delivery receipt)");
    assert_eq!(
        a.decrypt(&r0, &r0_pre).unwrap(),
        b"hi alice (delivery receipt)"
    );

    // Several back-and-forth turns exercise repeated DH ratchets.
    for i in 0..5u8 {
        let (ca, ca_pre) = seal(&mut a, &[i; 8]);
        assert_eq!(b.decrypt(&ca, &ca_pre).unwrap(), vec![i; 8]);
        let (cb, cb_pre) = seal(&mut b, &[i.wrapping_add(100); 8]);
        assert_eq!(
            a.decrypt(&cb, &cb_pre).unwrap(),
            vec![i.wrapping_add(100); 8]
        );
    }
}

#[test]
fn out_of_order_delivery_decrypts() {
    let (mut a, mut b) = establish();
    // Prime Bob's receiving chain with the first message (establishes his ratchet).
    let (c0, c0_pre) = seal(&mut a, b"m0");
    assert_eq!(b.decrypt(&c0, &c0_pre).unwrap(), b"m0");

    // Alice sends three more; the server shuffles them. All three ride the SAME (empty, since she
    // is now confirmed) preamble, but each is captured at its own send for clarity/robustness.
    let (c1, c1_pre) = seal(&mut a, b"m1");
    let (c2, c2_pre) = seal(&mut a, b"m2");
    let (c3, c3_pre) = seal(&mut a, b"m3");

    // Deliver 3, 1, 2 — skipped-message keys must cover the gaps.
    assert_eq!(b.decrypt(&c3, &c3_pre).unwrap(), b"m3");
    assert_eq!(b.decrypt(&c1, &c1_pre).unwrap(), b"m1");
    assert_eq!(b.decrypt(&c2, &c2_pre).unwrap(), b"m2");
}

#[test]
fn forward_secrecy_snapshot_cannot_decrypt_past() {
    let (mut a, mut b) = establish();
    let (c0, c0_pre) = seal(&mut a, b"secret-0");
    let (c1, c1_pre) = seal(&mut a, b"secret-1");

    assert_eq!(b.decrypt(&c0, &c0_pre).unwrap(), b"secret-0");
    assert_eq!(b.decrypt(&c1, &c1_pre).unwrap(), b"secret-1");

    // Snapshot Bob's state *after* consuming c0/c1, then try to re-decrypt c0. The message key was
    // derived and dropped, so the snapshot cannot recover message 0 — forward secrecy.
    let mut snapshot = Vec::new();
    ciborium::into_writer(&b, &mut snapshot).unwrap();
    let mut restored: Session = ciborium::from_reader(&snapshot[..]).unwrap();
    assert!(
        restored.decrypt(&c0, &c0_pre).is_err(),
        "a post-N snapshot must not decrypt message <N"
    );
}

#[test]
fn post_compromise_security_heals_after_round_trip() {
    let (mut a, mut b) = establish();
    let (c0, c0_pre) = seal(&mut a, b"m0");
    b.decrypt(&c0, &c0_pre).unwrap();

    // Attacker steals Bob's full ratchet state here (Bob currently holds ratchet key b1).
    let mut stolen: Vec<u8> = Vec::new();
    ciborium::into_writer(&b, &mut stolen).unwrap();

    // Healing requires Bob to rotate in a *fresh* ratchet key the attacker never saw, and Alice to
    // adopt it — i.e. one full DH-ratchet round trip. Bob injects a fresh key only when he next
    // receives Alice's new ratchet key, so drive one round trip in each direction:
    let (rb, rb_pre) = seal(&mut b, b"bob-1"); // still on the compromised key b1
    a.decrypt(&rb, &rb_pre).unwrap(); // Alice ratchets, generates A2
    let (ra, ra_pre) = seal(&mut a, b"alice-1");
    b.decrypt(&ra, &ra_pre).unwrap(); // Bob ratchets to A2, generates fresh b2 (attacker lacks it)
    let (rb2, rb2_pre) = seal(&mut b, b"bob-2"); // carries B2
    a.decrypt(&rb2, &rb2_pre).unwrap(); // Alice adopts B2 → her root now mixes the fresh b2

    // Alice's next message rides a chain the attacker can no longer reconstruct.
    let (c_future, c_future_pre) = seal(&mut a, b"post-heal secret");

    let mut thief: Session = ciborium::from_reader(&stolen[..]).unwrap();
    assert!(
        thief.decrypt(&c_future, &c_future_pre).is_err(),
        "stolen state must not decrypt messages sent after the healing round trip"
    );
    // The legitimate peer stays in sync.
    assert_eq!(
        b.decrypt(&c_future, &c_future_pre).unwrap(),
        b"post-heal secret"
    );
}

#[test]
fn session_survives_persistence_restart() {
    let (mut a, mut b) = establish();
    let (c0, c0_pre) = seal(&mut a, b"before restart");
    b.decrypt(&c0, &c0_pre).unwrap();

    // Persist Bob's session (as the encrypted store would), drop it, reload, and keep chatting.
    let mut sealed = Vec::new();
    ciborium::into_writer(&b, &mut sealed).unwrap();
    drop(b);
    let mut b2: Session = ciborium::from_reader(&sealed[..]).unwrap();

    let (c1, c1_pre) = seal(&mut a, b"after restart");
    assert_eq!(b2.decrypt(&c1, &c1_pre).unwrap(), b"after restart");
    let (r, r_pre) = seal(&mut b2, b"still here");
    assert_eq!(a.decrypt(&r, &r_pre).unwrap(), b"still here");
}
