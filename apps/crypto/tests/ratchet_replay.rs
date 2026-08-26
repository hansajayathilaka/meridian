//! Task 2.13 — a failed `DoubleRatchet::decrypt` (e.g. a byte-identical replay) must not corrupt
//! the receiving chain. Mirrors the byte-identical-state-comparison pattern task 1.18 used for
//! `ChatState` (`apps/core/tests/chat_manager.rs::undecryptable_envelope_is_rejected_without_touching_the_session`),
//! but at the ratchet layer directly and for the AEAD-failure path specifically (1.18 covered the
//! header-undecryptable path, which never reaches the mutations this task fixes).

use meridian_crypto::{CryptoError, DoubleRatchet};
use x25519_dalek::{PublicKey, StaticSecret};

/// (task 6.3, ADR 0016 C2/C3) `encrypt`/`decrypt` now take an explicit preamble argument, folded
/// into the v2 AAD. This file exercises ratchet failure-atomicity, not preamble binding (that is
/// `apps/crypto/src/ratchet.rs`'s own unit tests' job), and never carries an X3DH preamble on any
/// step here, so every call below consistently uses the empty preamble.
const NO_PREAMBLE: &[u8] = &[];

fn x25519_pair() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let s = StaticSecret::from(seed);
    (s.to_bytes(), PublicKey::from(&s).to_bytes())
}

/// Deterministic CBOR of the whole ratchet state (`DoubleRatchet` is `Serialize`) — the same
/// byte-identical-comparison technique task 1.18 used for `ChatState`, applied directly to the
/// ratchet since that is the layer whose internal mutation ordering is under test here.
fn state_bytes(r: &DoubleRatchet) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(r, &mut out).unwrap();
    out
}

fn established_pair() -> (DoubleRatchet, DoubleRatchet) {
    let root = [0x11u8; 32];
    let hk_ab = [0x22u8; 32];
    let hk_ba = [0x33u8; 32];
    let ad = vec![0x44u8; 16];

    let (bob_priv, bob_pub) = x25519_pair();

    let alice = DoubleRatchet::init_initiator(root, bob_pub, hk_ab, hk_ba, ad.clone())
        .expect("init_initiator");
    let bob = DoubleRatchet::init_responder(root, bob_priv, bob_pub, hk_ab, hk_ba, ad);
    (alice, bob)
}

/// A byte-identical replay of an already-consumed message: the header decodes fine (same header
/// key as ever), but the message key it re-derives no longer matches what the ciphertext was
/// sealed under, so `aead_open` must fail. Before the task-2.13 fix this left `ckr`/`nr` advanced
/// one step past the sender regardless, permanently wedging the chain. After the fix, the ratchet
/// must be byte-for-byte unchanged, and a genuine subsequent message must still open.
#[test]
fn failed_decrypt_leaves_ratchet_state_untouched_and_session_survives() {
    let (mut alice, mut bob) = established_pair();

    // Establish: alice's first message primes bob's receiving chain (his first DH ratchet step).
    let c0 = alice.encrypt(b"hello bob", NO_PREAMBLE).unwrap();
    assert_eq!(bob.decrypt(&c0, NO_PREAMBLE).unwrap(), b"hello bob");

    // A genuine second message, consumed normally — this is the one a relay will replay.
    let c1 = alice.encrypt(b"m1", NO_PREAMBLE).unwrap();
    assert_eq!(bob.decrypt(&c1, NO_PREAMBLE).unwrap(), b"m1");

    let before = state_bytes(&bob);

    // Replay: hand bob the exact same bytes again.
    let err = bob
        .decrypt(&c1, NO_PREAMBLE)
        .expect_err("a byte-identical replay must not decrypt a second time");
    assert!(
        matches!(err, CryptoError::Crypto),
        "a replay's header decodes fine (same header key) but the re-derived message key must \
         fail AEAD authentication — anything else (e.g. UndecryptableHeader) would mean this test \
         is not exercising the AEAD-failure path task 2.13 fixes. Got: {err:?}"
    );

    assert_eq!(
        before,
        state_bytes(&bob),
        "a failed decrypt (AEAD authentication failure) must leave the ratchet byte-identically \
         unchanged — no advanced ckr/nr, no DH-ratchet step, no leftover skipped-key entries \
         (task 2.13). Before this fix, `ckr`/`nr` were committed before `aead_open` ran and never \
         rolled back, permanently wedging the chain one step ahead of the sender."
    );

    // The session is genuinely still live: a subsequent GENUINE message decrypts fine. Before the
    // fix this would fail with CryptoError::Crypto forever, because bob's `ckr`/`nr` had already
    // been advanced past what alice's actual next message rides.
    let c2 = alice.encrypt(b"m2", NO_PREAMBLE).unwrap();
    assert_eq!(
        bob.decrypt(&c2, NO_PREAMBLE).unwrap(),
        b"m2",
        "a genuine message after a rejected replay must still decrypt — the rollback must not \
         itself have broken the happy path"
    );
}

/// Same property, but for the compound path the task file specifically flags as subtle: a failed
/// decrypt that would have run a **DH-ratchet step** (`dh_ratchet`) and populated `skipped` on
/// **both** the old chain (`skip_message_keys(pn)`) and the new one (`skip_message_keys(n)`) while
/// catching up — all before the final AEAD check fails. An incomplete rollback here would leave
/// skipped-key entries behind with zero authenticated bytes, which is exactly ADR 0016 R2's
/// unbounded-growth surface.
#[test]
fn failed_decrypt_during_a_dh_ratchet_catch_up_leaves_no_skipped_key_residue() {
    let (mut alice, mut bob) = established_pair();

    // Establish bob's receiving chain (his first DH-ratchet step, off alice's opening message).
    let c0 = alice.encrypt(b"hello bob", NO_PREAMBLE).unwrap();
    bob.decrypt(&c0, NO_PREAMBLE).unwrap();

    // Alice sends a second message on the SAME chain, but it is held back — bob will only learn
    // about it later, via a skipped-key catch-up on the *old* chain.
    let c1 = alice.encrypt(b"held-back-old-chain", NO_PREAMBLE).unwrap();

    // Bob replies. Alice must consume it to advance her own sending ratchet to a fresh chain
    // (the PCS DH step) — this is what makes bob's next receive of an alice message look like a
    // DH-ratchet step from his side.
    let r0 = bob.encrypt(b"hi alice", NO_PREAMBLE).unwrap();
    assert_eq!(alice.decrypt(&r0, NO_PREAMBLE).unwrap(), b"hi alice");

    // Alice sends two more messages, now on her NEW post-ratchet chain. Bob will only be handed
    // the second — a gap on the OLD chain (c1) plus a gap on the NEW chain (d0) that a single
    // `decrypt` call must catch up through a DH-ratchet step, all before the final AEAD check.
    let d0 = alice.encrypt(b"held-back-new-chain", NO_PREAMBLE).unwrap();
    let d1 = alice.encrypt(b"m3", NO_PREAMBLE).unwrap();

    let before = state_bytes(&bob);

    // Corrupt d1's ciphertext (last byte, well past the header) so the header still decodes fine
    // — driving `is_dh_ratchet`, `skip_message_keys(pn)` (catches up c1 on the OLD chain),
    // `dh_ratchet` (full key-schedule rotation, including regenerating bob's own DH keypair), and
    // `skip_message_keys(n)` (catches up d0 on the NEW chain) exactly as a real delivery would —
    // but the final `aead_open` must fail.
    let mut tampered = d1.clone();
    *tampered.last_mut().unwrap() ^= 0xFF;

    let err = bob
        .decrypt(&tampered, NO_PREAMBLE)
        .expect_err("a tampered ciphertext must not decrypt, even mid catch-up");
    assert!(
        matches!(err, CryptoError::Crypto),
        "expected the AEAD-failure path (after skip_message_keys/dh_ratchet ran), got: {err:?}"
    );

    assert_eq!(
        before,
        state_bytes(&bob),
        "a failed decrypt that would have run a DH-ratchet step AND populated `skipped` entries \
         on both the old and new chain while catching up must leave the ratchet byte-identically \
         unchanged — an incomplete rollback here is exactly ADR 0016 R2's unbounded-growth \
         surface, reachable with zero authenticated bytes"
    );

    // The session is still live: delivering the real (untampered) ciphertext runs the identical
    // catch-up for real and must open correctly.
    let opened = bob
        .decrypt(&d1, NO_PREAMBLE)
        .expect("the genuine message must still decrypt after a rejected tamper");
    assert_eq!(opened, b"m3");

    // And BOTH messages this real catch-up skipped over — one on the old chain, one on the new —
    // are recoverable from their retained skipped keys: proof the entries are present exactly
    // once each (a partial rollback that dropped one but not the other would fail this).
    assert_eq!(
        bob.decrypt(&c1, NO_PREAMBLE).unwrap(),
        b"held-back-old-chain"
    );
    assert_eq!(
        bob.decrypt(&d0, NO_PREAMBLE).unwrap(),
        b"held-back-new-chain"
    );
}
