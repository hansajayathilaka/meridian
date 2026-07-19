//! Double Ratchet (header-encrypted) conformance fixtures (`test-vectors/ratchet-v1.json`).
//!
//! Both parties' starting ratchet state is pinned directly — via
//! [`meridian_crypto::DoubleRatchet::init_responder`] (already deterministic) and the
//! test-support-only `init_initiator_with_keypair` (task 1.6; takes an explicit sending secret
//! instead of drawing one from the OS CSPRNG) — rather than via a fresh X3DH run, so nothing here
//! depends on randomness *until the protocol itself injects fresh entropy*.
//!
//! **Determinism boundary** (same spirit as the header-nonce carve-out below): every DH-ratchet
//! step generates a brand-new sending keypair via the OS CSPRNG (`dh_ratchet`, ratchet.rs) — that
//! is exactly the mechanism that gives post-compromise security, so it is not something to work
//! around. Concretely: Alice's *first* sending chain is deterministic (pinned via
//! `init_initiator_with_keypair`), and so is Bob's corresponding *receiving* chain (it only
//! depends on Bob's own pinned initial keypair, not on any randomly generated one). But the
//! instant Bob (or Alice, symmetrically) sends a *reply*, that reply rides a chain seeded by a
//! keypair `dh_ratchet` generated internally and never surfaces — so it cannot be byte-pinned.
//! Steps like that are recorded with `chain_key_pinned: false` and no `ck_before`/`ck_after`/`mk`
//! fields; the conformance test still drives them through the real API and asserts the plaintext
//! round-trips, just not against committed key material.
//!
//! Every *pinned* intermediate (`root`/chain-key/message-key) is computed with the crate's real
//! `dh`/`kdf_rk`/`kdf_ck` (via [`meridian_crypto::test_support`]), fed the exact keys the two
//! `DoubleRatchet` instances are constructed from, so the committed numbers are exactly what
//! `encrypt`/`decrypt` compute internally — not a parallel reimplementation.
//!
//! Header ciphertext is never pinned: `header_seal` draws a random 24-byte nonce by design, so a
//! byte-pinned header ciphertext would be flaky. The JSON instead carries a fixed header key +
//! header plaintext and states the round-trip property; the actual `header_seal`/`header_open`
//! round trip is asserted live by the conformance test.

use meridian_crypto::test_support::{dh, kdf_ck, kdf_rk};
use meridian_crypto::DoubleRatchet;
use serde::Serialize;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Serialize)]
struct Fixtures {
    version: u32,
    note: String,
    initial_state: InitialState,
    transcript: Vec<Step>,
    header_round_trip: HeaderRoundTrip,
}

#[derive(Serialize)]
struct InitialState {
    root_hex: String,
    hk_ab_hex: String,
    hk_ba_hex: String,
    ad_hex: String,
    /// Alice (initiator)'s fixed sending secret (`init_initiator_with_keypair`, test-support only).
    alice_dhs_priv_hex: String,
    alice_dhs_pub_hex: String,
    /// Bob (responder)'s fixed initial ratchet keypair (his X3DH signed prekey, in practice).
    bob_dhs_priv_hex: String,
    bob_dhs_pub_hex: String,
    /// `kdf_rk(root, DH(alice_dhs_priv, bob_dhs_pub))` — Alice's sending chain (and, since DH is
    /// commutative for the corresponding keypairs, Bob's matching *receiving* chain) at
    /// construction time. Real code, matches what `init_initiator_with_keypair` /
    /// `DoubleRatchet::decrypt`'s first `dh_ratchet` call compute internally.
    alice_initial_root_hex: String,
    alice_initial_cks_hex: String,
    alice_initial_nhks_hex: String,
}

#[derive(Serialize)]
struct Step {
    /// `"alice->bob"` or `"bob->alice"`.
    direction: String,
    /// Plaintext bytes sent (informational; ciphertext bytes are never pinned — see module doc).
    plaintext_hex: String,
    /// The message number `N` within its sending chain.
    n: u32,
    /// True the first time a message rides a *new* DH-ratchet step on this chain.
    dh_ratchet_step: bool,
    /// True if this message is delivered out of order (after a later message in the same chain
    /// has already advanced the receiver), exercising the skipped-message-key path.
    delivered_out_of_order: bool,
    /// False for a message whose chain key was seeded by a keypair the receiving side generated
    /// internally (`dh_ratchet`'s fresh CSPRNG draw) — see the determinism-boundary note above.
    /// When false, `ck_before_hex`/`ck_after_hex`/`mk_hex` are omitted.
    chain_key_pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ck_before_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ck_after_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mk_hex: Option<String>,
}

#[derive(Serialize)]
struct HeaderRoundTrip {
    note: String,
    hk_hex: String,
    header_plaintext_hex: String,
}

/// One party's ratchet-chain cursor, tracked independently of `DoubleRatchet` (which exposes no
/// getters by design) via the same real `kdf_ck` primitive.
struct ChainCursor {
    ck: [u8; 32],
}

impl ChainCursor {
    fn advance(&mut self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let before = self.ck;
        let (next, mk) = kdf_ck(&self.ck);
        self.ck = next;
        (before, next, mk)
    }
}

fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
    XPublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

pub fn generate_ratchet() -> Result<(), String> {
    let root = [0xAAu8; 32];
    let hk_ab = [0xBBu8; 32];
    let hk_ba = [0xCCu8; 32];
    let ad: Vec<u8> = (0u8..16).collect();

    let alice_dhs_priv = [0xEEu8; 32];
    let alice_dhs_pub = x25519_pub(&alice_dhs_priv);
    let bob_dhs_priv = [0xDDu8; 32];
    let bob_dhs_pub = x25519_pub(&bob_dhs_priv);

    // Real DH + KDF_RK — exactly what `init_initiator_with_keypair` (Alice) and the first
    // `dh_ratchet` call inside `decrypt` (Bob) compute internally.
    let alice_dh0 = dh(&alice_dhs_priv, &bob_dhs_pub);
    let (alice_root0, alice_cks0, alice_nhks0) = kdf_rk(&root, &alice_dh0);

    // Build both live ratchets from the same pinned inputs (real construction code, no RNG).
    let mut alice = DoubleRatchet::init_initiator_with_keypair(
        root,
        alice_dhs_priv,
        bob_dhs_pub,
        hk_ab,
        hk_ba,
        ad.clone(),
    );
    let mut bob =
        DoubleRatchet::init_responder(root, bob_dhs_priv, bob_dhs_pub, hk_ab, hk_ba, ad.clone());

    // Alice's sending-chain cursor, advanced with the real `kdf_ck` — byte-identical to what
    // `encrypt` consumes internally, without needing getters into `DoubleRatchet`'s private state.
    let mut alice_send = ChainCursor { ck: alice_cks0 };

    let mut transcript = Vec::new();

    // Step 0: Alice -> Bob, N=0. Establishes Bob's receiving chain (his first DH-ratchet step).
    let (ck_before, ck_after, mk) = alice_send.advance();
    let pt0 = b"hello bob".to_vec();
    let c0 = alice.encrypt(&pt0).map_err(|e| e.to_string())?;
    bob.decrypt(&c0).map_err(|e| e.to_string())?;
    transcript.push(Step {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt0),
        n: 0,
        dh_ratchet_step: true,
        delivered_out_of_order: false,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck_before)),
        ck_after_hex: Some(hex::encode(ck_after)),
        mk_hex: Some(hex::encode(mk)),
    });

    // Steps N=1,2,3 on Alice's same chain, delivered out of order (3, 1, 2) to exercise the
    // skipped-message-key path. Still deterministic: Bob hasn't replied yet, so neither side has
    // done a further (random) DH-ratchet step.
    let mut steps = Vec::new();
    for pt in [b"m1".to_vec(), b"m2".to_vec(), b"m3".to_vec()] {
        let (ck_before, ck_after, mk) = alice_send.advance();
        let ct = alice.encrypt(&pt).map_err(|e| e.to_string())?;
        steps.push((pt, ck_before, ck_after, mk, ct));
    }
    let (pt1, ck1b, ck1a, mk1, ct1) = steps.remove(0);
    let (pt2, ck2b, ck2a, mk2, ct2) = steps.remove(0);
    let (pt3, ck3b, ck3a, mk3, ct3) = steps.remove(0);

    bob.decrypt(&ct3).map_err(|e| e.to_string())?; // delivered first: N=3, out of order
    transcript.push(Step {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt3),
        n: 3,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck3b)),
        ck_after_hex: Some(hex::encode(ck3a)),
        mk_hex: Some(hex::encode(mk3)),
    });
    bob.decrypt(&ct1).map_err(|e| e.to_string())?; // N=1, arrives after N=3 (skipped-key path)
    transcript.push(Step {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt1),
        n: 1,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck1b)),
        ck_after_hex: Some(hex::encode(ck1a)),
        mk_hex: Some(hex::encode(mk1)),
    });
    bob.decrypt(&ct2).map_err(|e| e.to_string())?; // N=2, also a stored skipped key
    transcript.push(Step {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt2),
        n: 2,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck2b)),
        ck_after_hex: Some(hex::encode(ck2a)),
        mk_hex: Some(hex::encode(mk2)),
    });

    // Step 4: Bob -> Alice, his first send. This rides a chain seeded by the keypair Bob's own
    // `dh_ratchet` generated internally while processing Alice's opening message (step 0) — an
    // OS-CSPRNG draw with no injection point, and *is* the PCS mechanism, so it is not something
    // to pin. Recorded as a functional round trip only.
    let pt4 = b"hi alice".to_vec();
    let c4 = bob.encrypt(&pt4).map_err(|e| e.to_string())?;
    let decrypted4 = alice.decrypt(&c4).map_err(|e| e.to_string())?;
    if decrypted4 != pt4 {
        return Err("ratchet vector generation: bob->alice reply did not round-trip".into());
    }
    transcript.push(Step {
        direction: "bob->alice".into(),
        plaintext_hex: hex::encode(&pt4),
        n: 0,
        dh_ratchet_step: true,
        delivered_out_of_order: false,
        chain_key_pinned: false,
        ck_before_hex: None,
        ck_after_hex: None,
        mk_hex: None,
    });

    let fixtures = Fixtures {
        version: 1,
        note: "Double Ratchet (header-encrypted) conformance vectors. Regenerate with \
               `cargo run -p xtask -- vectors`. Chain-key/message-key values (where \
               `chain_key_pinned` is true) come from meridian-crypto's real `dh`/`kdf_rk`/`kdf_ck` \
               (via `test_support`), fed the exact keys both `DoubleRatchet` instances in this \
               fixture are constructed from — not a reimplementation. Steps with \
               `chain_key_pinned: false` ride a chain seeded by a keypair the receiving side's \
               `dh_ratchet` generated internally via the OS CSPRNG (the PCS mechanism) and so \
               cannot be byte-pinned; only their plaintext round-trip is asserted. Header \
               ciphertext is NEVER byte-pinned (random nonce by design) — only a functional \
               round-trip is recorded (see `header_round_trip`); do not 'fix' either determinism \
               boundary into a byte pin. Construction: docs/architecture/system-design.md §4.3, \
               apps/crypto/src/ratchet.rs."
            .into(),
        initial_state: InitialState {
            root_hex: hex::encode(root),
            hk_ab_hex: hex::encode(hk_ab),
            hk_ba_hex: hex::encode(hk_ba),
            ad_hex: hex::encode(&ad),
            alice_dhs_priv_hex: hex::encode(alice_dhs_priv),
            alice_dhs_pub_hex: hex::encode(alice_dhs_pub),
            bob_dhs_priv_hex: hex::encode(bob_dhs_priv),
            bob_dhs_pub_hex: hex::encode(bob_dhs_pub),
            alice_initial_root_hex: hex::encode(alice_root0),
            alice_initial_cks_hex: hex::encode(alice_cks0),
            alice_initial_nhks_hex: hex::encode(alice_nhks0),
        },
        transcript,
        header_round_trip: HeaderRoundTrip {
            note: "header_seal draws a random nonce, so ciphertext is never pinned. A conforming \
                   implementation must satisfy: header_open(hk, header_seal(hk, header)) == \
                   Some(header) for these fixed inputs."
                .into(),
            hk_hex: hex::encode(hk_ab),
            header_plaintext_hex: hex::encode(encode_header_for_vector(&bob_dhs_pub, 0, 0)),
        },
    };

    super::write_json(&super::vector_path("ratchet-v1.json"), &fixtures)
}

/// Mirrors `ratchet::encode_header` (private to `meridian_crypto`): `dh_pub(32) ‖ PN:u32-be ‖
/// N:u32-be`. Reimplemented here only to produce the fixed header-plaintext bytes recorded for
/// the functional round-trip vector (documented wire layout, not a KDF/derivation).
fn encode_header_for_vector(dh_pub: &[u8; 32], pn: u32, n: u32) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0..32].copy_from_slice(dh_pub);
    out[32..36].copy_from_slice(&pn.to_be_bytes());
    out[36..40].copy_from_slice(&n.to_be_bytes());
    out
}
