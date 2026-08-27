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
use meridian_envelope::{preamble_aad_bytes, Prekey};
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

    // (task 6.3, ADR 0016 C2/C3) `encrypt`/`decrypt` now take a preamble argument, folded into the
    // v2 AAD. This generator never carries an X3DH preamble on any step (its ratchets are built
    // directly, not via a fresh X3DH handshake), so every call below consistently uses the empty
    // preamble — this does not change any pinned value: ciphertext is never byte-pinned (see the
    // module doc), `ad_hex` is recorded from the local `ad` variable directly (not read back
    // through the now domain-tag-baked `DoubleRatchet::associated_data()`), and chain/message-key
    // derivation never depended on the AAD in the first place.
    let no_preamble: &[u8] = &[];

    // Step 0: Alice -> Bob, N=0. Establishes Bob's receiving chain (his first DH-ratchet step).
    let (ck_before, ck_after, mk) = alice_send.advance();
    let pt0 = b"hello bob".to_vec();
    let c0 = alice
        .encrypt(&pt0, no_preamble)
        .map_err(|e| e.to_string())?;
    bob.decrypt(&c0, no_preamble).map_err(|e| e.to_string())?;
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
        let ct = alice.encrypt(&pt, no_preamble).map_err(|e| e.to_string())?;
        steps.push((pt, ck_before, ck_after, mk, ct));
    }
    let (pt1, ck1b, ck1a, mk1, ct1) = steps.remove(0);
    let (pt2, ck2b, ck2a, mk2, ct2) = steps.remove(0);
    let (pt3, ck3b, ck3a, mk3, ct3) = steps.remove(0);

    bob.decrypt(&ct3, no_preamble).map_err(|e| e.to_string())?; // delivered first: N=3, out of order
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
    bob.decrypt(&ct1, no_preamble).map_err(|e| e.to_string())?; // N=1, arrives after N=3 (skipped-key path)
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
    bob.decrypt(&ct2, no_preamble).map_err(|e| e.to_string())?; // N=2, also a stored skipped key
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
    let c4 = bob.encrypt(&pt4, no_preamble).map_err(|e| e.to_string())?;
    let decrypted4 = alice.decrypt(&c4, no_preamble).map_err(|e| e.to_string())?;
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

// == v2 (task 6.5, ADR 0016 C2/C3): `ratchet-v2.json` =========================================
//
// Same transcript shape as v1, plus the v2 AAD construction (`"mrd.env/2" ‖ AD ‖ prekey_preamble
// ‖ enc_header`, ADR 0016 C3): every step now threads a real (possibly non-empty) preamble
// through `encrypt`/`decrypt`, and the fixture pins two new, fully-deterministic quantities that
// are byte-pinnable *unlike* the message ciphertext/header (see the v1 module doc's determinism
// boundary — that boundary is unchanged in v2, since it comes from `dh_ratchet`'s CSPRNG draw and
// `header_seal`'s random nonce, neither of which this task touches):
//   - `initial_state.baked_ad_hex` — the fixed AAD component both sides bake in at construction,
//     `"mrd.env/2" ‖ AD`, read back via the real, public `DoubleRatchet::associated_data()` getter
//     (never reimplemented/guessed here).
//   - `transcript[].aad_prefix_hex` — `baked_ad ‖ preamble` for that step. This is deterministic
//     for every step regardless of `chain_key_pinned`, because it depends on neither the random
//     DH-ratchet keypair draw nor the header's random nonce — only on the fixed baked AAD and the
//     (locally chosen, hence known) preamble bytes for that message. It stops short of the full
//     per-message AAD (`aad_prefix ‖ enc_header`) only because `enc_header` itself is
//     non-deterministic (random nonce), same reason ciphertext is never pinned.
// New separate structs (`Step2`/`InitialState2`/`Fixtures2`/`HeaderRoundTrip2`) so the v1
// generator's structs, and therefore `ratchet-v1.json`'s exact shape, are untouched.

#[derive(Serialize)]
struct FixturesV2 {
    version: u32,
    note: String,
    initial_state: InitialStateV2,
    transcript: Vec<StepV2>,
    header_round_trip: HeaderRoundTripV2,
}

#[derive(Serialize)]
struct InitialStateV2 {
    root_hex: String,
    hk_ab_hex: String,
    hk_ba_hex: String,
    ad_hex: String,
    /// `"mrd.env/2" ‖ ad_hex` — the fixed per-session AAD component both `DoubleRatchet` instances
    /// bake in at construction (ADR 0016 C3), read back via the real
    /// [`meridian_crypto::DoubleRatchet::associated_data`].
    baked_ad_hex: String,
    alice_dhs_priv_hex: String,
    alice_dhs_pub_hex: String,
    bob_dhs_priv_hex: String,
    bob_dhs_pub_hex: String,
    alice_initial_root_hex: String,
    alice_initial_cks_hex: String,
    alice_initial_nhks_hex: String,
}

#[derive(Serialize)]
struct StepV2 {
    direction: String,
    plaintext_hex: String,
    n: u32,
    dh_ratchet_step: bool,
    delivered_out_of_order: bool,
    chain_key_pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ck_before_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ck_after_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mk_hex: Option<String>,
    /// The [`meridian_envelope::preamble_aad_bytes`]-shaped preamble bytes threaded through
    /// `encrypt`/`decrypt` for this step (empty on every step but the session-opening one, which
    /// carries a stand-in X3DH preamble — see the module doc above).
    preamble_hex: String,
    /// `baked_ad ‖ preamble_hex` for this step (see the module doc above) — deterministic and
    /// pinned for every step, independent of `chain_key_pinned`.
    aad_prefix_hex: String,
}

#[derive(Serialize)]
struct HeaderRoundTripV2 {
    note: String,
    hk_hex: String,
    header_plaintext_hex: String,
}

/// `test-vectors/ratchet-v2.json`. See the module doc above for what's new relative to v1.
pub fn generate_ratchet_v2() -> Result<(), String> {
    let root = [0xAAu8; 32];
    let hk_ab = [0xBBu8; 32];
    let hk_ba = [0xCCu8; 32];
    let ad: Vec<u8> = (0u8..16).collect();

    let alice_dhs_priv = [0xEEu8; 32];
    let alice_dhs_pub = x25519_pub(&alice_dhs_priv);
    let bob_dhs_priv = [0xDDu8; 32];
    let bob_dhs_pub = x25519_pub(&bob_dhs_priv);

    let alice_dh0 = dh(&alice_dhs_priv, &bob_dhs_pub);
    let (alice_root0, alice_cks0, alice_nhks0) = kdf_rk(&root, &alice_dh0);

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

    // Real code, via the public getter — never reimplemented. Both sides must agree.
    let baked_ad = alice.associated_data().to_vec();
    if baked_ad != bob.associated_data() {
        return Err("ratchet v2 vector generation: alice/bob baked AAD diverged".into());
    }

    let aad_prefix = |preamble: &[u8]| -> Vec<u8> {
        let mut out = baked_ad.clone();
        out.extend_from_slice(preamble);
        out
    };

    let mut alice_send = ChainCursor { ck: alice_cks0 };
    let mut transcript = Vec::new();

    // Step 0: Alice -> Bob, N=0, the session-opening message. Carries a real, non-empty
    // preamble, built via the actual `meridian_envelope::preamble_aad_bytes` encoder (xtask can
    // and does depend on `meridian-envelope` — see envelope.rs's own generator in this same
    // directory) rather than hand-reproduced bytes, so the fixture can never silently diverge from
    // production's presence-flag encoding. `meridian-crypto` itself still cannot take this
    // dependency (F15) — its own copy in `apps/crypto/src/session.rs::preamble_bytes` stays a
    // byte-identical hand-kept twin, pinned in lockstep by this same vector.
    let preamble0: Vec<u8> = preamble_aad_bytes(&Some(Prekey {
        ek_pub: [0x55u8; 32],
        used_spk: [0x66u8; 32],
        used_opk: None,
    }));
    let (ck_before, ck_after, mk) = alice_send.advance();
    let pt0 = b"hello bob".to_vec();
    let c0 = alice.encrypt(&pt0, &preamble0).map_err(|e| e.to_string())?;
    bob.decrypt(&c0, &preamble0).map_err(|e| e.to_string())?;
    transcript.push(StepV2 {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt0),
        n: 0,
        dh_ratchet_step: true,
        delivered_out_of_order: false,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck_before)),
        ck_after_hex: Some(hex::encode(ck_after)),
        mk_hex: Some(hex::encode(mk)),
        preamble_hex: hex::encode(&preamble0),
        aad_prefix_hex: hex::encode(aad_prefix(&preamble0)),
    });

    // Steps N=1,2,3 on Alice's same chain, delivered out of order (3, 1, 2). No further preamble
    // (continuation messages on an already-open session carry none).
    let no_preamble: &[u8] = &[];
    let mut steps = Vec::new();
    for pt in [b"m1".to_vec(), b"m2".to_vec(), b"m3".to_vec()] {
        let (ck_before, ck_after, mk) = alice_send.advance();
        let ct = alice.encrypt(&pt, no_preamble).map_err(|e| e.to_string())?;
        steps.push((pt, ck_before, ck_after, mk, ct));
    }
    let (pt1, ck1b, ck1a, mk1, ct1) = steps.remove(0);
    let (pt2, ck2b, ck2a, mk2, ct2) = steps.remove(0);
    let (pt3, ck3b, ck3a, mk3, ct3) = steps.remove(0);

    bob.decrypt(&ct3, no_preamble).map_err(|e| e.to_string())?;
    transcript.push(StepV2 {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt3),
        n: 3,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck3b)),
        ck_after_hex: Some(hex::encode(ck3a)),
        mk_hex: Some(hex::encode(mk3)),
        preamble_hex: hex::encode(no_preamble),
        aad_prefix_hex: hex::encode(aad_prefix(no_preamble)),
    });
    bob.decrypt(&ct1, no_preamble).map_err(|e| e.to_string())?;
    transcript.push(StepV2 {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt1),
        n: 1,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck1b)),
        ck_after_hex: Some(hex::encode(ck1a)),
        mk_hex: Some(hex::encode(mk1)),
        preamble_hex: hex::encode(no_preamble),
        aad_prefix_hex: hex::encode(aad_prefix(no_preamble)),
    });
    bob.decrypt(&ct2, no_preamble).map_err(|e| e.to_string())?;
    transcript.push(StepV2 {
        direction: "alice->bob".into(),
        plaintext_hex: hex::encode(&pt2),
        n: 2,
        dh_ratchet_step: false,
        delivered_out_of_order: true,
        chain_key_pinned: true,
        ck_before_hex: Some(hex::encode(ck2b)),
        ck_after_hex: Some(hex::encode(ck2a)),
        mk_hex: Some(hex::encode(mk2)),
        preamble_hex: hex::encode(no_preamble),
        aad_prefix_hex: hex::encode(aad_prefix(no_preamble)),
    });

    // Step 4: Bob -> Alice, his first send — rides a chain seeded by a keypair Bob's own
    // `dh_ratchet` generated internally via the OS CSPRNG (the PCS mechanism), so `ck`/`mk` are
    // not pinned (see the v1 module doc's determinism boundary), but `aad_prefix_hex` still is.
    let pt4 = b"hi alice".to_vec();
    let c4 = bob.encrypt(&pt4, no_preamble).map_err(|e| e.to_string())?;
    let decrypted4 = alice.decrypt(&c4, no_preamble).map_err(|e| e.to_string())?;
    if decrypted4 != pt4 {
        return Err("ratchet v2 vector generation: bob->alice reply did not round-trip".into());
    }
    transcript.push(StepV2 {
        direction: "bob->alice".into(),
        plaintext_hex: hex::encode(&pt4),
        n: 0,
        dh_ratchet_step: true,
        delivered_out_of_order: false,
        chain_key_pinned: false,
        ck_before_hex: None,
        ck_after_hex: None,
        mk_hex: None,
        preamble_hex: hex::encode(no_preamble),
        aad_prefix_hex: hex::encode(aad_prefix(no_preamble)),
    });

    let fixtures = FixturesV2 {
        version: 2,
        note: "Double Ratchet (header-encrypted) conformance vectors, v2 (ADR 0016 C2/C3). \
               Regenerate with `cargo run -p xtask -- vectors`. Adds the v2 AAD construction \
               (\"mrd.env/2\" || AD || prekey_preamble || enc_header) on top of the v1 fixture \
               shape: `initial_state.baked_ad_hex` is the fixed \"mrd.env/2\" || AD component both \
               sides bake in at construction (real `DoubleRatchet::associated_data()`); each \
               transcript step's `preamble_hex`/`aad_prefix_hex` record the per-message preamble \
               and `baked_ad || preamble` — deterministic and pinned on every step regardless of \
               `chain_key_pinned`, since neither depends on the DH-ratchet's random keypair draw or \
               the header's random nonce. Chain-key/message-key values, header ciphertext, and the \
               full per-message AAD (which additionally includes the non-deterministic \
               `enc_header`) follow the exact same determinism boundary as v1 — see that fixture's \
               `note` field. Construction: docs/adr/0016-envelope-deniability.md, \
               apps/crypto/src/ratchet.rs."
            .into(),
        initial_state: InitialStateV2 {
            root_hex: hex::encode(root),
            hk_ab_hex: hex::encode(hk_ab),
            hk_ba_hex: hex::encode(hk_ba),
            ad_hex: hex::encode(&ad),
            baked_ad_hex: hex::encode(&baked_ad),
            alice_dhs_priv_hex: hex::encode(alice_dhs_priv),
            alice_dhs_pub_hex: hex::encode(alice_dhs_pub),
            bob_dhs_priv_hex: hex::encode(bob_dhs_priv),
            bob_dhs_pub_hex: hex::encode(bob_dhs_pub),
            alice_initial_root_hex: hex::encode(alice_root0),
            alice_initial_cks_hex: hex::encode(alice_cks0),
            alice_initial_nhks_hex: hex::encode(alice_nhks0),
        },
        transcript,
        header_round_trip: HeaderRoundTripV2 {
            note: "header_seal draws a random nonce, so ciphertext is never pinned. A conforming \
                   implementation must satisfy: header_open(hk, header_seal(hk, header)) == \
                   Some(header) for these fixed inputs."
                .into(),
            hk_hex: hex::encode(hk_ab),
            header_plaintext_hex: hex::encode(encode_header_for_vector(&bob_dhs_pub, 0, 0)),
        },
    };

    super::write_json(&super::vector_path("ratchet-v2.json"), &fixtures)
}
