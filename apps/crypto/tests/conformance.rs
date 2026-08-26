//! Conformance-vector gate (task 1.6, review finding F1): re-derive every committed
//! `test-vectors/{x3dh,ratchet,envelope,safety-numbers}-v1.json` fixture via `meridian-crypto`'s
//! *real* code path and assert byte-for-byte equality against the committed values. This is what
//! actually gates CI — not just "the generator ran" — so a spec-divergent KDF label or wire-layout
//! change fails here instead of surfacing as a silent cross-implementation interop break.
//!
//! The deliberately-divergent-KDF-label negative test lives inside the crate itself
//! (`src/x3dh.rs`'s `#[cfg(test)]` module), because it needs `pub(crate)` access to `X3DH_INFO`/
//! the internal `hkdf` helper that this external `tests/` file cannot see.
//!
//! **Task 6.5 (ADR 0016 C2/C3/C5):** adds the v2 siblings, `test-vectors/{ratchet,envelope}-v2.json`
//! — see [`ratchet_v2_vectors_match_real_derivation`] and [`envelope_vectors_match_real_encoding`]
//! below, plus [`ratchet_v2_aad_harness_catches_domain_tag_and_preamble_drift`], the harness-integrity
//! check analogous to `x3dh.rs`'s `divergent_kdf_label_does_not_match_committed_vector`. Unlike the
//! X3DH case, the v2 AAD construction (`bake_ad`/`message_aad`/`AAD_DOMAIN`) is crate-private and not
//! exposed via `test_support`, so this file never reimplements it: every "correct" value below comes
//! from the real, public [`meridian_crypto::DoubleRatchet::associated_data`] getter (or from
//! `encrypt`/`decrypt` themselves), and only the deliberately-*wrong* comparison values are built by
//! hand from raw bytes, exactly the way `x3dh.rs`'s negative test mutates a real label byte rather
//! than reimplementing `derive()`.

use std::path::PathBuf;

use meridian_crypto::test_support::{dh, header_open, header_seal, kdf_ck, kdf_rk};
use meridian_crypto::{display_groups, safety_number, x3dh, DoubleRatchet};
use meridian_envelope::{MessageEnvelope, Prekey};
use meridian_store::{MemorySecretStore, SecretStore};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("meridian-crypto lives at <root>/apps/crypto")
        .join("test-vectors")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn b32(v: &Value, field: &str) -> [u8; 32] {
    let hexstr = v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"));
    let bytes = hex::decode(hexstr).unwrap_or_else(|e| panic!("{field}: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{field}: expected 32 bytes, got {}", b.len()))
}

fn bvec(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}")),
    )
    .unwrap()
}

fn b16(v: &Value, field: &str) -> [u8; 16] {
    let hexstr = v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"));
    let bytes = hex::decode(hexstr).unwrap_or_else(|e| panic!("{field}: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{field}: expected 16 bytes, got {}", b.len()))
}

#[test]
fn x3dh_vectors_match_real_derivation() {
    let fixtures = load("x3dh-v1.json");
    for vec in fixtures["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let inputs = &vec["inputs"];
        let responder_ik_seed = b32(inputs, "responder_ik_seed_hex");
        let responder_ik_pub = b32(inputs, "responder_ik_pub_hex");
        let initiator_ik_pub = b32(inputs, "initiator_ik_pub_hex");
        let spk_secret = b32(inputs, "spk_secret_hex");
        let opk_secret = inputs
            .get("opk_secret_hex")
            .and_then(Value::as_str)
            .map(|h| {
                let b = hex::decode(h).unwrap();
                let a: [u8; 32] = b.try_into().unwrap();
                a
            });
        let ek_a_pub = b32(inputs, "ek_a_pub_hex");

        let store = MemorySecretStore::new();
        let handle = store.store("responder-ik", &responder_ik_seed).unwrap();

        let result = x3dh::respond(
            &store,
            &handle,
            &responder_ik_pub,
            &initiator_ik_pub,
            &ek_a_pub,
            &spk_secret,
            opk_secret,
        )
        .unwrap_or_else(|e| panic!("x3dh vector '{name}': respond failed: {e}"));

        assert_eq!(
            hex::encode(result.root),
            vec["derived"]["root_hex"],
            "{name}: root"
        );
        assert_eq!(
            hex::encode(result.hka),
            vec["derived"]["hka_hex"],
            "{name}: hka"
        );
        assert_eq!(
            hex::encode(result.nhkb),
            vec["derived"]["nhkb_hex"],
            "{name}: nhkb"
        );
        assert_eq!(
            hex::encode(&result.ad),
            vec["derived"]["ad_hex"],
            "{name}: ad"
        );

        // Cross-check the recorded DH legs too (real `test_support::dh`/`ed25519_pub_to_x25519`).
        let peer_ik_x =
            meridian_crypto::test_support::ed25519_pub_to_x25519(&initiator_ik_pub).unwrap();
        let dh1 = dh(&spk_secret, &peer_ik_x);
        let dh2 = store
            .use_key(&handle, meridian_store::SignOrDh::Dh, &ek_a_pub)
            .unwrap();
        let dh3 = dh(&spk_secret, &ek_a_pub);
        assert_eq!(
            hex::encode(dh1.as_slice()),
            vec["dh_legs"]["dh1_hex"],
            "{name}: dh1"
        );
        assert_eq!(hex::encode(&dh2), vec["dh_legs"]["dh2_hex"], "{name}: dh2");
        assert_eq!(
            hex::encode(dh3.as_slice()),
            vec["dh_legs"]["dh3_hex"],
            "{name}: dh3"
        );
        if let Some(opk) = opk_secret {
            let dh4 = dh(&opk, &ek_a_pub);
            assert_eq!(
                hex::encode(dh4.as_slice()),
                vec["dh_legs"]["dh4_hex"],
                "{name}: dh4"
            );
        }
    }
}

#[test]
fn ratchet_vectors_match_real_derivation() {
    let fixtures = load("ratchet-v1.json");
    let init = &fixtures["initial_state"];
    let root = b32(init, "root_hex");
    let hk_ab = b32(init, "hk_ab_hex");
    let hk_ba = b32(init, "hk_ba_hex");
    let ad = bvec(init, "ad_hex");
    let alice_dhs_priv = b32(init, "alice_dhs_priv_hex");
    let bob_dhs_priv = b32(init, "bob_dhs_priv_hex");
    let bob_dhs_pub = b32(init, "bob_dhs_pub_hex");

    // Real DH + KDF_RK, independently recomputed from the committed inputs.
    let alice_dh0 = dh(&alice_dhs_priv, &bob_dhs_pub);
    let (alice_root0, alice_cks0, alice_nhks0) = kdf_rk(&root, &alice_dh0);
    assert_eq!(hex::encode(alice_root0), init["alice_initial_root_hex"]);
    assert_eq!(hex::encode(alice_cks0), init["alice_initial_cks_hex"]);
    assert_eq!(hex::encode(alice_nhks0), init["alice_initial_nhks_hex"]);

    let mut alice = DoubleRatchet::init_initiator_with_keypair(
        root,
        alice_dhs_priv,
        bob_dhs_pub,
        hk_ab,
        hk_ba,
        ad.clone(),
    );
    let mut bob = DoubleRatchet::init_responder(root, bob_dhs_priv, bob_dhs_pub, hk_ab, hk_ba, ad);

    // Steps are recorded in *delivery* order (some deliberately out of order), not chain
    // (`N`) order, so each pinned step is checked against its own committed `ck_before` rather
    // than a single running cursor. Chain continuity (ck_after[N] == ck_before[N+1]) is checked
    // separately below, sorted by `N`, within the one sending chain these vectors exercise.
    let mut pinned_by_n: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();

    for step in fixtures["transcript"].as_array().unwrap() {
        let plaintext = bvec(step, "plaintext_hex");
        let direction = step["direction"].as_str().unwrap();

        if step["chain_key_pinned"].as_bool().unwrap() {
            let ck_before = b32(step, "ck_before_hex");
            let (next, mk) = kdf_ck(&ck_before);
            assert_eq!(
                hex::encode(next),
                step["ck_after_hex"],
                "ck_after N={}",
                step["n"]
            );
            assert_eq!(hex::encode(mk), step["mk_hex"], "mk N={}", step["n"]);
            pinned_by_n.push((step["n"].as_u64().unwrap(), ck_before, next));
        }

        // (task 6.3, ADR 0016 C2/C3) `encrypt`/`decrypt` now take a preamble argument, folded into
        // the v2 AAD alongside the domain tag baked into `ad` at construction. This transcript
        // never carries an X3DH preamble on any step (it starts from an already-established
        // `init_initiator_with_keypair`/`init_responder` pair, not a fresh X3DH handshake), so both
        // sides consistently use the empty preamble here — this is a self-consistent round-trip
        // check (chain-key continuity + plaintext recovery), never a byte-pinned ciphertext check
        // (see the note below), so it needs no v2 vector regeneration (task 6.5) to stay meaningful.
        let preamble: &[u8] = &[];
        match direction {
            "alice->bob" => {
                let ct = alice.encrypt(&plaintext, preamble).unwrap();
                let pt = bob.decrypt(&ct, preamble).unwrap();
                assert_eq!(pt, plaintext);
            }
            "bob->alice" => {
                let ct = bob.encrypt(&plaintext, preamble).unwrap();
                let pt = alice.decrypt(&ct, preamble).unwrap();
                assert_eq!(pt, plaintext);
            }
            other => panic!("unknown direction {other}"),
        }
    }

    // Chain continuity: the one sending chain these vectors exercise (Alice's, N=0..3) must
    // advance monotonically regardless of delivery order — ck_after[N] == ck_before[N+1] — and
    // must start from the real `init_initiator_with_keypair`-derived `alice_cks0`.
    pinned_by_n.sort_by_key(|(n, _, _)| *n);
    assert_eq!(
        pinned_by_n.first().unwrap().1,
        alice_cks0,
        "chain must start at alice_cks0"
    );
    for pair in pinned_by_n.windows(2) {
        let (_, _, after) = pair[0];
        let (_, before, _) = pair[1];
        assert_eq!(
            after, before,
            "chain-key continuity broken between N={} and N={}",
            pair[0].0, pair[1].0
        );
    }

    // Note: the transcript above re-encrypts fresh ciphertext each run (headers carry random
    // nonces, so committed ciphertext is never pinned — see the vector's own note); only the
    // pinned chain-key/message-key values and functional round trips are checked against the
    // committed fixture.

    let hk = b32(&fixtures["header_round_trip"], "hk_hex");
    let header = bvec(&fixtures["header_round_trip"], "header_plaintext_hex");
    let enc = header_seal(&hk, &header).unwrap();
    assert_eq!(
        header_open(&hk, &enc),
        Some(header),
        "header_seal/header_open round trip"
    );
}

/// (task 6.5, ADR 0016 C2/C3) `ratchet-v2.json`'s sibling of the v1 test above: same transcript
/// shape, plus the two new deterministic quantities the v2 AAD construction adds —
/// `initial_state.baked_ad_hex` (`"mrd.env/2" ‖ AD`, read back via the real, public
/// [`DoubleRatchet::associated_data`]) and each step's `aad_prefix_hex` (`baked_ad ‖ preamble`,
/// which — unlike the message ciphertext/full AAD — is independent of both the DH-ratchet's
/// random keypair draw and the header's random nonce, so it is pinned on every step regardless of
/// `chain_key_pinned`; see the vector's own `note` field).
#[test]
fn ratchet_v2_vectors_match_real_derivation() {
    let fixtures = load("ratchet-v2.json");
    let init = &fixtures["initial_state"];
    let root = b32(init, "root_hex");
    let hk_ab = b32(init, "hk_ab_hex");
    let hk_ba = b32(init, "hk_ba_hex");
    let ad = bvec(init, "ad_hex");
    let alice_dhs_priv = b32(init, "alice_dhs_priv_hex");
    let bob_dhs_priv = b32(init, "bob_dhs_priv_hex");
    let bob_dhs_pub = b32(init, "bob_dhs_pub_hex");

    let alice_dh0 = dh(&alice_dhs_priv, &bob_dhs_pub);
    let (alice_root0, alice_cks0, alice_nhks0) = kdf_rk(&root, &alice_dh0);
    assert_eq!(hex::encode(alice_root0), init["alice_initial_root_hex"]);
    assert_eq!(hex::encode(alice_cks0), init["alice_initial_cks_hex"]);
    assert_eq!(hex::encode(alice_nhks0), init["alice_initial_nhks_hex"]);

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

    // The fixed AAD component (ADR 0016 C3) both sides bake in at construction, read back via the
    // real public getter — never reimplemented — and checked against the committed vector.
    let baked_ad_hex = hex::encode(alice.associated_data());
    assert_eq!(
        baked_ad_hex, init["baked_ad_hex"],
        "baked ad (\"mrd.env/2\" || AD) must match the committed vector"
    );
    assert_eq!(
        hex::encode(bob.associated_data()),
        init["baked_ad_hex"],
        "both sides must bake an identical fixed AAD"
    );

    let mut pinned_by_n: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();

    for step in fixtures["transcript"].as_array().unwrap() {
        let plaintext = bvec(step, "plaintext_hex");
        let direction = step["direction"].as_str().unwrap();
        let preamble = bvec(step, "preamble_hex");

        // `aad_prefix_hex` (`baked_ad || preamble`) is deterministic on every step — verify it
        // against the real `associated_data()` output plus this step's own preamble bytes.
        let mut expected_aad_prefix = alice.associated_data().to_vec();
        expected_aad_prefix.extend_from_slice(&preamble);
        assert_eq!(
            hex::encode(&expected_aad_prefix),
            step["aad_prefix_hex"],
            "aad_prefix (baked_ad || preamble) mismatch at n={}",
            step["n"]
        );

        if step["chain_key_pinned"].as_bool().unwrap() {
            let ck_before = b32(step, "ck_before_hex");
            let (next, mk) = kdf_ck(&ck_before);
            assert_eq!(
                hex::encode(next),
                step["ck_after_hex"],
                "ck_after N={}",
                step["n"]
            );
            assert_eq!(hex::encode(mk), step["mk_hex"], "mk N={}", step["n"]);
            pinned_by_n.push((step["n"].as_u64().unwrap(), ck_before, next));
        }

        match direction {
            "alice->bob" => {
                let ct = alice.encrypt(&plaintext, &preamble).unwrap();
                let pt = bob.decrypt(&ct, &preamble).unwrap();
                assert_eq!(pt, plaintext);
            }
            "bob->alice" => {
                let ct = bob.encrypt(&plaintext, &preamble).unwrap();
                let pt = alice.decrypt(&ct, &preamble).unwrap();
                assert_eq!(pt, plaintext);
            }
            other => panic!("unknown direction {other}"),
        }
    }

    pinned_by_n.sort_by_key(|(n, _, _)| *n);
    assert_eq!(
        pinned_by_n.first().unwrap().1,
        alice_cks0,
        "chain must start at alice_cks0"
    );
    for pair in pinned_by_n.windows(2) {
        let (_, _, after) = pair[0];
        let (_, before, _) = pair[1];
        assert_eq!(
            after, before,
            "chain-key continuity broken between N={} and N={}",
            pair[0].0, pair[1].0
        );
    }

    let hk = b32(&fixtures["header_round_trip"], "hk_hex");
    let header = bvec(&fixtures["header_round_trip"], "header_plaintext_hex");
    let enc = header_seal(&hk, &header).unwrap();
    assert_eq!(
        header_open(&hk, &enc),
        Some(header),
        "header_seal/header_open round trip"
    );
}

/// Harness-integrity check for the v2 AAD construction (task 6.5), analogous to
/// `x3dh.rs::divergent_kdf_label_does_not_match_committed_vector`: proves the conformance harness
/// actually catches drift in the domain-tag/preamble-in-AAD construction, rather than being a
/// vacuous "any bytes would pass" fixture. Every *correct* value below comes from the real, public
/// `DoubleRatchet::associated_data()` getter; the *wrong* values are hand-built, standing in for
/// two concrete regressions ADR 0016 C3 calls out by name:
/// - dropping the `"mrd.env/2"` domain tag from the fixed AAD (the exact shape v1's AAD had — v1
///   never carried a domain tag at all, so "the old v1 construction" *is* "no domain tag" here);
/// - omitting the preamble from the AAD, or substituting a locally-recomputed preamble for the one
///   actually received (the specific regression `DoubleRatchet::decrypt`'s own doc comment warns
///   against — see `apps/crypto/src/ratchet.rs`).
#[test]
fn ratchet_v2_aad_harness_catches_domain_tag_and_preamble_drift() {
    let fixtures = load("ratchet-v2.json");
    let init = &fixtures["initial_state"];
    let root = b32(init, "root_hex");
    let hk_ab = b32(init, "hk_ab_hex");
    let hk_ba = b32(init, "hk_ba_hex");
    let ad = bvec(init, "ad_hex");
    let bob_dhs_priv = b32(init, "bob_dhs_priv_hex");
    let bob_dhs_pub = b32(init, "bob_dhs_pub_hex");

    let bob =
        DoubleRatchet::init_responder(root, bob_dhs_priv, bob_dhs_pub, hk_ab, hk_ba, ad.clone());

    // Sanity: the real construction matches the committed vector (otherwise this test would prove
    // nothing about the harness's sensitivity).
    let real_baked_ad = bob.associated_data().to_vec();
    assert_eq!(hex::encode(&real_baked_ad), init["baked_ad_hex"]);

    // Regression 1: drop the "mrd.env/2" domain tag — i.e. what the *raw X3DH AD alone* looks
    // like, exactly v1's (tag-less) AAD shape. Must NOT match the committed v2 vector.
    let wrong_baked_ad_no_domain_tag = ad.clone();
    assert_ne!(
        hex::encode(&wrong_baked_ad_no_domain_tag),
        init["baked_ad_hex"],
        "a domain-tag-less (v1-shaped) AD must not reproduce the committed v2 baked_ad vector — \
         if it does, this harness cannot catch a dropped/wrong domain tag"
    );

    // Regression 2/3: the session-opening step (index 0) carries a real, non-empty preamble.
    // Compute the wrong aad_prefix two ways — omitting the preamble entirely, and substituting a
    // different ("locally recomputed") preamble for the one actually sent — and confirm neither
    // reproduces the committed `aad_prefix_hex`.
    let step0 = &fixtures["transcript"][0];
    let sent_preamble = bvec(step0, "preamble_hex");
    assert!(
        !sent_preamble.is_empty(),
        "sanity: step 0 must carry a non-empty preamble for this check to be meaningful"
    );

    let omitted_preamble_aad = real_baked_ad.clone(); // baked_ad alone, no preamble appended
    assert_ne!(
        hex::encode(&omitted_preamble_aad),
        step0["aad_prefix_hex"],
        "omitting the preamble from the AAD must not reproduce the committed vector — if it does, \
         this harness cannot catch a dropped preamble"
    );

    let locally_recomputed_preamble = vec![0xFFu8; sent_preamble.len()];
    assert_ne!(
        sent_preamble, locally_recomputed_preamble,
        "sanity: must actually differ from the genuinely-sent preamble"
    );
    let mut wrong_aad_local_preamble = real_baked_ad.clone();
    wrong_aad_local_preamble.extend_from_slice(&locally_recomputed_preamble);
    assert_ne!(
        hex::encode(&wrong_aad_local_preamble),
        step0["aad_prefix_hex"],
        "a locally-recomputed preamble standing in for the received bytes must not reproduce the \
         committed vector — if it does, this harness cannot catch that class of regression"
    );
}

/// **Pre-6.5 note (kept for history):** `test-vectors/envelope-v1.json` pins the **v1** wire shape
/// (`sender_pub`/`prekey`/`ct`/`sig`), which envelope v2 (task 6.3, ADR 0016 C2/C3/C5)
/// deliberately no longer parses at all — v1/v2 is a hard flag day (R5), not a mixed-version
/// window. `envelope-v1.json` therefore has no live re-derivation consumer any more (it stays
/// committed as a frozen historical record — `generate_envelope` (v1) is a permanent no-op, see
/// `tools/xtask/src/vectors/envelope.rs`); this test now targets the v2 shape and vector
/// (task 6.5), and is un-ignored accordingly.
#[test]
fn envelope_vectors_match_real_encoding() {
    let fixtures = load("envelope-v2.json");
    for vec in fixtures["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let v = vec["v"].as_u64().unwrap() as u16;
        let sender_pub = b32(vec, "sender_pub_hex");
        let eid = b16(vec, "eid_hex");
        let ct = bvec(vec, "ct_hex");
        let prekey = vec["prekey"].as_object().map(|p| Prekey {
            ek_pub: {
                let b = hex::decode(p["ek_pub_hex"].as_str().unwrap()).unwrap();
                b.try_into().unwrap()
            },
            used_spk: {
                let b = hex::decode(p["used_spk_hex"].as_str().unwrap()).unwrap();
                b.try_into().unwrap()
            },
            used_opk: p.get("used_opk_hex").and_then(Value::as_str).map(|h| {
                let b = hex::decode(h).unwrap();
                let a: [u8; 32] = b.try_into().unwrap();
                a
            }),
        });

        let env = MessageEnvelope {
            v,
            sender_pub,
            eid,
            prekey,
            ct,
        };
        assert_eq!(
            v,
            meridian_envelope::ENVELOPE_VERSION,
            "{name}: vector's v must match the crate's current ENVELOPE_VERSION"
        );
        let blob = env.to_blob().unwrap();
        assert_eq!(hex::encode(&blob), vec["blob_hex"], "{name}: to_blob()");

        let decoded = MessageEnvelope::from_blob(&blob).unwrap();
        assert_eq!(decoded, env, "{name}: from_blob(to_blob(_)) round trip");
    }
}

#[test]
fn safety_number_vectors_match_real_computation() {
    let fixtures = load("safety-numbers-v1.json");
    for vec in fixtures["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let a = b32(vec, "a_hex");
        let b = b32(vec, "b_hex");
        let number = safety_number(&a, &b);
        assert_eq!(number, vec["safety_number"], "{name}: safety_number");
        assert_eq!(
            display_groups(&number),
            vec["display"],
            "{name}: display_groups"
        );
    }
    for oi in fixtures["order_independence"].as_array().unwrap() {
        let a = b32(oi, "a_hex");
        let b = b32(oi, "b_hex");
        let same = safety_number(&a, &b) == safety_number(&b, &a);
        assert_eq!(same, oi["same"].as_bool().unwrap());
        assert!(same, "safety_number must be order-independent");
    }
}
