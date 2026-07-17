//! Conformance-vector gate (task 1.6, review finding F1): re-derive every committed
//! `test-vectors/{x3dh,ratchet,envelope,safety-numbers}-v1.json` fixture via `meridian-crypto`'s
//! *real* code path and assert byte-for-byte equality against the committed values. This is what
//! actually gates CI — not just "the generator ran" — so a spec-divergent KDF label or wire-layout
//! change fails here instead of surfacing as a silent cross-implementation interop break.
//!
//! The deliberately-divergent-KDF-label negative test lives inside the crate itself
//! (`src/x3dh.rs`'s `#[cfg(test)]` module), because it needs `pub(crate)` access to `X3DH_INFO`/
//! the internal `hkdf` helper that this external `tests/` file cannot see.

use std::path::PathBuf;

use meridian_crypto::test_support::{dh, header_open, header_seal, kdf_ck, kdf_rk};
use meridian_crypto::{display_groups, safety_number, x3dh, DoubleRatchet};
use meridian_proto::{MessageEnvelope, Prekey};
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

        match direction {
            "alice->bob" => {
                let ct = alice.encrypt(&plaintext).unwrap();
                let pt = bob.decrypt(&ct).unwrap();
                assert_eq!(pt, plaintext);
            }
            "bob->alice" => {
                let ct = bob.encrypt(&plaintext).unwrap();
                let pt = alice.decrypt(&ct).unwrap();
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

#[test]
fn envelope_vectors_match_real_encoding() {
    let fixtures = load("envelope-v1.json");
    for vec in fixtures["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let sender_pub = b32(vec, "sender_pub_hex");
        let ct = bvec(vec, "ct_hex");
        let sig_bytes = bvec(vec, "sig_hex");
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
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
            sender_pub,
            prekey,
            ct,
            sig,
        };
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
