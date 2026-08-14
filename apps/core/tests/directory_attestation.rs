//! Task 4.8 — org directory-attestation ingest: the target named by the task file
//! (`cargo nextest run -p meridian-core --test directory_attestation`).
//!
//! Schema under test: `docs/security/directory-attestation.md` (architect+security-reviewer
//! approved). The single property every test here ultimately serves is the
//! **provenance-not-authority boundary**: a directory attestation is petname *provenance*, never
//! petname *authority* — see [`meridian_core::directory`]'s module doc for how that boundary is
//! enforced structurally (not just by these tests) in the implementation itself.

use meridian_core::directory::{
    DirectoryAttestation, DirectoryAttestationSignable, DirectoryEntry, DirectoryError,
    DIRECTORY_VERSION, MAX_DIRECTORY_ENTRIES, MAX_HR_NAME_LEN, MAX_TOTAL_DIRECTORY_SUGGESTIONS,
};
use meridian_core::trust::{TrustState, TrustStore};
use meridian_identity::{
    generate_account, sign, AccountId, KeyHandle, MemorySecretStore, SecretStore,
};

/// A freshly generated "org" — an ordinary account key used here purely as an Ed25519 signing
/// identity, exactly as an issuing org would hold one.
fn org() -> (MemorySecretStore, AccountId) {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "org-a.test").expect("generate org key");
    (store, account)
}

/// Build a correctly-signed [`DirectoryAttestation`]: signs the CBOR encoding of the
/// [`DirectoryAttestationSignable`] built from every field except `sig`, under `handle` (which
/// need not belong to `org_signing_pub` — tests that want a signed-under-a-different-key artifact
/// pass a `store`/`handle` whose real public key differs from `org_signing_pub`).
fn sign_attestation(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    org_signing_pub: [u8; 32],
    org_domain: &str,
    issued_at: u64,
    entries: Vec<DirectoryEntry>,
) -> DirectoryAttestation {
    let signable = DirectoryAttestationSignable {
        v: DIRECTORY_VERSION,
        org_domain: org_domain.to_string(),
        org_signing_pub,
        issued_at,
        entries: entries.clone(),
    };
    let msg = signable.to_cbor().expect("encode signable");
    let sig = sign(store, handle, &msg).expect("sign");
    DirectoryAttestation {
        v: DIRECTORY_VERSION,
        org_domain: org_domain.to_string(),
        org_signing_pub,
        issued_at,
        entries,
        sig: *sig.as_bytes(),
    }
}

/// A deterministic, distinct `[u8; 32]` account key for index `i` — these never need to be valid
/// Ed25519 points (only `org_signing_pub` does), just distinct map keys.
fn idx_key(i: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k
}

#[test]
fn valid_attestation_records_suggestion_without_touching_trust_state() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(1);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Dana Smith, Finance".to_string(),
        }],
    );

    let mut trust = TrustStore::default();
    let ingested = trust
        .ingest_directory(&artifact, &org_pub)
        .expect("valid, correctly-signed artifact ingests");
    assert_eq!(ingested, 1);

    let suggestions: Vec<_> = trust.directory_suggestions(&account_pub).collect();
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].hr_name, "Dana Smith, Finance");
    assert_eq!(suggestions[0].org_domain, "org-a.test");
    assert_eq!(suggestions[0].org_signing_pub, org_pub);
    assert_eq!(suggestions[0].attested_at, 1_000);

    // The critical assertion: ingest must NEVER touch Contact/TrustState. Not "the suggestion
    // exists" alone -- the contacts map itself must be completely untouched.
    assert!(
        trust.contacts().next().is_none(),
        "ingest_directory must never create a Contact"
    );
    assert!(trust.contact(&account_pub).is_none());
    assert_eq!(trust.trust_state(&account_pub), TrustState::New);
}

#[test]
fn tampered_entry_after_signing_is_rejected() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(2);

    let mut artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Alice".to_string(),
        }],
    );
    // Tamper with an entry's hr_name after the signature was already computed.
    artifact.entries[0].hr_name = "Mallory".to_string();

    let mut trust = TrustStore::default();
    let err = trust
        .ingest_directory(&artifact, &org_pub)
        .expect_err("tampered entry must fail signature verification");
    assert!(matches!(err, DirectoryError::BadSignature));
    assert!(trust.directory_suggestions(&account_pub).next().is_none());
}

#[test]
fn signed_under_a_different_key_than_claimed_is_rejected() {
    let (_org_a_store, org_a) = org();
    let (org_b_store, org_b) = org();
    let org_a_pub = *org_a.public_key().as_bytes();
    let account_pub = idx_key(3);

    // Claims org_a's public key in the artifact, but is actually signed with org_b's private key.
    let artifact = sign_attestation(
        &org_b_store,
        org_b.handle(),
        org_a_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Bob".to_string(),
        }],
    );

    let mut trust = TrustStore::default();
    let err = trust
        .ingest_directory(&artifact, &org_a_pub)
        .expect_err("signature by a different key than claimed must not verify");
    assert!(matches!(err, DirectoryError::BadSignature));
    assert!(trust.directory_suggestions(&account_pub).next().is_none());
}

#[test]
fn org_signing_pub_mismatch_against_caller_expected_is_rejected_even_if_internally_valid() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(4);

    // Perfectly valid, self-consistent artifact (its own claimed key matches what signed it) --
    // but the caller pins a DIFFERENT expected_org_signing_pub (the trust anchor).
    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Carol".to_string(),
        }],
    );
    let wrong_expected = idx_key(999);

    let mut trust = TrustStore::default();
    let err = trust
        .ingest_directory(&artifact, &wrong_expected)
        .expect_err("org_signing_pub must be pinned by the caller, not self-asserted");
    assert!(matches!(err, DirectoryError::OrgKeyMismatch));
    assert!(trust.directory_suggestions(&account_pub).next().is_none());
}

#[test]
fn multi_org_suggestions_for_one_account_dont_collide() {
    let (store_a, org_a) = org();
    let (store_b, org_b) = org();
    let pub_a = *org_a.public_key().as_bytes();
    let pub_b = *org_b.public_key().as_bytes();
    let account_pub = idx_key(5);

    let artifact_a = sign_attestation(
        &store_a,
        org_a.handle(),
        pub_a,
        "org-a.test",
        100,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Dana (Org A)".to_string(),
        }],
    );
    let artifact_b = sign_attestation(
        &store_b,
        org_b.handle(),
        pub_b,
        "org-b.test",
        200,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Dana (Org B)".to_string(),
        }],
    );

    let mut trust = TrustStore::default();
    trust
        .ingest_directory(&artifact_a, &pub_a)
        .expect("org a ingests");
    trust
        .ingest_directory(&artifact_b, &pub_b)
        .expect("org b ingests");

    let suggestions: Vec<_> = trust.directory_suggestions(&account_pub).collect();
    assert_eq!(
        suggestions.len(),
        2,
        "both orgs' suggestions must be retained side by side"
    );
    let names: std::collections::BTreeSet<_> =
        suggestions.iter().map(|s| s.hr_name.clone()).collect();
    assert!(names.contains("Dana (Org A)"));
    assert!(names.contains("Dana (Org B)"));
    let pubs: std::collections::BTreeSet<_> =
        suggestions.iter().map(|s| s.org_signing_pub).collect();
    assert!(pubs.contains(&pub_a));
    assert!(pubs.contains(&pub_b));
}

#[test]
fn same_org_reimport_replaces_only_on_strictly_later_issued_at() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(6);

    let mk = |issued_at: u64, hr_name: &str| {
        sign_attestation(
            &org_store,
            org_account.handle(),
            org_pub,
            "org-a.test",
            issued_at,
            vec![DirectoryEntry {
                account_pub,
                hr_name: hr_name.to_string(),
            }],
        )
    };

    let mut trust = TrustStore::default();

    trust
        .ingest_directory(&mk(100, "Old Name"), &org_pub)
        .unwrap();
    assert_eq!(
        trust
            .directory_suggestions(&account_pub)
            .next()
            .unwrap()
            .hr_name,
        "Old Name"
    );

    trust
        .ingest_directory(&mk(200, "New Name"), &org_pub)
        .unwrap();
    assert_eq!(
        trust
            .directory_suggestions(&account_pub)
            .next()
            .unwrap()
            .hr_name,
        "New Name"
    );

    // Earlier issued_at than what's on record: must not regress.
    trust
        .ingest_directory(&mk(150, "Stale Name"), &org_pub)
        .unwrap();
    assert_eq!(
        trust
            .directory_suggestions(&account_pub)
            .next()
            .unwrap()
            .hr_name,
        "New Name",
        "an earlier issued_at must never replace a later one already on record"
    );

    // Equal issued_at: must also not replace.
    trust
        .ingest_directory(&mk(200, "Also Stale"), &org_pub)
        .unwrap();
    assert_eq!(
        trust
            .directory_suggestions(&account_pub)
            .next()
            .unwrap()
            .hr_name,
        "New Name",
        "an equal issued_at must not replace the existing entry either"
    );

    // Still exactly one suggestion for this account -- same-org re-imports upsert, never duplicate.
    assert_eq!(trust.directory_suggestions(&account_pub).count(), 1);
}

#[test]
fn oversized_artifact_is_rejected() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();

    let entries: Vec<DirectoryEntry> = (0..=MAX_DIRECTORY_ENTRIES as u32)
        .map(|i| DirectoryEntry {
            account_pub: idx_key(i),
            hr_name: format!("Person {i}"),
        })
        .collect();
    assert_eq!(entries.len(), MAX_DIRECTORY_ENTRIES + 1);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        entries,
    );

    let mut trust = TrustStore::default();
    let err = trust
        .ingest_directory(&artifact, &org_pub)
        .expect_err("entries.len() > MAX_DIRECTORY_ENTRIES must be rejected");
    assert!(matches!(err, DirectoryError::TooManyEntries(n) if n == MAX_DIRECTORY_ENTRIES + 1));
    assert!(trust.directory_suggestions(&idx_key(0)).next().is_none());
}

#[test]
fn oversized_hr_name_is_truncated_not_rejected() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(7);

    // '💥' is 4 bytes in UTF-8 -- straddles the truncation boundary if done naively.
    let hr_name: String = "a".repeat(MAX_HR_NAME_LEN - 2) + "💥💥💥";
    assert!(hr_name.len() > MAX_HR_NAME_LEN);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: hr_name.clone(),
        }],
    );

    let mut trust = TrustStore::default();
    trust
        .ingest_directory(&artifact, &org_pub)
        .expect("truncated, not rejected");
    let suggestion = trust.directory_suggestions(&account_pub).next().unwrap();
    assert!(suggestion.hr_name.len() <= MAX_HR_NAME_LEN);
    assert!(hr_name.starts_with(&suggestion.hr_name));
    assert!(suggestion.hr_name.chars().count() > 0);
}

#[test]
fn total_cap_eviction_evicts_the_globally_oldest_not_an_arbitrary_entry() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();

    let per_artifact = MAX_DIRECTORY_ENTRIES;
    let full_artifacts = MAX_TOTAL_DIRECTORY_SUGGESTIONS / per_artifact;
    assert_eq!(
        full_artifacts * per_artifact,
        MAX_TOTAL_DIRECTORY_SUGGESTIONS,
        "test assumes the cap is an exact multiple of the per-artifact limit"
    );

    let mut trust = TrustStore::default();
    let mut next_key = 0u32;

    // Fill the store to exactly MAX_TOTAL_DIRECTORY_SUGGESTIONS, in `full_artifacts` batches with
    // strictly increasing issued_at -- batch 0 (issued_at == 1) is the globally oldest.
    for batch in 0..full_artifacts {
        let issued_at = (batch as u64) + 1;
        let entries: Vec<DirectoryEntry> = (0..per_artifact)
            .map(|_| {
                let k = idx_key(next_key);
                next_key += 1;
                DirectoryEntry {
                    account_pub: k,
                    hr_name: format!("p{next_key}"),
                }
            })
            .collect();
        let artifact = sign_attestation(
            &org_store,
            org_account.handle(),
            org_pub,
            "org-a.test",
            issued_at,
            entries,
        );
        let n = trust
            .ingest_directory(&artifact, &org_pub)
            .expect("batch ingests");
        assert_eq!(n, per_artifact);
    }

    let count = |trust: &TrustStore, range: std::ops::Range<u32>| {
        range
            .filter(|&i| trust.directory_suggestions(&idx_key(i)).next().is_some())
            .count()
    };
    assert_eq!(count(&trust, 0..next_key), MAX_TOTAL_DIRECTORY_SUGGESTIONS);

    // One more, distinct, newer suggestion -- pushes the running total past the cap.
    let new_key = idx_key(next_key);
    let newest = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        999,
        vec![DirectoryEntry {
            account_pub: new_key,
            hr_name: "Newest".to_string(),
        }],
    );
    trust
        .ingest_directory(&newest, &org_pub)
        .expect("newest ingests");
    next_key += 1;

    // Total stays capped, not grown.
    assert_eq!(count(&trust, 0..next_key), MAX_TOTAL_DIRECTORY_SUGGESTIONS);
    // The newest suggestion survived.
    assert!(trust.directory_suggestions(&new_key).next().is_some());

    // Exactly one entry from the globally-oldest batch (issued_at == 1) was evicted.
    let oldest_batch_remaining = count(&trust, 0..(per_artifact as u32));
    assert_eq!(
        oldest_batch_remaining,
        per_artifact - 1,
        "eviction must remove exactly one entry from the globally oldest batch"
    );

    // Every newer batch (issued_at 2..=full_artifacts) is completely untouched.
    for batch in 1..full_artifacts {
        let start = (batch * per_artifact) as u32;
        let end = start + per_artifact as u32;
        assert_eq!(
            count(&trust, start..end),
            per_artifact,
            "batch {batch} (newer than the evicted one) must be fully intact"
        );
    }
}

#[test]
fn suggestion_is_structurally_distinct_from_a_verified_petname() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(8);

    let mut trust = TrustStore::default();
    // A real, verified contact -- with no petname set.
    trust.observe(account_pub, "org-a.test", 1_000);
    trust.mark_verified(&account_pub).expect("known contact");
    assert_eq!(trust.contact(&account_pub).unwrap().petname, None);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Dana Smith".to_string(),
        }],
    );
    trust
        .ingest_directory(&artifact, &org_pub)
        .expect("ingests");

    // The suggestion is recorded...
    assert_eq!(
        trust
            .directory_suggestions(&account_pub)
            .next()
            .unwrap()
            .hr_name,
        "Dana Smith"
    );
    // ...but it never auto-applies as the contact's real petname, and the trust state (already
    // Verified) is completely unaffected by ingest.
    let contact = trust.contact(&account_pub).unwrap();
    assert_eq!(
        contact.petname, None,
        "a directory suggestion must never auto-apply as Contact::petname"
    );
    assert_eq!(contact.state, TrustState::Verified);
}

#[test]
fn directory_suggestions_survive_seal_at_rest_round_trip() {
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(10);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Dana Smith, Finance".to_string(),
        }],
    );

    let account_store = MemorySecretStore::new();
    let account = generate_account(&account_store, "user.test").expect("account key");

    let mut trust = TrustStore::default();
    trust
        .ingest_directory(&artifact, &org_pub)
        .expect("ingests");
    let sealed = trust
        .seal_at_rest(&account_store, account.handle())
        .expect("seal");

    let reopened = TrustStore::open_at_rest(&account_store, account.handle(), &sealed)
        .expect("open sealed store");
    let suggestions: Vec<_> = reopened.directory_suggestions(&account_pub).collect();
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].hr_name, "Dana Smith, Finance");
    assert_eq!(suggestions[0].org_signing_pub, org_pub);
    assert_eq!(suggestions[0].attested_at, 1_000);
}

#[test]
fn unmatched_entry_is_held_for_a_key_never_observed() {
    // An attestation for a key this store has never `observe`d still records a suggestion (per
    // the schema's "unmatched entries are held, not dropped") -- and still creates no Contact.
    let (org_store, org_account) = org();
    let org_pub = *org_account.public_key().as_bytes();
    let account_pub = idx_key(9);

    let artifact = sign_attestation(
        &org_store,
        org_account.handle(),
        org_pub,
        "org-a.test",
        1_000,
        vec![DirectoryEntry {
            account_pub,
            hr_name: "Future Hire".to_string(),
        }],
    );

    let mut trust = TrustStore::default();
    trust
        .ingest_directory(&artifact, &org_pub)
        .expect("ingests even for an unknown key");
    assert!(trust.directory_suggestions(&account_pub).next().is_some());
    assert!(trust.contact(&account_pub).is_none());
    assert_eq!(trust.trust_state(&account_pub), TrustState::New);
}
