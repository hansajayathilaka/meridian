//! Task 5.6 (review finding F6) — closes the T08 trust-state matrix's last federated gap.
//!
//! Task 2.12's cross-org cell
//! (`apps/rendezvous/tests/federation_abuse.rs::cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client`)
//! only ever proves the A2×2 (colluding org servers) defense on a **fresh** contact — no prior
//! trust record at all. Task 4.10's verified-contact key-change BLOCK
//! (`apps/core/tests/desync_recovery.rs::attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it`'s
//! `Verified` case, extended to a real P2P session by task 5.5's
//! `apps/core/tests/session.rs::recover_from_desync_hard_blocks_a_key_substitution_against_a_verified_established_session`)
//! only ever proves it **single-org**. Neither alone proves the headline A2×2 property against a
//! contact alice has ALREADY VERIFIED, over a genuinely federated (two-real-server, colluding-org)
//! topology — this file closes that gap by combining both, without adding or touching any
//! trust-state-machine logic (`apps/core/src/trust.rs` stays byte-for-byte untouched — this is
//! coverage only, per this task's own scope note).
//!
//! Two halves, mirroring `mitm_preexisting_contact.rs`'s own two-numbered-assertion structure and
//! its own scope-boundary discipline (that file's own doc comment already explains why the
//! decision-gate half is proven in-process, never via a live fetch — the reasoning below extends
//! that unchanged, just now tied concretely to a federated topology):
//!
//! 1. [`federated_colluding_servers_bundle_substitution_against_an_already_verified_contact_fails_closed_at_the_fetch_layer`] —
//!    network+federated-CLI layer. A real two-server topology: org-a.test (alice's home, honest)
//!    and org-b.test (bob's home, **colluding** — `allow_test_tamper` armed for the whole
//!    instance, task 2.12's federated `test-tamper-hook` extension). Alice already has bob
//!    **VERIFIED** — not merely pinned — via the real `meridian contact add` +
//!    `meridian verify --scan-file` CLI surface (`TrustStore::mark_verified` under the hood,
//!    exactly `verify.rs`'s own round trip). Org B's real, already-published bundle for bob is
//!    substituted on the FEDERATED fetch path; alice's client (which only ever talks to org-a)
//!    must abort via its OWN `verify_bundle` check, `SignalError::BundleVerification`
//!    FATAL/non-zero, exactly like 2.12's fresh-contact federated cell — AND, the part that cell
//!    cannot check (it starts from no trust record at all): the pre-existing VERIFIED trust
//!    record survives byte-identical — no phantom `PinnedKeyChanged`/`Blocked` demotion, no new
//!    contact row for the substituted key.
//! 2. [`federated_colluding_org_key_substitution_against_a_verified_contact_hard_blocks_via_the_recovery_gate`] —
//!    decision-gate layer, honestly labelled. `attempt_recovery` (`apps/core/src/desync.rs`) is an
//!    I/O-free, topology-agnostic pure function over `ChatState`/`TrustStore`: no network, no server
//!    config, and no notion of "org" reaches it. This test's call shape and assertions are therefore
//!    functionally identical to the pre-existing single-org verified-contact case
//!    (`apps/core/tests/desync_recovery.rs`'s `Verified` case and
//!    `apps/core/tests/session.rs::recover_from_desync_hard_blocks_a_key_substitution_against_a_verified_established_session`)
//!    — only variable/label names differ. Labelling Mallory as hosted at the SAME colluding org
//!    (`org-b.test`) as bob is documentation flavour, not an enforced or exercised property:
//!    `attempt_recovery` has no way to check where a key is "hosted". This half is **not**
//!    federation-specific coverage, and does not claim to be. It exists as a topology-agnostic
//!    regression-consistency pin that completes the T08 trust-state coverage matrix's symmetry — the
//!    `Pinned` case already has a decision-gate regression test at the single-org layer, and this
//!    gives `Verified` the same, reached this time via this file's federated framing — and, per this
//!    task's mutation testing, it genuinely catches a regression if the gate/guard is bypassed: real
//!    value, just not a federation-specific proof. See `harnesses/mitm-sim/README.md`'s "Scope
//!    boundaries" section for why no equivalent federated `Pinned` decision-gate cell was added.
//!    Mirrors `desync_recovery.rs`'s and `session.rs`'s own verified-contact assertion shape
//!    exactly: `TrustState::Blocked`, no session installed, canonical `verification-ux.md`
//!    wording, `acknowledge_key_change` refused even against the state this very call just
//!    produced.
//!
//! **Scope boundary on assertion 1's trust-record half** (the same caveat
//! `mitm_preexisting_contact.rs` already states for its own byte-identical assertion, applies
//! unchanged here). `fetch-bundle` is `main.rs::cmd_fetch_bundle`, a standalone verify-and-print
//! diagnostic that never reads or writes `TrustStore` at all today — so the "pre-existing VERIFIED
//! record survives byte-identical" half of test 1 is, on today's code, also a **structural**
//! guarantee (there is no call path from this command into the trust store for it to have taken),
//! not merely an empirically-observed one. It is still real, non-vacuous coverage: it pins the fact
//! down as a regression test, so that a future change wiring `fetch-bundle` (or a `chat`-flow
//! equivalent) into trust bookkeeping over the federated path specifically cannot silently start
//! writing a failed/tampered fetch's substituted key into an already-VERIFIED contact's record
//! without this test catching it.

use meridian_core::chat::ChatState;
use meridian_core::desync::{attempt_recovery, RecoveryOutcome};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::signaling::generate_bundle;
use meridian_core::trust::{SendGate, TrustError, TrustState, TrustStore};

mod support;
use support::{stderr, stdout, Client};

const TEST_NOW_UNIX: u64 = 1_700_000_000;

/// `meridian contact list --json`'s raw stdout — used as the before/after trust-state snapshot,
/// mirroring `mitm_preexisting_contact.rs`'s own `contact_list_json`.
fn contact_list_json(client: &Client) -> String {
    let out = client.run(&["contact", "list", "--json"]);
    assert!(out.status.success(), "contact list: {}", stderr(&out));
    stdout(&out)
}

// -- 1. network+federated-CLI layer: fetch-layer defense holds against a VERIFIED contact --------

#[test]
fn federated_colluding_servers_bundle_substitution_against_an_already_verified_contact_fails_closed_at_the_fetch_layer(
) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let rig = rt.block_on(support::boot_federated_pair_bidirectional_with_b_tamper());

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");
    let alice_id = alice.id();

    let bob = Client::new();
    bob.new_account("bob.key", "org-b.test");
    let bob_id = bob.id();

    // Both register at their own home org — this also publishes each one's REAL bundle, so the
    // substitution below is proven to be org-b lying about a real, already-published identity, not
    // merely reporting "not found" under a different guise (mirrors `federation_abuse.rs`'s own
    // non-vacuity note).
    for (who, client, server) in [
        ("alice", &alice, &rig.a_c2s_url),
        ("bob", &bob, &rig.b_c2s_url),
    ] {
        let out = client.run(&["register", "--server", server]);
        assert!(out.status.success(), "{who} register: {}", stderr(&out));
    }

    // Alice already has a VERIFIED relationship with bob BEFORE any attack is attempted — the real
    // CLI surfaces a user would actually use: `contact add` (TOFU-pin), then `verify --scan-file`
    // (the headless compare flow, `TrustStore::mark_verified` under the hood — `verify.rs` proves
    // this round trip in isolation; this file proves it survives a federated attack afterward).
    let out = alice.run(&["contact", "add", &bob_id]);
    assert!(out.status.success(), "contact add: {}", stderr(&out));

    let me = meridian_core::identity::parse_id(&alice_id).expect("parse alice id");
    let peer = meridian_core::identity::parse_id(&bob_id).expect("parse bob id");
    let number = meridian_core::crypto::safety_number(me.pubkey(), peer.pubkey());
    let qr_dir = tempfile::tempdir().unwrap();
    let qr_path = qr_dir.path().join("safety.png");
    meridian_core::identity::render_luma(&number)
        .expect("render safety number as a QR bitmap")
        .save(&qr_path)
        .expect("write QR fixture to disk");
    let out = alice.run(&["verify", &bob_id, "--scan-file", qr_path.to_str().unwrap()]);
    assert!(out.status.success(), "verify --scan-file: {}", stderr(&out));

    let before = contact_list_json(&alice);
    assert!(
        before.contains("\"state\":\"verified\""),
        "sanity: bob must already be VERIFIED before the attack: {before}"
    );
    assert!(
        !before.is_empty() && before.lines().count() == 1,
        "sanity: exactly one pre-existing contact row: {before:?}"
    );

    // THE ATTACK: two colluding federated servers. Org A (alice's own, honest) and org B (bob's
    // home, malicious — `allow_test_tamper` armed) attempt a key substitution over the FEDERATED
    // fetch path. `--tamper` is deliberately NOT passed on the CLI: `handle_fed_fetch`'s
    // substitution is unconditional on `allow_test_tamper` alone (no client-supplied opt-in bit
    // exists on the wire) — a real colluding B does not wait to be asked to lie, exactly like
    // `federation_abuse.rs::cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client`.
    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &rig.a_c2s_url]);
    assert!(
        !out.status.success(),
        "a federated bundle substitution must fail closed even against an already-VERIFIED \
         contact; stdout={}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("FATAL: bundle signature does not match requested identity"),
        "expected the identical FATAL abort proven for a fresh federated contact (2.12) and a \
         pre-existing PINNED single-org contact (4.10), got: {}",
        stderr(&out)
    );

    // THE NEW ASSERTION: alice's pre-existing VERIFIED trust record for bob survives byte-identical
    // — no phantom PinnedKeyChanged/Blocked demotion, no new contact row for the attacker's
    // substituted key. This is the coverage 2.12's fresh-contact federated cell structurally cannot
    // provide (it starts with no trust record to protect) and `mitm_preexisting_contact.rs`
    // structurally cannot provide either (single-org, and only ever reaches `pinned`, never
    // `verified`).
    let after = contact_list_json(&alice);
    assert_eq!(
        before, after,
        "a failed federated tampered-bundle fetch must leave an already-VERIFIED trust record \
         byte-identical: no demotion and no new contact row for the attacker's substituted key may \
         appear just because a federated fetch attempt happened to fail"
    );

    rig.kill_both_servers();
}

// -- 2. decision-gate layer: topology-agnostic regression-consistency pin (see module doc) -------

struct Peer {
    store: MemorySecretStore,
    account: AccountId,
}

impl Peer {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).expect("account");
        Self { store, account }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
    fn handle(&self) -> KeyHandle {
        self.account.handle().clone()
    }
}

/// Mirrors `desync_recovery.rs`'s and `session.rs`'s own `assert_canonical_substance` exactly (the
/// canonical `docs/security/verification-ux.md` wording must, in substance: name the safety
/// number, name the benign explanation, name the interception possibility, and offer verification —
/// never collapse into pure reassurance). Duplicated in miniature rather than factored into a
/// shared test-support crate, matching `desync_recovery.rs`'s own judgment call on the same point.
fn assert_canonical_substance(reason: &str) {
    let lower = reason.to_lowercase();
    assert!(
        lower.contains("safety number"),
        "must name what changed: {reason}"
    );
    assert!(
        lower.contains("reinstalled") || lower.contains("switched devices"),
        "must state the benign explanation: {reason}"
    );
    assert!(
        lower.contains("intercept"),
        "must state the interception possibility, never soften into pure reassurance: {reason}"
    );
    assert!(
        lower.contains("verify"),
        "must offer a Verify action: {reason}"
    );
}

#[test]
fn federated_colluding_org_key_substitution_against_a_verified_contact_hard_blocks_via_the_recovery_gate(
) {
    let alice = Peer::new("fed5.6.alice");
    // bob is hosted at org-b.test — the same colluding org armed in test 1 above.
    let bob = Peer::new("fed5.6.bob");
    // mallory is ALSO hosted at org-b.test: the substituted identity is concretely tied to the
    // colluding org, not an unrelated synthetic key.
    let mallory = Peer::new("fed5.6.mallory");
    let (alice_ik, bob_ik, mallory_ik) = (alice.ik(), bob.ik(), mallory.ik());

    let bob_gen = generate_bundle(&bob.store, &bob.handle(), bob_ik, 5).expect("bob bundle");
    let mut alice_chat = ChatState::default();
    alice_chat
        .start_initiator_session(
            &alice.store,
            &alice.handle(),
            &alice_ik,
            &bob_ik,
            &bob_gen.bundle.spk,
            bob_gen.bundle.otks.first().copied(),
        )
        .expect("start_initiator_session");
    // Just needs an existing session to "recover" — mirrors `desync_recovery.rs`'s own comment.
    let _ = alice_chat
        .seal_outbound(
            &alice.store,
            &alice.handle(),
            &alice_ik,
            &bob_ik,
            &ChatContent::Text {
                id: [1; 16],
                body: "hi".to_string(),
            },
        )
        .expect("seal_outbound");

    // Alice already has bob VERIFIED — the real headline state 4.10's matrix names, labelled here
    // with this file's federated framing (hostnames, hint strings) even though `attempt_recovery`
    // itself has no notion of "org" and does not check it — see the module doc's honest scope note.
    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "org-b.test", TEST_NOW_UNIX);
    trust.mark_verified(&bob_ik).expect("known contact");

    // Mallory's bundle is genuinely, honestly self-signed under her OWN key — not a corrupted
    // signature. Framed as if org-b, having colluded to surface her identity instead of bob's during
    // the recovery window, handed `attempt_recovery` a bundle owner key that differs from the peer
    // alice actually meant to reach — but `attempt_recovery` takes that key as a plain parameter and
    // has no way to check its origin, so this framing is documentation only, not an enforced or
    // exercised property (see module doc).
    let mallory_gen =
        generate_bundle(&mallory.store, &mallory.handle(), mallory_ik, 5).expect("mallory bundle");

    let outcome = attempt_recovery(
        &mut alice_chat,
        &mut trust,
        &alice.store,
        &alice.handle(),
        &alice_ik,
        &bob_ik,
        &mallory_ik, // bundle genuinely verified under a DIFFERENT key than peer_ik
        &mallory_gen.bundle.spk,
        mallory_gen.bundle.otks.first().copied(),
        "org-b.test",
        TEST_NOW_UNIX + 1,
    )
    .expect("gated outcomes are Ok, never an Err");

    let reason = match &outcome {
        RecoveryOutcome::Gated(SendGate::Blocked(reason)) => reason.clone(),
        other => panic!(
            "a substituted key surfaced by the colluding org against a VERIFIED contact must \
             hard-BLOCK, never merely warn or — worse — silently recover: {other:?}"
        ),
    };
    assert_canonical_substance(&reason);
    assert!(
        reason.to_lowercase().contains("block"),
        "a verified-contact substitution must say sends are BLOCKED, not merely paused: {reason}"
    );
    assert_eq!(trust.trust_state(&mallory_ik), TrustState::Blocked);
    assert!(
        !alice_chat.has_session(&mallory_ik),
        "no session may be installed under the substituted key while blocked"
    );

    // No bypass: the pinned-case escape hatch cannot clear a verified-contact key-change block
    // either, even reached this way — mirrors `desync_recovery.rs`'s and `session.rs`'s own
    // adversarial checks, on the SAME `TrustStore` `attempt_recovery` just gated, not a fresh one.
    let err = trust
        .acknowledge_key_change(&mallory_ik)
        .expect_err("acknowledging a Blocked (verified) key change must be a hard error");
    assert!(matches!(err, TrustError::NotAcknowledgeable));
    assert_eq!(trust.can_send(&mallory_ik), SendGate::Blocked(reason));
}
