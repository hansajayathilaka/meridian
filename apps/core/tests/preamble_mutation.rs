//! Task 1.32 + [ADR 0016](../../../docs/adr/0016-envelope-deniability.md) "Test obligations" —
//! **X3DH prekey-preamble mutation, and the anti-DoS property that makes rejection free.**
//!
//! # Why these cells are here and not in the relay harness
//!
//! `apps/cli/tests/relay_attacks.rs` mounts the attacks a *routing relay* can mount: forging
//! `Deliver.from`, replay, reorder, drop, cross-delivery. Preamble mutation is not one of them —
//! `meridian-rendezvous` has no envelope types (it depends on `meridian-proto` and nothing else from
//! the workspace, `tools/lint-server-no-core.sh`), so it cannot reach `used_opk`/`used_spk` even in
//! a test hook. These cells therefore drive the mutation directly against
//! [`ChatState::open_inbound`], which is where the defence lives, standing in for any on-path
//! attacker with byte access to a genuine envelope.
//!
//! # What is asserted, and what actually stops preamble mutation (v1 vs. v2)
//!
//! ADR 0016 records preamble integrity (R3) as enforced only *implicitly* by the ratchet AEAD:
//! `ek_pub`, `used_spk` and `used_opk` are never authenticated directly, only indirectly (they feed
//! X3DH's key derivation, so a wrong value derives a session that fails to decrypt). Under **v1**
//! the thing that actually stopped preamble mutation was the Ed25519 envelope signature, whose
//! input covered `sender_pub + prekey + ct`: mutate any preamble field and `verify` failed *before*
//! the vault was touched at all — with the AEAD's own implicit protection never even exercised,
//! because `take_otk_secret`/`sessions.insert` ran eagerly, before decrypt, and would have been
//! unsafe on their own (ADR 0016 R3). ADR 0016 flagged this as a **live gap even in v1** —
//! `apps/core/tests/chat_manager.rs` covers wrong-`from` and a ciphertext byte-flip but never a
//! preamble mutation. These cells closed that gap for v1, and (task 6.3) now exercise the **v2**
//! mechanism directly: no signature exists any more, so it is the ratchet AEAD's implicit
//! protection — now safely exercisable *before* anything commits, per commit-on-decrypt (C2) — that
//! must, and does, stop every cell below.
//!
//! Each cell asserts all four properties ADR 0016 lists, not merely "it errored":
//!   1. the rejection is a ratchet-AEAD failure ([`ChatError::Crypto`]) **specifically** — the
//!      provisional session derived from the mutated preamble is a *structurally valid* X3DH
//!      establishment against real prekey material in every cell below (never `UnknownPrekey`),
//!      which is what makes the AEAD failure — not a shortcut earlier in the pipeline — the actual
//!      thing under test;
//!   2. the **OTK pool depth is unchanged** (counted, in [`otk_depth`]);
//!   3. **no session is installed** — and in fact the whole `ChatState` is byte-identical;
//!   4. the genuine envelope **subsequently still opens**, which is what proves (2) and (3) were not
//!      achieved by breaking the honest path.
//!
//! Together (2)+(4) are the anti-DoS property task 1.32 names: a rejected prekey envelope consumes
//! no one-time prekey and installs no session. Under v1 that was because `open_bytes` verified the
//! signature before `take_otk_secret`; under v2 (task 6.3) it is because `open_bytes` runs X3DH
//! *provisionally* and only commits (`take_otk_secret`, `sessions.insert`) on a **successful**
//! decrypt (ADR 0016 C2) — a mutated preamble derives a session that fails to decrypt the genuine
//! ciphertext, and the provisional attempt is discarded without a trace. Without C2, any on-path
//! attacker could burn a peer's whole OTK pool and permanently block the real sender with a
//! poisoned responder session — exactly the R3 residual C2 exists to close.
//!
//! # v2 note (task 6.3 re-pointed these cells; task 6.6 owns new adversarial cells)
//!
//! Envelope v2 drops the signature, so property (1)'s detector moved from the signature to the
//! ratchet AEAD (this file, task 6.3) — these cells were re-pointed, **not** deleted, per ADR
//! 0016's own "Test obligations" section. Designing *new* C3/R1 adversarial cells (e.g. a
//! sign-flipped `sender_pub`) is task 6.6's job, not this re-pointing pass's.

use meridian_core::chat::{ChatError, ChatState, PREV_GENERATION_GRACE_SECS};
use meridian_envelope::{ChatContent, MessageEnvelope};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::{generate_bundle, GeneratedBundle};

const TEST_NOW_UNIX: u64 = 1_700_000_000;
/// Small enough to make [`otk_depth`] assertions readable, >1 so "another held OTK" exists.
const OTK_BATCH: usize = 3;

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
    fn publish_at(&mut self, now_unix: u64) -> GeneratedBundle {
        let ik = self.ik();
        let gen = generate_bundle(&self.store, self.account.handle(), ik, OTK_BATCH).unwrap();
        let otks: Vec<([u8; 32], [u8; 32])> = gen
            .bundle
            .otks
            .iter()
            .zip(gen.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        self.state
            .vault
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, now_unix);
        gen
    }
    fn publish(&mut self) -> GeneratedBundle {
        self.publish_at(TEST_NOW_UNIX)
    }
    fn start(&mut self, peer: &[u8; 32], spk: &[u8; 32], opk: Option<[u8; 32]>) {
        let ik = self.ik();
        self.state
            .start_initiator_session(&self.store, self.account.handle(), &ik, peer, spk, opk)
            .unwrap();
    }
    fn send(&mut self, peer: &[u8; 32], id: u8, body: &str) -> Vec<u8> {
        let ik = self.ik();
        self.state
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                &ChatContent::Text {
                    id: [id; 16],
                    body: body.into(),
                },
            )
            .unwrap()
    }
    /// This file exercises ADR 0016 preamble-mutation defences, not the task-2.10 request-queue UX
    /// (see `apps/core/tests/message_request_gate.rs` for that): a first contact is transparently
    /// auto-accepted here so "the genuine envelope still opens" reads exactly as it did before the
    /// gate existed.
    fn recv(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let ik = self.ik();
        match self
            .state
            .open_inbound(&self.store, self.account.handle(), &ik, from, blob)
        {
            Err(ChatError::MessageRequest) => Ok(self
                .state
                .accept_request(from)
                .expect("just gated by open_inbound")
                .intro),
            other => other,
        }
    }
}

/// Deterministic CBOR of the whole chat state, for a byte-identical before/after comparison. Same
/// trick as `chat_manager.rs::state_bytes` (`seal_at_rest` is unusable — its AEAD nonce is random).
fn state_bytes(state: &ChatState) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(state, &mut out).unwrap();
    out
}

/// The number of one-time prekey secrets the vault still holds, across the current generation **and**
/// the retained previous one (task 1.31 keeps at most one).
///
/// `PrekeyVault`'s fields are private, so this reads them the only way a test can without widening
/// the production API: through the state's own canonical CBOR. That is deliberate — this file must
/// not add a public accessor to `meridian-core` just to be testable, and the CBOR *is* the
/// persisted shape, so a rename that broke this counter would be a real wire-of-record change.
fn otk_depth(state: &ChatState) -> usize {
    use ciborium::value::Value;
    let bytes = state_bytes(state);
    let root: Value = ciborium::from_reader(&bytes[..]).unwrap();
    let vault = map_get(&root, "vault").expect("chat state has a vault");
    let mut count = array_len(map_get(vault, "otks"));
    if let Some(Value::Map(_)) = map_get(vault, "previous") {
        count += array_len(map_get(map_get(vault, "previous").unwrap(), "otks"));
    }
    count
}

fn map_get<'a>(v: &'a ciborium::value::Value, key: &str) -> Option<&'a ciborium::value::Value> {
    let ciborium::value::Value::Map(entries) = v else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| matches!(k, ciborium::value::Value::Text(t) if t == key))
        .map(|(_, val)| val)
}

fn array_len(v: Option<&ciborium::value::Value>) -> usize {
    match v {
        Some(ciborium::value::Value::Array(items)) => items.len(),
        _ => 0,
    }
}

/// Decode a blob, hand its envelope to `mutate`, and re-encode — the capability of an on-path
/// attacker, who has the bytes but (envelope v2 has no signature at all — anyone with the bytes can
/// mutate the preamble; the only question is whether the ratchet AEAD then rejects it) not the
/// sender's session key material needed to make the mutation actually decrypt.
fn mutate_preamble(blob: &[u8], mutate: impl FnOnce(&mut MessageEnvelope)) -> Vec<u8> {
    let mut env = MessageEnvelope::from_blob(blob).unwrap();
    let before = env.prekey.clone();
    mutate(&mut env);
    assert_ne!(
        before, env.prekey,
        "NON-VACUITY: the mutation must actually change the preamble. If the 'attack' is a no-op \
         this cell degenerates into replaying a genuine envelope and proves nothing."
    );
    env.to_blob().unwrap()
}

/// The shared assertion block: reject via the ratchet AEAD ([`ChatError::Crypto`], task 6.3's
/// commit-on-decrypt re-point of the v1 signature detector), touch nothing, and let the genuine
/// envelope through afterwards.
fn assert_rejected_for_free(
    bob: &mut Party,
    alice_ik: &[u8; 32],
    attack_blob: &[u8],
    genuine_blob: &[u8],
    expect_body: &str,
) {
    let depth_before = otk_depth(&bob.state);
    assert!(
        depth_before > 0,
        "the vault must hold one-time prekeys, or 'depth unchanged' is trivially true"
    );
    let before = state_bytes(&bob.state);

    match bob.recv(alice_ik, attack_blob) {
        Err(ChatError::Crypto(_)) => {}
        Ok(content) => panic!(
            "SECURITY FAILURE: a mutated X3DH preamble was ACCEPTED and decrypted: {content:?}"
        ),
        Err(other) => panic!(
            "a mutated preamble must be rejected by the RATCHET AEAD (ADR 0016 C2/C3 — the \
             provisional session it derives fails to decrypt the genuine ciphertext), never by \
             something upstream like UnknownPrekey (every mutation here still names real prekey \
             material Bob holds — see this file's own module doc). A different error means the \
             rejection happened somewhere else, and the 'consumed nothing' assertions below would \
             not be evidence for the property this cell claims. Got: {other:?}"
        ),
    }

    assert_eq!(
        otk_depth(&bob.state),
        depth_before,
        "ANTI-DoS: a rejected prekey envelope must consume NO one-time prekey — `open_bytes` \
         verifies the signature before `take_otk_secret`. Otherwise an on-path attacker drains the \
         pool for free (ADR 0016 R3/C2)."
    );
    assert!(
        !bob.state.has_session(alice_ik),
        "a rejected prekey envelope must install NO responder session — a poisoned session would \
         permanently block the real sender"
    );
    assert_eq!(
        before,
        state_bytes(&bob.state),
        "and in fact NOTHING in the chat state may change: rejection is free"
    );

    // (4) The genuine envelope still opens — which is what proves the three assertions above were
    // not satisfied by simply breaking the honest path.
    match bob.recv(alice_ik, genuine_blob) {
        Ok(ChatContent::Text { body, .. }) => assert_eq!(body, expect_body),
        other => panic!(
            "after the mutated envelope was refused, the GENUINE one must still establish the \
             session and decrypt — otherwise the attacker achieved denial of service anyway, and \
             the 'consumed nothing' assertions above are hollow. Got: {other:?}"
        ),
    }
    assert!(bob.state.has_session(alice_ik));

    // Positive control for the counter itself: an ACCEPTED prekey envelope *does* consume exactly
    // one one-time prekey. Without this, `otk_depth` could be returning a constant and the
    // "unchanged" assertion above would be unfalsifiable — the shape of vacuous test 1.28's review
    // called out.
    assert_eq!(
        otk_depth(&bob.state),
        depth_before - 1,
        "the genuine envelope must consume exactly one OTK — this is what proves otk_depth() is \
         sensitive, and therefore that 'unchanged' above means something"
    );
}

/// Set up Alice→Bob on a fresh generation and return `(alice, bob, alice_ik, bundle, blob)`.
fn opening_envelope(hint: &str) -> (Party, Party, [u8; 32], GeneratedBundle, Vec<u8>) {
    let mut alice = Party::new(&format!("{hint}.a"));
    let mut bob = Party::new(&format!("{hint}.b"));
    let bundle = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[0]));
    let blob = alice.send(&bob_ik, 1, "genuine");
    (alice, bob, alice_ik, bundle, blob)
}

// -- ADR 0016: forged prekey envelope claiming `from = Alice` -----------------

/// A fabricated prekey envelope that *claims* `sender_pub = Alice` and is routed as `from = Alice`,
/// so both the sender/origin cross-check and the routing layer are satisfied. It is built from a
/// genuine Carol→Bob envelope — so its preamble names a real SPK and a real one-time prekey Bob
/// holds — with `sender_pub` swapped to Alice. Only the signature can catch it, and must.
///
/// This is the routing-independent half of ADR 0016's "forged prekey envelope claiming
/// `from = Alice`" obligation; the relay-mounted half is
/// `apps/cli/tests/relay_attacks.rs::forged_deliver_from_is_rejected_as_sender_mismatch`.
#[test]
fn forged_prekey_envelope_claiming_alice_costs_bob_nothing() {
    let mut alice = Party::new("forge.a");
    let mut carol = Party::new("forge.c");
    let mut bob = Party::new("forge.b");
    let bundle = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // Carol builds a real opening envelope against Bob's bundle; the attacker relabels it as Alice's.
    carol.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[0]));
    let carols = carol.send(&bob_ik, 9, "carol's real message");
    let mut env = MessageEnvelope::from_blob(&carols).unwrap();
    env.sender_pub = alice_ik;
    let forged = env.to_blob().unwrap();

    // Alice's own genuine envelope, for the "still works afterwards" leg.
    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[1]));
    let genuine = alice.send(&bob_ik, 1, "alice's real message");

    assert_rejected_for_free(
        &mut bob,
        &alice_ik,
        &forged,
        &genuine,
        "alice's real message",
    );

    // And Carol's original — whose one-time prekey the forgery referenced — is still openable, a
    // direct behavioural proof that the forgery burned nothing.
    let carol_ik = carol.ik();
    assert!(
        bob.recv(&carol_ik, &carols).is_ok(),
        "the one-time prekey the forged envelope referenced must still be available to its real \
         owner's session"
    );
}

// -- ADR 0016: preamble mutation ---------------------------------------------

/// `used_opk` → `None`. Downgrades the handshake to the no-one-time-prekey X3DH variant, which
/// derives a different root key. Under v1 the signature stops it; under v2 (no signature) this is
/// the case that would install a poisoned session unless C2 is honoured.
#[test]
fn preamble_mutation_used_opk_to_none_is_rejected_for_free() {
    let (_alice, mut bob, alice_ik, _bundle, genuine) = opening_envelope("opk-none");
    let attack = mutate_preamble(&genuine, |env| {
        let p = env
            .prekey
            .as_mut()
            .expect("opening envelope has a preamble");
        assert!(p.used_opk.is_some(), "the genuine envelope must use an OTK");
        p.used_opk = None;
    });
    assert_rejected_for_free(&mut bob, &alice_ik, &attack, &genuine, "genuine");
}

/// `used_opk` → **another one-time prekey Bob holds**. The prekey-depletion attack in its sharpest
/// form: if it were accepted, one genuine envelope would burn two OTKs, and every *other* peer that
/// fetched the same bundle would find its own prekey already consumed.
#[test]
fn preamble_mutation_used_opk_to_another_held_otk_is_rejected_for_free() {
    let (_alice, mut bob, alice_ik, bundle, genuine) = opening_envelope("opk-swap");
    let other_otk = bundle.bundle.otks[1];
    assert_ne!(
        other_otk, bundle.bundle.otks[0],
        "the batch must contain a second, distinct one-time prekey"
    );
    let attack = mutate_preamble(&genuine, |env| {
        env.prekey.as_mut().unwrap().used_opk = Some(other_otk);
    });
    assert_rejected_for_free(&mut bob, &alice_ik, &attack, &genuine, "genuine");

    // The specifically-targeted OTK is provably still usable: a third party opens a session with it.
    let mut dave = Party::new("opk-swap.d");
    let dave_ik = dave.ik();
    let bob_ik = bob.ik();
    dave.start(&bob_ik, &bundle.bundle.spk, Some(other_otk));
    let daves = dave.send(&bob_ik, 7, "dave");
    assert!(
        bob.recv(&dave_ik, &daves).is_ok(),
        "the one-time prekey the mutation tried to burn must still open its rightful owner's session"
    );
}

/// `used_spk` → the **previous generation's** signed prekey, which Bob still holds inside task
/// 1.31's 60-second grace window. The most plausible of the three: it points at material that
/// genuinely exists, so nothing downstream would reject it for being unknown.
#[test]
fn preamble_mutation_used_spk_to_previous_generation_is_rejected_for_free() {
    let mut alice = Party::new("spk-prev.a");
    let mut bob = Party::new("spk-prev.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    let gen_n = bob.publish_at(TEST_NOW_UNIX);
    let gen_n1 = bob.publish_at(TEST_NOW_UNIX + 1);
    assert_ne!(
        gen_n.bundle.spk, gen_n1.bundle.spk,
        "the republish must produce a genuinely different signed prekey"
    );
    // Bob is inside the grace window, so he holds BOTH generations' secrets — the mutation points at
    // real, live material rather than at something that would fail as merely unknown.
    bob.state
        .expire_previous_generation(TEST_NOW_UNIX + 1 + PREV_GENERATION_GRACE_SECS - 1);

    alice.start(&bob_ik, &gen_n1.bundle.spk, Some(gen_n1.bundle.otks[0]));
    let genuine = alice.send(&bob_ik, 1, "genuine");
    let attack = mutate_preamble(&genuine, |env| {
        env.prekey.as_mut().unwrap().used_spk = gen_n.bundle.spk;
    });

    assert_rejected_for_free(&mut bob, &alice_ik, &attack, &genuine, "genuine");
}
