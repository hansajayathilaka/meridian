//! Task 6.4 (ADR 0016 C7 second half) — the envelope-level `eid` replay-dedup key.
//!
//! `MessageEnvelope::eid` is a sender-random 128-bit dedup key, generated once per
//! `ChatState::seal_bytes` call and checked early — before any provisional establishment or
//! decrypt attempt — in `ChatState::open_bytes`. This file proves the three properties task 6.4's
//! own Tests section names:
//!
//! 1. A redelivered envelope (byte-identical, including `eid`) is recognized and dropped **without
//!    a second full decrypt attempt** — not just that the end result is correct, but that the
//!    expensive path genuinely wasn't re-run (see [`redelivered_envelope_is_dropped_before_any_decrypt_attempt`]).
//! 2. A legitimate unconfirmed-initiator retransmit (the sender hasn't seen a reply yet, resends
//!    the same logical message — here, the exact previously-produced envelope bytes, per
//!    `ChatState::seal_bytes`'s own doc comment on what "retransmit" means for this dedup to work)
//!    is recognized and dropped, **never classified as an attack** and never breaking delivery (see
//!    [`unconfirmed_initiator_retransmit_is_not_treated_as_an_attack`]).
//! 3. The dedup store is provably bounded under a flood of distinct `eid`s — mirrors
//!    `apps/core/tests/message_request_flood.rs`'s shape (see
//!    [`seen_eid_set_is_bounded_under_a_flood_of_distinct_eids`]).
//!
//! What this file deliberately does NOT claim: `eid` dedup is a redelivery/duplicate-processing
//! convenience, not a pre-crypto DoS filter and not an independent security boundary (ADR 0016 R2 —
//! see `ChatError::DuplicateEnvelope`'s own doc comment). A flood of *distinct* fake `eid`s carrying
//! garbage ciphertext is not stopped by this mechanism at all — cell 3 below floods with *genuine*,
//! successfully-decrypting envelopes specifically because that is the only way this set grows.

use meridian_core::chat::{ChatError, ChatState, MAX_SEEN_EIDS};
use meridian_envelope::ChatContent;
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use proptest::prelude::*;
use std::collections::HashSet;

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

    /// Publish a bundle with `otk_count` one-time prekeys.
    fn publish(&mut self, otk_count: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let ik = self.ik();
        let gen = generate_bundle(&self.store, self.account.handle(), ik, otk_count).unwrap();
        let otks: Vec<([u8; 32], [u8; 32])> = gen
            .bundle
            .otks
            .iter()
            .zip(gen.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        self.state
            .vault
            .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, 1_700_000_000);
        (gen.bundle.spk, gen.bundle.otks)
    }

    fn start(&mut self, peer: &[u8; 32], peer_spk: &[u8; 32], peer_opk: Option<[u8; 32]>) {
        let ik = self.ik();
        self.state
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                peer,
                peer_spk,
                peer_opk,
            )
            .unwrap();
    }

    fn seal(&mut self, peer: &[u8; 32], id: u8, body: &str) -> Vec<u8> {
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

    /// The generic, gate-free primitive — like `commit_on_decrypt_independent.rs`'s `recv_raw` —
    /// so this file can drive `open_bytes` directly without task 2.10's message-request gate
    /// (`open_inbound`) folding first-contact and redelivery outcomes together.
    fn recv_raw(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, ChatError> {
        let ik = self.ik();
        self.state
            .open_bytes(&self.store, self.account.handle(), &ik, from, blob)
    }

    fn recv_content(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let pt = self.recv_raw(from, blob)?;
        Ok(ChatContent::decode(&pt).unwrap())
    }
}

/// Deterministic CBOR of the whole chat state, for byte-identical before/after comparisons — same
/// trick `chat_manager.rs`/`desync_recovery.rs`/`preamble_mutation.rs` all use (`seal_at_rest`'s
/// AEAD nonce is random, so two seals of identical state differ).
fn state_bytes(state: &ChatState) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(state, &mut out).unwrap();
    out
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

/// The number of `eid`s currently recorded in `ChatState`'s (private) `seen_eids` set — read via
/// the state's own canonical CBOR, exactly the technique `preamble_mutation.rs`'s `otk_depth`
/// uses, and for the same reason: this file must not widen `meridian-core`'s public API just to be
/// testable.
fn seen_eids_len(state: &ChatState) -> usize {
    use ciborium::value::Value;
    let bytes = state_bytes(state);
    let root: Value = ciborium::from_reader(&bytes[..]).unwrap();
    match map_get(&root, "seen_eids") {
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    }
}

/// The number of one-time prekey secrets the vault still holds (current generation only — none of
/// this file's cells republish, so there is never a retained "previous" generation to add in).
fn otk_depth(state: &ChatState) -> usize {
    use ciborium::value::Value;
    let bytes = state_bytes(state);
    let root: Value = ciborium::from_reader(&bytes[..]).unwrap();
    let vault = map_get(&root, "vault").expect("chat state has a vault");
    match map_get(vault, "otks") {
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    }
}

// -- 1. a redelivered envelope is dropped WITHOUT a second full decrypt attempt -----------------

/// A byte-identical redelivery of an already-processed, ordinary (non-prekey, steady-state)
/// message is recognized via `eid` and dropped — and, crucially, **never reaches the ratchet a
/// second time**. Proven, not merely inferred, by the specific error variant pinned below:
/// `ChatError::DuplicateEnvelope` is producible *only* by the early `eid` check, strictly before
/// `Session::decrypt` is ever called on this branch. Confirmed empirically during this task's own
/// development (temporarily disabling the early check and re-running this cell): without it, this
/// exact redelivery instead reaches `Session::decrypt` a second time, which fails with a generic
/// `CryptoError::Crypto` (the message key for that counter was already consumed and deleted on the
/// first, genuine decrypt, so the ratchet's own single-use-key discipline — not this task's dedup
/// check — is what would reject it) and surfaces as `ChatError::Crypto(_)`, a *different* variant
/// this cell explicitly does not accept. Pinning the exact variant is therefore direct evidence the
/// expensive decrypt call was skipped, not just that "some rejection" came back.
#[test]
fn redelivered_envelope_is_dropped_before_any_decrypt_attempt() {
    let mut alice = Party::new("eid.redeliver.a");
    let mut bob = Party::new("eid.redeliver.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let (bob_spk, bob_otks) = bob.publish(2);

    alice.start(&bob_ik, &bob_spk, Some(bob_otks[0]));
    let opening = alice.seal(&bob_ik, 1, "hello");
    assert_eq!(
        bob.recv_content(&alice_ik, &opening).unwrap(),
        ChatContent::Text {
            id: [1u8; 16],
            body: "hello".into()
        }
    );
    let reply = bob.seal(&alice_ik, 2, "hi back");
    alice.recv_content(&bob_ik, &reply).unwrap(); // confirms alice's session

    // An ordinary, steady-state continuation message — no prekey attached any more.
    let second = alice.seal(&bob_ik, 3, "second message");
    let got = bob
        .recv_content(&alice_ik, &second)
        .expect("the genuine second message must open normally");
    assert_eq!(
        got,
        ChatContent::Text {
            id: [3u8; 16],
            body: "second message".into()
        }
    );
    assert_eq!(bob.state.desync_count(&alice_ik), 0, "healthy so far");

    let before = state_bytes(&bob.state);

    // THE REDELIVERY: the relay (or the network) hands Bob the exact same bytes again.
    let duplicate_result = bob.recv_raw(&alice_ik, &second);
    assert!(
        matches!(duplicate_result, Err(ChatError::DuplicateEnvelope)),
        "a byte-identical redelivery must be classified as ChatError::DuplicateEnvelope, not \
         reprocessed as new content and not misclassified as an ordinary rejection — got: \
         {duplicate_result:?}"
    );

    // `desync_count` staying at zero is a supplementary, defense-in-depth check (this specific
    // branch's own `UndecryptableHeader`/`Desync` classification is not what a redelivered,
    // already-consumed steady-state message hits — see the doc comment above for the variant it
    // would hit instead if the eid check were missing) — asserted anyway so a future refactor that
    // *did* route this case through the Desync classifier would be caught here too.
    assert_eq!(
        bob.state.desync_count(&alice_ik),
        0,
        "a genuinely redelivered envelope must never bump the desync counter"
    );

    // Nothing in the chat state changes at all — no session touched, no OTK touched, no
    // bookkeeping mutated (the `eid` was already recorded, so `record_seen_eid` is a no-op). Note
    // this alone would also hold even if `Session::decrypt` had actually been (redundantly)
    // attempted and failed — task 2.13's failure-atomicity means a rejected decrypt leaves no
    // trace either — so this is a general safety net, not by itself the ordering proof; the
    // `DuplicateEnvelope`-vs-`Crypto` variant pinned above is what carries that proof.
    assert_eq!(
        before,
        state_bytes(&bob.state),
        "a rejected duplicate must leave the ENTIRE chat state untouched"
    );

    // The session is still genuinely live afterwards — the duplicate didn't wedge anything.
    let third = alice.seal(&bob_ik, 4, "still fine");
    assert_eq!(
        bob.recv_content(&alice_ik, &third).unwrap(),
        ChatContent::Text {
            id: [4u8; 16],
            body: "still fine".into()
        }
    );
}

// -- 2. a legitimate unconfirmed-initiator retransmit is NOT treated as an attack ---------------

/// Alice sends an opening message to Bob and has not yet seen a reply (`Session::needs_prekey`
/// still true — an "unconfirmed initiator"). Per `ChatState::seal_bytes`'s own doc comment, the
/// dedup property this task promises for a genuine retransmit of that same logical message holds
/// when the retransmission resends the *exact* previously-produced envelope bytes — so this cell
/// constructs exactly that: Bob receives the identical opening envelope twice, because (for
/// example) Alice's first send raced a network hiccup and she is not yet sure it arrived. The
/// second arrival must be recognized as a duplicate, never as a forged/malicious envelope, and
/// must not leave the channel unusable afterwards.
#[test]
fn unconfirmed_initiator_retransmit_is_not_treated_as_an_attack() {
    let mut alice = Party::new("eid.retransmit.a");
    let mut bob = Party::new("eid.retransmit.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let (bob_spk, bob_otks) = bob.publish(2);

    alice.start(&bob_ik, &bob_spk, Some(bob_otks[0]));
    // Alice has NOT received a reply yet: this opening envelope carries the X3DH preamble, and — a
    // genuine, unrelated property of `Session` — would carry the identical preamble again on any
    // further `seal_bytes` call for as long as she stays unconfirmed. This cell tests the
    // resend-the-same-bytes retransmit case, not that unrelated property.
    let opening = alice.seal(&bob_ik, 1, "resend me");

    let depth_before = otk_depth(&bob.state);
    assert!(
        depth_before > 0,
        "vault must hold OTKs for the assertions below to be meaningful"
    );

    // First arrival: genuinely new, must establish the session and deliver.
    let first = bob
        .recv_content(&alice_ik, &opening)
        .expect("the first, genuine arrival must open normally");
    assert_eq!(
        first,
        ChatContent::Text {
            id: [1u8; 16],
            body: "resend me".into()
        }
    );
    assert!(bob.state.has_session(&alice_ik));
    assert_eq!(
        otk_depth(&bob.state),
        depth_before - 1,
        "the genuine first arrival must consume exactly one OTK"
    );

    // THE RETRANSMIT: Alice (or the network) resends the exact same envelope bytes, because no
    // reply has been seen yet.
    let retransmit_result = bob.recv_raw(&alice_ik, &opening);
    match retransmit_result {
        Err(ChatError::DuplicateEnvelope) => {}
        Err(ChatError::Desync) | Err(ChatError::Crypto(_)) | Err(ChatError::UnknownPrekey) => {
            panic!(
                "a legitimate unconfirmed-initiator retransmit must NEVER be classified as an \
                 attack-shaped rejection (Desync/Crypto/UnknownPrekey) — got: {retransmit_result:?}"
            )
        }
        Ok(content) => panic!(
            "SECURITY/CORRECTNESS FAILURE: the retransmit was reprocessed as a brand-new message \
             and delivered a second time: {content:?}"
        ),
        Err(other) => panic!("unexpected rejection for a legitimate retransmit: {other:?}"),
    }

    // Nothing extra was consumed or disturbed by the retransmit: still exactly one OTK gone, and
    // the session Bob installed on the first, genuine arrival is untouched.
    assert_eq!(
        otk_depth(&bob.state),
        depth_before - 1,
        "the retransmit must consume NO additional one-time prekey — it must never re-run X3DH"
    );
    assert!(
        bob.state.has_session(&alice_ik),
        "the retransmit must not tear down or replace the session the genuine arrival installed"
    );

    // And delivery is not broken: a further, genuinely new message from Alice still opens fine.
    let follow_up = alice.seal(&bob_ik, 2, "did you get that?");
    assert_eq!(
        bob.recv_content(&alice_ik, &follow_up).unwrap(),
        ChatContent::Text {
            id: [2u8; 16],
            body: "did you get that?".into()
        }
    );
}

// -- 3. the eid dedup store is provably bounded under a flood of distinct eids ------------------

/// Mirrors `apps/core/tests/message_request_flood.rs`'s shape: `MAX_SEEN_EIDS + K` distinct,
/// genuinely fresh identities each complete one OTK-free first-contact handshake against Bob (an
/// attacker's cheapest way to grow `seen_eids`, since — unlike `pending_requests` — an entry here
/// is recorded only on a *successful* decrypt, per `ChatError::DuplicateEnvelope`'s own doc
/// comment; garbage ciphertext never grows this set at all, in or out of a flood). `seen_eids`
/// must stay capped at `MAX_SEEN_EIDS`, never `MAX_SEEN_EIDS + K`.
#[test]
fn seen_eid_set_is_bounded_under_a_flood_of_distinct_eids() {
    let mut bob = Party::new("eid.flood.bob");
    let bob_ik = bob.ik();
    let (bob_spk, _) = bob.publish(0); // OTK-free: every flood sender's X3DH costs bob nothing to admit

    const K: usize = 8; // strictly more than the cap, so eviction must actually fire K times.
    let total = MAX_SEEN_EIDS + K;

    for i in 0..total {
        let hint = format!("eid.flood.stranger.{i}");
        let mut sender = Party::new(&hint);
        let sender_ik = sender.ik();
        sender.start(&bob_ik, &bob_spk, None);
        let blob = sender.seal(&bob_ik, 1, "hi, a stranger");
        let outcome = bob.recv_raw(&sender_ik, &blob);
        assert!(
            outcome.is_ok(),
            "every fresh flood sender must decrypt successfully (that's what grows seen_eids) — \
             got {outcome:?} at i={i}"
        );
    }

    assert_eq!(
        seen_eids_len(&bob.state),
        MAX_SEEN_EIDS,
        "seen_eids must be capped at MAX_SEEN_EIDS regardless of flood size — this is the \
         assertion that fails outright against an unbounded implementation (it would read `total`)"
    );
}

// -- 4. property coverage (task 7.4, review finding F6) -----------------------------------------
//
// The three cells above are hand-picked scenarios. This block generalizes two of task 6.4's own
// claims across randomized, proptest-generated sequences instead of the three fixed examples:
//
//   1. Exact-duplicate detection holds regardless of arrival order: any envelope not yet delivered
//      must succeed, and any envelope already delivered — no matter how many other (fresh or
//      duplicate) envelopes arrived in between, and no matter whether it arrives in-order or
//      out-of-order relative to the other fresh ones — must be rejected as
//      `ChatError::DuplicateEnvelope`.
//   2. `seen_eids_len(&state) <= MAX_SEEN_EIDS` holds at every step of a randomized sequence, well
//      below the cap (the exact-at-cap boundary is cell 3's job, not this one's) — and, since no
//      eviction can fire below the cap, `seen_eids_len` must track the number of *distinct*
//      successfully-delivered envelopes exactly.
//
// Cost discipline (this task's own Scope/Out note, and 6.4's Decision 3): growing `seen_eids`
// costs a genuine successful decrypt per entry, so this harness does exactly ONE X3DH handshake
// per generated case — alice's opening message plus bob's confirming reply — and then reuses that
// single confirmed session for every further (cheap, symmetric-ratchet-only) message in the
// sequence, the same pattern cell 1 uses for its "second"/"third" steady-state messages. Case
// count and sequence length are kept small per the task's guidance.

/// Build one confirmed alice→bob session (one handshake) and seal `n` distinct steady-state
/// envelopes from alice to bob, returned in sealing order. `n` is small (never more than a
/// handful), so this never approaches `MAX_SEEN_EIDS`.
fn confirmed_session_with_envelopes(n: usize) -> (Party, Party, [u8; 32], Vec<Vec<u8>>) {
    let mut alice = Party::new("eid.prop.a");
    let mut bob = Party::new("eid.prop.b");
    let (bob_ik, alice_ik) = (bob.ik(), alice.ik());
    let (bob_spk, bob_otks) = bob.publish(1);

    alice.start(&bob_ik, &bob_spk, Some(bob_otks[0]));
    let opening = alice.seal(&bob_ik, 0, "open");
    bob.recv_content(&alice_ik, &opening)
        .expect("the opening handshake message must decrypt");
    let reply = bob.seal(&alice_ik, 0, "ack");
    alice
        .recv_content(&bob_ik, &reply)
        .expect("bob's reply must confirm alice's session");

    // The opening message itself already occupies index 0 of bob's `seen_eids`; the sequence
    // below deals only in FURTHER, steady-state envelopes, sealed and handed back distinctly.
    let envelopes = (0..n)
        .map(|i| alice.seal(&bob_ik, (i % 256) as u8, &format!("steady-state #{i}")))
        .collect();
    (alice, bob, bob_ik, envelopes)
}

proptest! {
    // Keep well under a minute: one handshake per case, sequence lengths bounded to a few dozen
    // entries, nowhere near MAX_SEEN_EIDS (256) — see this block's header comment.
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// For every `(n, delivery_order)` pair — `n` distinct fresh envelopes and a random sequence of
    /// indices into them (repeats allowed, any order) — every FIRST occurrence of an index must
    /// succeed and every REPEAT occurrence must be `Err(ChatError::DuplicateEnvelope)`, regardless
    /// of where in the sequence it falls. Simultaneously, `seen_eids_len` must never exceed
    /// `MAX_SEEN_EIDS` and, since `n` never approaches the cap, must track the number of distinct
    /// indices delivered so far exactly (no spurious growth from duplicates, no spurious eviction).
    #[test]
    fn eid_dedup_holds_under_random_interleavings(
        (n, delivery_order) in (2usize..=6).prop_flat_map(|n| {
            (Just(n), proptest::collection::vec(0..n, 6..=24))
        })
    ) {
        let (alice, mut bob, _bob_ik, envelopes) = confirmed_session_with_envelopes(n);

        let mut delivered: HashSet<usize> = HashSet::new();

        for idx in delivery_order {
            let outcome = bob.recv_raw(&alice.ik(), &envelopes[idx]);
            if delivered.insert(idx) {
                // First time this index has appeared in the sequence: must be genuinely fresh.
                prop_assert!(
                    outcome.is_ok(),
                    "a not-yet-delivered envelope (index {idx}) must succeed, got {outcome:?}"
                );
            } else {
                // Already delivered earlier in this same sequence: must be rejected as a duplicate,
                // never reprocessed and never misclassified as some other rejection.
                prop_assert!(
                    matches!(outcome, Err(ChatError::DuplicateEnvelope)),
                    "a redelivery of already-delivered index {idx} must be \
                     Err(ChatError::DuplicateEnvelope), got {outcome:?}"
                );
            }

            let len = seen_eids_len(&bob.state);
            prop_assert!(
                len <= MAX_SEEN_EIDS,
                "seen_eids_len ({len}) must never exceed MAX_SEEN_EIDS ({MAX_SEEN_EIDS})"
            );
            // `n` is tiny relative to MAX_SEEN_EIDS, so eviction never fires in this test: the
            // count of distinct successfully-delivered indices (the handshake entry, plus every
            // distinct fresh index seen so far) must match `seen_eids_len` exactly.
            prop_assert_eq!(
                len,
                1 + delivered.len(),
                "below the cap, seen_eids_len must equal exactly one entry per distinct \
                 successful decrypt (the confirming handshake plus each distinct fresh index)"
            );
        }
    }
}
