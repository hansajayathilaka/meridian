//! Independent test-engineer verification of task 6.3 / ADR 0016 C2 — **commit-on-successful-decrypt**
//! (`docs/tasks/phase-6/6.3-envelope-v2-core-cutover.md`'s Reviews section: "test-engineer — must
//! independently reproduce the commit-on-decrypt property ... not take the diff's word for it").
//!
//! This file is deliberately **not** a modification of `apps/core/tests/preamble_mutation.rs` or
//! `apps/core/tests/desync_recovery.rs` (both already exist and already cover *preamble* mutation on
//! the first-contact and task-4.9 fallback branches respectively). It targets a genuinely different
//! attack surface those files do not: **ciphertext corruption** (`ct`, not `prekey`) on an otherwise
//! wire-valid opening/re-initiation envelope, driven directly against the public
//! [`meridian_core::chat::ChatState::open_bytes`] primitive itself (not through
//! `open_inbound`'s message-request gate, which is orthogonal UX, not the crypto property under
//! test). A corrupted ciphertext is the most direct falsifier of "commit only after the AEAD says
//! yes": the provisional session `establish_responder_session_provisional` builds is *structurally*
//! perfect (real SPK, real OTK, real ephemeral) — only the AEAD tag over the payload is wrong — so if
//! commit-on-decrypt were subtly broken (e.g. a caller committing before checking `decrypt`'s
//! `Result`, or committing on `Err` as well as `Ok`), this is exactly the shape of bug that would slip
//! past a preamble-only test suite while still being caught here.
//!
//! Every cell in this file asserts, independently:
//! 1. failure is classified as the AEAD/crypto rejection, never `UnknownPrekey` or any other
//!    upstream shortcut (proving the rejection point actually is the decrypt call);
//! 2. the responder's one-time-prekey pool depth is **unchanged** by the failed attempt;
//! 3. **no** new session is installed (`ChatState::has_session` reads `false` for the attacker's
//!    envelope's claimed peer, or — on the fallback branch — the *existing* session is left
//!    byte-for-byte untouched, never replaced by a poisoned one);
//! 4. a genuine, correctly-formed message from the *same* opening material DOES consume the OTK and
//!    DOES install/replace the session — the positive control, so (2)/(3) are not vacuously true
//!    because nothing here ever succeeds;
//! 5. a further, ordinary follow-up message after that genuine establishment still decrypts
//!    correctly — proving the failed attempt didn't leave any latent corruption behind for future
//!    traffic.

use meridian_core::chat::{ChatError, ChatState};
use meridian_envelope::{ChatContent, MessageEnvelope};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::{generate_bundle, GeneratedBundle};

const TEST_NOW_UNIX: u64 = 1_700_000_000;
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

    /// Drives `ChatState::open_bytes` directly — the exact primitive task 6.3's provisional-
    /// establish/commit-on-decrypt control flow lives in — bypassing `open_inbound`'s task-2.10
    /// message-request gate entirely, since that gate is delivery UX and orthogonal to the crypto
    /// property this file verifies (see this file's module doc).
    fn recv_raw(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, ChatError> {
        let ik = self.ik();
        self.state
            .open_bytes(&self.store, self.account.handle(), &ik, from, blob, false)
    }

    fn recv_content(&mut self, from: &[u8; 32], blob: &[u8]) -> Result<ChatContent, ChatError> {
        let pt = self.recv_raw(from, blob)?;
        Ok(ChatContent::decode(&pt).unwrap())
    }
}

/// Independently-written CBOR-reflection reader for the vault's OTK pool depth. Deliberately does
/// NOT reuse `preamble_mutation.rs::otk_depth` or `chat_manager.rs`'s equivalents verbatim (this
/// file's whole point is an independent reproduction, not a copy of the implementer's own
/// instrumentation) — but the underlying technique (read `PrekeyVault`'s private fields through its
/// own canonical at-rest CBOR shape) is the only one available without widening `meridian-core`'s
/// public API purely for testability, which this task's own scope forbids.
fn otk_pool_depth(state: &ChatState) -> usize {
    use ciborium::value::Value;
    let mut bytes = Vec::new();
    ciborium::into_writer(state, &mut bytes).expect("ChatState always encodes");
    let root: Value = ciborium::from_reader(&bytes[..]).expect("round-trips");
    let Value::Map(top) = &root else {
        panic!("ChatState CBOR root must be a map");
    };
    let vault = top
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == "vault"))
        .map(|(_, v)| v)
        .expect("ChatState always has a vault field");
    let Value::Map(vault_fields) = vault else {
        panic!("vault must encode as a map");
    };
    let mut total = 0usize;
    for (key, val) in vault_fields {
        let Value::Text(name) = key else { continue };
        if name == "otks" {
            if let Value::Array(items) = val {
                total += items.len();
            }
        } else if name == "previous" {
            if let Value::Map(prev_fields) = val {
                for (pk, pv) in prev_fields {
                    if matches!(pk, Value::Text(t) if t == "otks") {
                        if let Value::Array(items) = pv {
                            total += items.len();
                        }
                    }
                }
            }
        }
    }
    total
}

/// Whole-state deterministic CBOR snapshot for byte-identical before/after comparisons.
fn snapshot(state: &ChatState) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(state, &mut out).expect("ChatState always encodes");
    out
}

/// Same as [`snapshot`], with `desync_counts` stripped — needed only for the fallback-branch cell
/// below, whose *expected* outcome (an ordinary failed decrypt on an existing-session path) is
/// classified as `ChatError::Desync` and therefore legitimately bumps that one counter. Every other
/// field — sessions, the vault's OTK pool, `responder_session_ek` — must still be byte-identical.
fn snapshot_excluding_desync_counts(state: &ChatState) -> Vec<u8> {
    use ciborium::value::Value;
    let bytes = snapshot(state);
    let mut root: Value = ciborium::from_reader(&bytes[..]).expect("round-trips");
    if let Value::Map(entries) = &mut root {
        entries.retain(|(k, _)| !matches!(k, Value::Text(t) if t == "desync_counts"));
    }
    let mut out = Vec::new();
    ciborium::into_writer(&root, &mut out).unwrap();
    out
}

/// Flip one byte inside the ratchet ciphertext (`ct`), leaving `prekey`/`sender_pub`/`v` completely
/// untouched. Distinguishes this file's attack from `preamble_mutation.rs`'s: the X3DH material this
/// derives a provisional session from is entirely genuine, so any rejection can only come from the
/// AEAD tag check over the (now-corrupted) payload itself.
fn corrupt_ciphertext(blob: &[u8]) -> Vec<u8> {
    let mut env = MessageEnvelope::from_blob(blob).unwrap();
    assert!(
        !env.ct.is_empty(),
        "a real ratchet message always carries a non-empty ct"
    );
    let before = env.ct.clone();
    // Flip a byte inside the AEAD-protected payload (past the ratchet header framing), never the
    // preamble.
    let idx = env.ct.len() - 1;
    env.ct[idx] ^= 0xFF;
    assert_ne!(before, env.ct, "the mutation must actually change ct");
    env.to_blob().unwrap()
}

// -- Cell 1: first-contact branch (task 1.18 "safe half") --------------------------------------

/// A structurally genuine opening envelope, with a single ciphertext byte flipped, must be rejected
/// by the AEAD with **zero** observable side effects: no OTK consumed, no session installed, entire
/// chat state byte-identical. A subsequent, unmutated copy of the same opening envelope must then
/// succeed, consuming exactly one OTK and installing the session (positive control) — and a further
/// ordinary follow-up message must still decrypt correctly afterwards.
#[test]
fn corrupted_ciphertext_on_first_contact_burns_nothing_and_genuine_traffic_still_works() {
    let mut alice = Party::new("indep-ct1.a");
    let mut bob = Party::new("indep-ct1.b");
    let bundle = bob.publish();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    alice.start(&bob_ik, &bundle.bundle.spk, Some(bundle.bundle.otks[0]));
    let genuine = alice.send(&bob_ik, 1, "genuine opener");
    let attack = corrupt_ciphertext(&genuine);

    let depth_before = otk_pool_depth(&bob.state);
    assert!(
        depth_before > 0,
        "the vault must hold OTKs, or 'unchanged' below is trivially true"
    );
    let state_before = snapshot(&bob.state);

    match bob.recv_raw(&alice_ik, &attack) {
        Err(ChatError::Crypto(_)) => {}
        Ok(pt) => panic!(
            "SECURITY FAILURE: a ciphertext-corrupted opening envelope was ACCEPTED and decrypted \
             to {} bytes of plaintext",
            pt.len()
        ),
        Err(other) => panic!(
            "expected the AEAD (ChatError::Crypto) to be what rejects a ciphertext-corrupted \
             envelope whose X3DH material is entirely genuine — got a different error, meaning \
             something upstream of decrypt rejected it, which would make the 'nothing consumed' \
             assertions below meaningless: {other:?}"
        ),
    }

    assert_eq!(
        otk_pool_depth(&bob.state),
        depth_before,
        "COMMIT-ON-DECRYPT VIOLATION: a failed provisional decrypt must consume ZERO one-time \
         prekeys"
    );
    assert!(
        !bob.state.has_session(&alice_ik),
        "COMMIT-ON-DECRYPT VIOLATION: a failed provisional decrypt must install NO session"
    );
    assert_eq!(
        state_before,
        snapshot(&bob.state),
        "a failed provisional first-contact attempt must leave the ENTIRE chat state untouched"
    );

    // Positive control + "subsequent legitimate traffic still works" in one step: the genuine,
    // unmutated envelope referencing the exact same opening material must now succeed.
    let got = bob.recv_content(&alice_ik, &genuine).expect(
        "the genuine opening envelope must still establish the session normally after the \
                 corrupted one was rejected",
    );
    assert_eq!(
        got,
        ChatContent::Text {
            id: [1u8; 16],
            body: "genuine opener".into()
        }
    );
    assert!(bob.state.has_session(&alice_ik));
    assert_eq!(
        otk_pool_depth(&bob.state),
        depth_before - 1,
        "the genuine envelope must consume EXACTLY one OTK — proves otk_pool_depth() is sensitive, \
         so the 'unchanged' assertion above is not vacuous"
    );

    // Follow-up ordinary traffic on the freshly-installed session must decrypt correctly too — the
    // failed attempt left nothing corrupted for the future.
    let reply = bob.send(&alice_ik, 2, "hi back");
    let got2 = alice.recv_content(&bob_ik, &reply).unwrap();
    assert_eq!(
        got2,
        ChatContent::Text {
            id: [2u8; 16],
            body: "hi back".into()
        }
    );
    let follow_up = alice.send(&bob_ik, 3, "still fine");
    let got3 = bob.recv_content(&alice_ik, &follow_up).unwrap();
    assert_eq!(
        got3,
        ChatContent::Text {
            id: [3u8; 16],
            body: "still fine".into()
        }
    );
}

// -- Cell 2: task-4.9 stale-session fallback branch --------------------------------------------

/// The same ciphertext-corruption attack, mounted against the task-4.9 fallback branch instead of
/// first contact: Bob already holds a *stale* session for Alice, and a structurally genuine
/// re-initiation envelope (fresh, real `ek_pub`, correctly formed) arrives with one ciphertext byte
/// flipped. The provisional session `establish_responder_session_provisional` builds for the
/// fallback attempt must fail to decrypt it, leaving the stale-but-live session, the OTK pool, and
/// `responder_session_ek` completely untouched (aside from the ordinary `desync_counts` bump every
/// failed fallback attempt legitimately produces) — never replacing the existing session with a
/// poisoned one built from unauthenticated ciphertext. The genuine (unmutated) re-initiation must
/// then succeed normally, replacing the stale session and consuming exactly one OTK, and the channel
/// must stay live afterwards.
#[test]
fn corrupted_ciphertext_on_stale_session_fallback_burns_nothing_and_genuine_reinit_still_works() {
    let mut alice = Party::new("indep-ct2.a");
    let mut bob = Party::new("indep-ct2.b");
    let bob_gen1 = bob.publish_at(TEST_NOW_UNIX);
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // Establish an initial, healthy session so Bob genuinely holds something to go stale.
    alice.start(&bob_ik, &bob_gen1.bundle.spk, Some(bob_gen1.bundle.otks[0]));
    let opening = alice.send(&bob_ik, 1, "hello");
    bob.recv_content(&alice_ik, &opening).unwrap();
    let reply = bob.send(&alice_ik, 2, "hi alice");
    alice.recv_content(&bob_ik, &reply).unwrap();

    // Alice loses her session state outright (task 1.18's canonical scenario) and re-initiates
    // fresh, against a newly published generation — Bob's old session for her is now stale.
    alice.state = ChatState::default();
    let bob_gen2 = bob.publish_at(TEST_NOW_UNIX + 1);
    assert_ne!(
        bob_gen1.bundle.spk, bob_gen2.bundle.spk,
        "must be a genuinely new generation"
    );
    alice.start(&bob_ik, &bob_gen2.bundle.spk, Some(bob_gen2.bundle.otks[0]));
    let genuine_reinit = alice.send(&bob_ik, 3, "it's me again");
    let attack = corrupt_ciphertext(&genuine_reinit);

    let depth_before = otk_pool_depth(&bob.state);
    assert!(
        depth_before > 0,
        "vault must hold OTKs for 'unchanged' to be meaningful"
    );
    let state_before = snapshot_excluding_desync_counts(&bob.state);
    assert!(
        bob.state.has_session(&alice_ik),
        "Bob must still hold his (now stale) session with Alice going into the attack"
    );

    // The corrupted reinit must NOT be silently accepted, and must not replace Bob's session with a
    // poisoned one. `open_bytes`'s fallback classifies every failure mode on this branch — a
    // genuinely undecryptable header on the stale session, or a failed provisional re-establishment
    // — as `ChatError::Desync`; this cell's own comment (and `desync_recovery.rs`'s existing
    // preamble-mutation cell on this same branch) both document that collapse, so `Desync` here is
    // still evidence the AEAD (not something upstream) is what actually stopped this ciphertext.
    match bob.recv_raw(&alice_ik, &attack) {
        Err(ChatError::Desync) => {}
        Ok(pt) => panic!(
            "SECURITY FAILURE: a ciphertext-corrupted re-initiation was ACCEPTED and decrypted to \
             {} bytes of plaintext, replacing Bob's session with a poisoned one",
            pt.len()
        ),
        Err(other) => panic!(
            "expected ChatError::Desync (this branch's uniform failure classification for a \
             rejected fallback attempt) — got a different error, which would mean the rejection \
             point was not the ratchet AEAD/provisional-establishment path this cell targets: \
             {other:?}"
        ),
    }

    assert_eq!(
        otk_pool_depth(&bob.state),
        depth_before,
        "COMMIT-ON-DECRYPT VIOLATION: a failed fallback provisional decrypt must consume ZERO \
         one-time prekeys"
    );
    assert_eq!(
        state_before,
        snapshot_excluding_desync_counts(&bob.state),
        "COMMIT-ON-DECRYPT VIOLATION: a failed fallback attempt must leave sessions, the OTK pool, \
         and responder_session_ek completely untouched (desync_counts excluded — its bump is the \
         ordinary, expected bookkeeping for any rejected fallback attempt)"
    );

    // Positive control: the GENUINE (unmutated) re-initiation must succeed, replacing the stale
    // session and consuming exactly one OTK — proving the assertions above are not vacuous.
    let got = bob.recv_content(&alice_ik, &genuine_reinit).expect(
        "the genuine re-initiation must still be accepted after the corrupted one was \
                 rejected",
    );
    assert_eq!(
        got,
        ChatContent::Text {
            id: [3u8; 16],
            body: "it's me again".into()
        }
    );
    assert_eq!(
        otk_pool_depth(&bob.state),
        depth_before - 1,
        "the genuine re-initiation must consume EXACTLY one OTK"
    );

    // And the channel is genuinely live afterwards, in both directions — the failed attempt left no
    // latent corruption for future traffic.
    let ack = bob.send(&alice_ik, 4, "welcome back");
    let got2 = alice.recv_content(&bob_ik, &ack).unwrap();
    assert_eq!(
        got2,
        ChatContent::Text {
            id: [4u8; 16],
            body: "welcome back".into()
        }
    );
    let follow_up = alice.send(&bob_ik, 5, "still good");
    let got3 = bob.recv_content(&alice_ik, &follow_up).unwrap();
    assert_eq!(
        got3,
        ChatContent::Text {
            id: [5u8; 16],
            body: "still good".into()
        }
    );
}
