//! Task 5.5 (review finding F5) — `P2pSession::recover_from_desync`'s own receive-side wiring
//! (`cargo nextest run -p meridian-core --test session`, this file's own target name per the task
//! file). Closes the gap review finding F5 named: before this task, `apps/core/src/session.rs` held
//! zero `TrustStore`/`can_send` references at all, so `TrustStore::can_send`'s fail-open for
//! unknown/unobserved contacts meant a MITM against an **already-established P2P session** went
//! undetected outside `meridian chat`'s relay path.
//!
//! **Scope, precisely (mirrors `apps/core/tests/desync_recovery.rs`'s own scope note).** This does
//! *not* re-test `TrustStore::observe_key_change`/`can_send`'s own state-transition logic —
//! `apps/core/tests/key_change_gate.rs` (task 4.4) and `apps/core/tests/desync_recovery.rs` (task
//! 4.9/4.10) already own and prove that at the core-module level. This file proves the one thing
//! those files structurally cannot: that `P2pSession` — a **real** dial/answer handshake over
//! `LoopbackTransport`, not a bare `ChatState`/`TrustStore` pair — now actually wires that
//! already-correct machinery into its own receive-side desync path via
//! `P2pSession::recover_from_desync`, and that a key substitution surfaced through it is detected
//! and blocked exactly like the CLI's own `apps/cli/src/chat.rs::maybe_attempt_recovery` /
//! `meridian_core::desync::attempt_recovery` — not merely "the gate function itself is correct in
//! isolation".
//!
//! **Why the desync itself is forced directly against `ChatState`, not driven over the live P2P
//! data channel.** `P2pSession` has no raw-channel-send escape hatch by design (every outbound frame
//! goes through `chat.seal_outbound`/`seal_bytes` — see `send_chat`/`send_chat_content`), so there is
//! no way to inject a mangled ratchet frame through the transport without reaching into private
//! fields. `recover_from_desync`'s own contract only cares that
//! `ChatState::recovery_recommended` reads `true` for this session's peer — it does not care *how*
//! the desync counter got there — so forcing it via the same `mangle` technique
//! `desync_recovery.rs`/`chat_manager.rs` already use, directly against the session's own `ChatState`,
//! is the honest, minimal way to reach that precondition while still exercising the method under a
//! **real, already-established** `P2pSession` (real dial/answer, real DTLS-fingerprint-equivalent
//! loopback handshake, real `mrd.chat/1` message exchange beforehand and — the substrate-integrity
//! half of this file's own proof — afterward).
//!
//! **Why the substituted-key bundle is handed to `recover_from_desync` directly, never fetched over
//! a live `SignalingClient`.** Mirrors `crate::desync::attempt_recovery`'s own doc comment precisely:
//! a real fetch pins the returned bundle's signature to the *exact requested* key
//! (`meridian_signaling::verify_bundle`), so a genuine on-the-wire substitution against an already
//! -known peer fails closed at that fetch, structurally before `recover_from_desync` is ever reached
//! — `apps/cli/tests/mitm_preexisting_contact.rs` already proves that half over a real network. What
//! remains to prove — and what this file proves — is that *if* a caller's fetch strategy ever did
//! resolve to a different key (a future hint/directory lookup, or T13 multi-device), the substrate's
//! own gate still catches it, never silently completing a session on the caller's behalf.

use std::sync::Arc;

use meridian_core::chat::{ChatError, ChatState, DESYNC_RECOVERY_THRESHOLD};
use meridian_core::desync::RecoveryOutcome;
use meridian_core::envelope::{ChatContent, MessageEnvelope};
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionError, SessionEvent};
use meridian_core::signaling::generate_bundle;
use meridian_core::streams::StreamRegistry;
use meridian_core::transport::{LoopbackFabric, LoopbackTransport};
use meridian_core::trust::{SendGate, TrustState, TrustStore};

const TEST_NOW_UNIX: u64 = 1_700_000_000;

struct Peer {
    store: MemorySecretStore,
    account: AccountId,
    chat: ChatState,
}

impl Peer {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).expect("account");
        Self {
            store,
            account,
            chat: ChatState::default(),
        }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
    fn handle(&self) -> KeyHandle {
        self.account.handle().clone()
    }
    /// Seal a legitimate outbound message under this peer's own live session — used both for the
    /// ordinary before/after health checks and as raw material for [`mangle`].
    fn seal(&mut self, to: &[u8; 32], id: u8, body: &str) -> Vec<u8> {
        let ik = self.ik();
        self.chat
            .seal_outbound(
                &self.store,
                &self.handle(),
                &ik,
                to,
                &ChatContent::Text {
                    id: [id; 16],
                    body: body.to_string(),
                },
            )
            .expect("seal_outbound")
    }
}

/// Mirrors `apps/core/tests/desync_recovery.rs::mangle` exactly: corrupt an envelope's ratchet
/// header (a byte inside `enc_header`, past the 2-byte length prefix). Envelope v2 has no signature
/// to preserve — `sender_pub`/routing `from` are untouched, so the mangled bytes reach the ratchet
/// unchanged and come back undecryptable (`ChatError::Desync`), never a forged sender.
fn mangle(blob: &[u8]) -> Vec<u8> {
    let mut env = MessageEnvelope::from_blob(blob).expect("decode envelope");
    env.ct[2] ^= 0xFF;
    env.to_blob().expect("encode envelope")
}

/// Establishes a real T03 ratchet (Alice initiator, Bob responder) then a real T04 P2P session over
/// `LoopbackTransport` — the exact `dial`/`answer` pair every production caller of this substrate
/// uses, not a hand-rolled stand-in.
async fn establish() -> (
    P2pSession<LoopbackTransport>,
    P2pSession<LoopbackTransport>,
    Peer,
    Peer,
) {
    let mut alice = Peer::new("session5-5.a");
    let mut bob = Peer::new("session5-5.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    let bundle = generate_bundle(&bob.store, &bob.handle(), bob_ik, 5).expect("bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = bundle
        .bundle
        .otks
        .iter()
        .zip(bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.chat
        .vault
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks, TEST_NOW_UNIX);
    alice
        .chat
        .start_initiator_session(
            &alice.store,
            &alice.handle(),
            &alice_ik,
            &bob_ik,
            &bundle.bundle.spk,
            bundle.bundle.otks.first().copied(),
        )
        .expect("start_initiator_session");

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::with_scenario(
        fabric.clone(),
        Default::default(),
    ));
    let tb = Arc::new(LoopbackTransport::with_scenario(
        fabric.clone(),
        Default::default(),
    ));
    let (mut relay_a, mut relay_b) = MemRelay::pair(alice_ik, bob_ik);
    let (ahandle, bhandle) = (alice.handle(), bob.handle());
    let (achat, bchat) = (&mut alice.chat, &mut bob.chat);
    let (ra, rb) = tokio::join!(
        dial(
            ta,
            &alice.store,
            &ahandle,
            alice_ik,
            bob_ik,
            achat,
            &mut relay_a,
            Arc::new(StreamRegistry::with_builtins()),
        ),
        answer(
            tb,
            &bob.store,
            &bhandle,
            bob_ik,
            alice_ik,
            bchat,
            &mut relay_b,
            Arc::new(StreamRegistry::with_builtins()),
        ),
    );
    let asess = ra.expect("dial");
    let bsess = rb.expect("answer");
    (asess, bsess, alice, bob)
}

/// Alice → Bob's opening message is Bob's genuine first P2P contact with Alice (task 2.14's gate) —
/// pump it through and accept, exactly like `apps/core/tests/p2p_session.rs`'s own
/// `accept_first_p2p_message`, so both sides land on a real, live, two-way-confirmed session before
/// this file's own desync/recovery scenario begins.
async fn open_and_confirm(
    asess: &mut P2pSession<LoopbackTransport>,
    bsess: &mut P2pSession<LoopbackTransport>,
    alice: &mut Peer,
    bob: &mut Peer,
) {
    let (ahandle, bhandle) = (alice.handle(), bob.handle());
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hello over p2p")
        .await
        .expect("alice send");
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Err(SessionError::Chat(ChatError::MessageRequest)) => {
            bob.chat
                .accept_request(&alice.ik())
                .expect("open_inbound_gated inserted a request");
        }
        other => panic!("expected a gated first-contact message request, got {other:?}"),
    }
    bsess
        .send_chat(&bob.store, &bhandle, &mut bob.chat, "hi back")
        .await
        .expect("bob send");
    match asess.pump(&alice.store, &ahandle, &mut alice.chat).await {
        Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
            assert_eq!(body, "hi back");
        }
        other => panic!("expected alice's reply pump to decode bob's text, got {other:?}"),
    }
}

/// Drives `DESYNC_RECOVERY_THRESHOLD` consecutive, authentically-signed-but-undecryptable envelopes
/// from `bob` into `alice.chat` directly (see this file's own module doc for why this bypasses the
/// live transport rather than reaching into `P2pSession`'s private fields), asserting each one
/// classifies as `Desync` and that the threshold has not fired early.
fn force_desync_threshold(alice: &mut Peer, bob: &mut Peer) {
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    for i in 0..DESYNC_RECOVERY_THRESHOLD {
        assert!(
            !alice.chat.recovery_recommended(&bob_ik),
            "must not fire before the threshold (iteration {i})"
        );
        let noise = bob.seal(&alice_ik, (200 + i) as u8, "noise");
        let mangled = mangle(&noise);
        let err = alice
            .chat
            .open_inbound(&alice.store, &alice.handle(), &alice_ik, &bob_ik, &mangled)
            .expect_err("a mangled-but-authentic envelope must not decode");
        assert!(
            matches!(err, ChatError::Desync),
            "iteration {i} must classify as Desync, got {err:?}"
        );
    }
    assert!(alice.chat.recovery_recommended(&bob_ik));
}

// -------------------------------------------------------------------------------------------------
// Boundary: below the threshold, recover_from_desync is a true no-op
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn recover_from_desync_is_a_noop_below_the_threshold_and_touches_nothing() {
    let (asess, _bsess, mut alice, mut bob) = establish().await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "session5-5.b", TEST_NOW_UNIX);
    let before_trust = format!("{trust:?}");

    // Only DESYNC_RECOVERY_THRESHOLD - 1 forced desyncs — never crosses the threshold.
    for i in 0..DESYNC_RECOVERY_THRESHOLD - 1 {
        let noise = bob.seal(&alice_ik, (10 + i) as u8, "noise");
        let mangled = mangle(&noise);
        let _ =
            alice
                .chat
                .open_inbound(&alice.store, &alice.handle(), &alice_ik, &bob_ik, &mangled);
    }
    assert!(!alice.chat.recovery_recommended(&bob_ik));

    let alice_handle = alice.handle();
    let outcome = asess
        .recover_from_desync(
            &mut alice.chat,
            &mut trust,
            &alice.store,
            &alice_handle,
            &bob_ik,
            &[0x11u8; 32],
            None,
            "session5-5.b",
            TEST_NOW_UNIX + 1,
        )
        .expect("no error below the threshold");
    assert_eq!(outcome, None, "must be a no-op below the threshold");
    assert_eq!(
        format!("{trust:?}"),
        before_trust,
        "trust must be byte-identical when recovery is not even recommended yet"
    );
}

// -------------------------------------------------------------------------------------------------
// The flagship proof: a substituted key against an established P2P session is detected and blocked
// -------------------------------------------------------------------------------------------------

/// The canonical wording (`docs/security/verification-ux.md`) must, in substance, name the safety
/// number, the benign explanation, the interception possibility, and offer verification — mirrors
/// `apps/core/tests/desync_recovery.rs::assert_canonical_substance` exactly (same reasoning: the
/// only other call site, not worth a shared test-support crate for one reuse).
fn assert_canonical_substance(reason: &str) {
    let lower = reason.to_lowercase();
    assert!(lower.contains("safety number"), "{reason}");
    assert!(
        lower.contains("reinstalled") || lower.contains("switched devices"),
        "{reason}"
    );
    assert!(lower.contains("intercept"), "{reason}");
    assert!(lower.contains("verify"), "{reason}");
}

#[tokio::test]
async fn recover_from_desync_warns_and_blocks_a_key_substitution_against_a_pinned_established_session(
) {
    let (mut asess, mut bsess, mut alice, mut bob) = establish().await;
    open_and_confirm(&mut asess, &mut bsess, &mut alice, &mut bob).await;
    let bob_ik = bob.ik();

    force_desync_threshold(&mut alice, &mut bob);

    // Alice has an ordinary, TOFU-pinned (not yet verified) trust record for Bob.
    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "session5-5.b", TEST_NOW_UNIX);
    assert_eq!(trust.can_send(&bob_ik), SendGate::Ok);

    // THE ATTACK: the "fresh bundle" handed to recovery is genuinely signed under Mallory's key, not
    // Bob's — exactly the shape a substituting fetch strategy would hand this method (see this
    // file's own module doc for why a *live* fetch can never reach this in practice today).
    let mallory = Peer::new("session5-5.m");
    let mallory_ik = mallory.ik();
    let mallory_gen =
        generate_bundle(&mallory.store, &mallory.handle(), mallory_ik, 5).expect("mallory bundle");

    let alice_handle = alice.handle();
    let outcome = asess
        .recover_from_desync(
            &mut alice.chat,
            &mut trust,
            &alice.store,
            &alice_handle,
            &mallory_ik,
            &mallory_gen.bundle.spk,
            mallory_gen.bundle.otks.first().copied(),
            "session5-5.b",
            TEST_NOW_UNIX + 1,
        )
        .expect("gated outcomes are Ok, never an Err");

    let reason = match outcome {
        Some(RecoveryOutcome::Gated(SendGate::Warn(reason))) => reason,
        other => panic!(
            "a substituted key against a pinned contact must WARN, never silently succeed or hard-\
             block outright: {other:?}"
        ),
    };
    assert_canonical_substance(&reason);
    assert_eq!(trust.trust_state(&mallory_ik), TrustState::PinnedKeyChanged);
    assert!(
        !alice.chat.has_session(&mallory_ik),
        "no session may be installed under the substituted key while gated"
    );

    // The live, already-established P2P session with the REAL Bob is completely unaffected: it can
    // still exchange a genuine message afterward, over the real transport, proving the attempted
    // (and refused) recovery touched nothing about the actual conversation.
    bsess
        .send_chat(&bob.store, &bob.handle(), &mut bob.chat, "still here")
        .await
        .expect("bob send after the refused recovery attempt");
    match asess
        .pump(&alice.store, &alice.handle(), &mut alice.chat)
        .await
    {
        Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
            assert_eq!(body, "still here");
        }
        other => panic!(
            "the real, established session with Bob must still be perfectly healthy after the \
             refused substituted-key recovery attempt: {other:?}"
        ),
    }
}

#[tokio::test]
async fn recover_from_desync_hard_blocks_a_key_substitution_against_a_verified_established_session()
{
    let (mut asess, _bsess, mut alice, mut bob) = establish().await;
    // Bob's own first-contact gate isn't needed for this scenario: only Alice's inbound desync
    // detection and Alice's own trust decision matter here, mirroring
    // `desync_recovery.rs`'s Case 2 (`attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it`).
    let bob_ik = bob.ik();
    // Alice needs *something* to have already sent, so a session genuinely exists to "recover".
    let _ = asess
        .send_chat(&alice.store, &alice.handle(), &mut alice.chat, "hi")
        .await;

    force_desync_threshold(&mut alice, &mut bob);

    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "session5-5.b", TEST_NOW_UNIX);
    trust.mark_verified(&bob_ik).expect("known contact");

    let mallory = Peer::new("session5-5.m2");
    let mallory_ik = mallory.ik();
    let mallory_gen =
        generate_bundle(&mallory.store, &mallory.handle(), mallory_ik, 5).expect("mallory bundle");

    let alice_handle = alice.handle();
    let outcome = asess
        .recover_from_desync(
            &mut alice.chat,
            &mut trust,
            &alice.store,
            &alice_handle,
            &mallory_ik,
            &mallory_gen.bundle.spk,
            mallory_gen.bundle.otks.first().copied(),
            "session5-5.b",
            TEST_NOW_UNIX + 1,
        )
        .expect("gated outcomes are Ok, never an Err");

    let reason = match outcome {
        Some(RecoveryOutcome::Gated(SendGate::Blocked(reason))) => reason,
        other => panic!(
            "a substituted key against a VERIFIED contact must hard-BLOCK, never merely warn or — \
             worse — silently recover: {other:?}"
        ),
    };
    assert_canonical_substance(&reason);
    assert_eq!(trust.trust_state(&mallory_ik), TrustState::Blocked);
    assert!(
        !alice.chat.has_session(&mallory_ik),
        "no session may be installed under the substituted key while blocked"
    );

    // No bypass: the pinned-case escape hatch cannot clear a verified-contact key-change block
    // either, even reached this way (mirrors `desync_recovery.rs`'s own adversarial check).
    let err = trust
        .acknowledge_key_change(&mallory_ik)
        .expect_err("acknowledging a Blocked (verified) key change must be a hard error");
    assert!(matches!(
        err,
        meridian_core::trust::TrustError::NotAcknowledgeable
    ));
}

// -------------------------------------------------------------------------------------------------
// Positive control: an unresolved key change already on file for this session's own peer refuses an
// automatic re-handshake outright — `recover_from_desync` never bypasses `can_send`'s early gate even
// when no substitution is involved at all.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn recover_from_desync_refuses_outright_when_the_sessions_own_peer_is_already_blocked() {
    let (mut asess, mut bsess, mut alice, mut bob) = establish().await;
    open_and_confirm(&mut asess, &mut bsess, &mut alice, &mut bob).await;
    let bob_ik = bob.ik();

    force_desync_threshold(&mut alice, &mut bob);

    // Bob himself (not a substituted third party) is already `Blocked` from a prior, unrelated
    // key-change incident — mirrors `apps/core/tests/desync_recovery.rs`'s own
    // `stand_in_prior_key` pattern for constructing a real, already-blocked contact record keyed
    // exactly at the peer this session is talking to.
    let mut trust = TrustStore::default();
    let stand_in_prior_key = [0xABu8; 32];
    trust.observe(stand_in_prior_key, "session5-5.b", TEST_NOW_UNIX);
    trust
        .mark_verified(&stand_in_prior_key)
        .expect("known contact");
    trust
        .observe_key_change(
            &stand_in_prior_key,
            bob_ik,
            "session5-5.b",
            TEST_NOW_UNIX + 1,
        )
        .expect("known contact, distinct new key");
    assert_eq!(trust.trust_state(&bob_ik), TrustState::Blocked);

    let alice_handle = alice.handle();
    let outcome = asess
        .recover_from_desync(
            &mut alice.chat,
            &mut trust,
            &alice.store,
            &alice_handle,
            &bob_ik, // the bundle owner IS bob_ik here — no substitution, bob genuinely republished
            &[0x22u8; 32],
            None,
            "session5-5.b",
            TEST_NOW_UNIX + 2,
        )
        .expect("gated outcomes are Ok, never an Err");

    match outcome {
        Some(RecoveryOutcome::Gated(SendGate::Blocked(_))) => {}
        other => panic!(
            "an automatic re-handshake must never be layered on top of an already-unresolved \
             key-change block, even for the session's own genuine peer: {other:?}"
        ),
    }
    assert!(!alice.chat.has_session(&[0x22u8; 32]));
}

// -------------------------------------------------------------------------------------------------
// The genuine success path (test-engineer review finding): none of the four tests above ever call
// `recover_from_desync` with `bundle_owner_ik == peer_ik` (the real, non-adversarial peer) and a
// clean `can_send` — the ordinary, everyday case this whole receive-side recovery path exists for.
// Proves the wrapper actually completes a real re-handshake, not merely that it correctly refuses in
// every adversarial/gated shape.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn recover_from_desync_actually_recovers_against_the_genuine_peer_with_a_clean_can_send() {
    let (mut asess, mut bsess, mut alice, mut bob) = establish().await;
    open_and_confirm(&mut asess, &mut bsess, &mut alice, &mut bob).await;
    let bob_ik = bob.ik();

    force_desync_threshold(&mut alice, &mut bob);

    // Alice's trust record for Bob is an ordinary, healthy TOFU-pinned contact — `can_send` reads
    // `Ok`, the everyday, non-adversarial case.
    let mut trust = TrustStore::default();
    trust.observe(bob_ik, "session5-5.b", TEST_NOW_UNIX);
    assert_eq!(trust.can_send(&bob_ik), SendGate::Ok);

    // Bob genuinely republishes a fresh bundle — the ordinary, non-key-change case:
    // `bundle_owner_ik == peer_ik`, mirroring `apps/core/tests/desync_recovery.rs`'s own
    // `repeated_desync_triggers_guarded_recovery_and_restores_the_session_end_to_end`.
    let bob_gen2 =
        generate_bundle(&bob.store, &bob.handle(), bob_ik, 5).expect("bob's fresh bundle");
    let otks2: Vec<([u8; 32], [u8; 32])> = bob_gen2
        .bundle
        .otks
        .iter()
        .zip(bob_gen2.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.chat.vault.set_bundle(
        bob_gen2.bundle.spk,
        *bob_gen2.spk_secret,
        otks2,
        TEST_NOW_UNIX + 1,
    );

    let alice_handle = alice.handle();
    let outcome = asess
        .recover_from_desync(
            &mut alice.chat,
            &mut trust,
            &alice.store,
            &alice_handle,
            &bob_ik, // bundle_owner_ik == peer_ik: the ordinary, non-key-change case
            &bob_gen2.bundle.spk,
            bob_gen2.bundle.otks.first().copied(),
            "session5-5.b",
            TEST_NOW_UNIX + 2,
        )
        .expect("recovery against the genuine peer must never error");

    assert_eq!(
        outcome,
        Some(RecoveryOutcome::Recovered),
        "recover_from_desync must actually complete a fresh re-handshake on the ordinary, \
         non-gated success path — not merely refuse in every adversarial shape"
    );
    assert_eq!(
        alice.chat.desync_count(&bob_ik),
        0,
        "an attempted recovery resets the desync counter regardless of outcome"
    );
    assert_eq!(
        trust.trust_state(&bob_ik),
        TrustState::Pinned,
        "recovering against the genuine, non-substituted peer must never touch trust state"
    );

    // The channel is genuinely live again, end to end, over the real P2P transport: Alice's freshly
    // re-initiated session reaches Bob — who still holds the old, now-stale session, exactly like
    // `ChatState::open_bytes`'s existing "accept a fresh reinitiation despite a stale session"
    // contract — and Bob's reply decodes cleanly back through the same live `asess`/`bsess` pair
    // used throughout this test.
    asess
        .send_chat(&alice.store, &alice_handle, &mut alice.chat, "recovered!")
        .await
        .expect("alice send over the freshly re-initiated session");
    let bob_handle = bob.handle();
    match bsess.pump(&bob.store, &bob_handle, &mut bob.chat).await {
        Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
            assert_eq!(body, "recovered!");
        }
        other => panic!(
            "bob must accept the fresh re-initiation despite holding a stale session: {other:?}"
        ),
    }
    bsess
        .send_chat(&bob.store, &bob_handle, &mut bob.chat, "welcome back")
        .await
        .expect("bob send");
    match asess
        .pump(&alice.store, &alice_handle, &mut alice.chat)
        .await
    {
        Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
            assert_eq!(body, "welcome back");
        }
        other => panic!("the channel must be genuinely live again in both directions: {other:?}"),
    }
}
