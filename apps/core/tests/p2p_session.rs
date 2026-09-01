//! T04 acceptance harness for the P2P session substrate
//! (docs/architecture/features/04-p2p-session-substrate.md).
//!
//! Drives two peers over a shared [`LoopbackFabric`] and an in-memory signaling relay, proving the
//! spec's criteria deterministically in CI (the netns rig exercises the same substrate over the
//! webrtc-rs backend across real NATs):
//!   * **server-down chat continuity** — establish P2P, drop the relay, chat keeps flowing;
//!   * **fingerprint mismatch tears down 100%** of the time (§4.6), forced at the DTLS layer;
//!   * the inner SDP rides opaque inside the encrypted envelope, so a relay touching only the
//!     *outer* routing cannot read or forge it (an active relay-rewrite attack against a real
//!     backend is not yet exercised here — tracked for 1.28, flagged during 1.23's split);
//!   * **capability exchange rejects unknown mandatory stream types gracefully**;
//!   * **ICE restart** on a network change keeps the session and ratchet alive (<5 s, invariant 5);
//!   * (1.33) the dialer's wait for an answer is **bounded**: a peer that never answers (offline, or
//!     a hostile relay that lets the responder reject without ever producing one — 1.28) times out
//!     with a distinct, diagnosable `SessionError::AnswerTimeout` rather than hanging forever;
//!   * (2.17) the mirror on the answerer's side: `answer`'s wait for an offer is **bounded** too — a
//!     dialer that never offers (offline, or, since federation, a route rejected server-side before
//!     any offer reaches the answering side at all) times out with a distinct, diagnosable
//!     `SessionError::OfferTimeout` rather than hanging forever.

use std::sync::Arc;

/// Fixed wall clock for `PrekeyVault::set_bundle` (task 1.31 takes time as a parameter rather than
/// reading a clock, so `meridian-core` stays wasm-safe). These tests publish exactly one bundle
/// generation, so any fixed value works — the generation-rotation/expiry behaviour itself is covered
/// by `chat_manager.rs`.
const TEST_NOW_UNIX: u64 = 1_700_000_000;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::{ChatContent, SignalContent};
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::relay;
use meridian_core::session::{
    answer, answer_with_config, dial, dial_with_config, MemRelay, P2pSession, SessionError,
    SessionEvent, SignalRelay,
};
use meridian_core::signaling::generate_bundle;
use meridian_core::streams::{register_stream_type, StreamRegistry, StreamType};
use meridian_core::transport::Result as TransportResult;
use meridian_core::transport::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, IceServer,
    LoopbackFabric, LoopbackTransport, MediaKind, Path, Sdp, SessionHandle, TrackId, Transport,
};

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
}

/// Establish the T03 ratchet between Alice (initiator) and Bob (responder) exactly as chat does:
/// Bob publishes a bundle (vault set), Alice starts an initiator session against it. The P2P offer
/// then rides the X3DH preamble like any first message.
fn establish_ratchet(alice: &mut Peer, bob: &mut Peer) {
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
        .expect("start session");
}

/// Run dial+answer concurrently and return the two established sessions (or the pair of results).
async fn connect<T: meridian_core::transport::Transport>(
    ta: Arc<T>,
    tb: Arc<T>,
    alice: &mut Peer,
    bob: &mut Peer,
    reg_a: Arc<StreamRegistry>,
    reg_b: Arc<StreamRegistry>,
) -> (
    Result<P2pSession<T>, SessionError>,
    Result<P2pSession<T>, SessionError>,
) {
    let (mut relay_a, mut relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let (astore, ahandle) = (&alice.store, alice.handle());
    let (bstore, bhandle) = (&bob.store, bob.handle());
    let achat = &mut alice.chat;
    let bchat = &mut bob.chat;
    tokio::join!(
        dial(
            ta,
            astore,
            &ahandle,
            alice_ik,
            bob_ik,
            achat,
            &mut relay_a,
            reg_a,
        ),
        answer(
            tb,
            bstore,
            &bhandle,
            bob_ik,
            alice_ik,
            bchat,
            &mut relay_b,
            reg_b,
        ),
    )
}

/// (task 2.14) Pump `sess`'s **first-ever** `mrd.chat/1` content frame through the message-request
/// gate and accept it, asserting the held intro matches `expected_body` — the substrate-level
/// counterpart of a CLI user answering "y" to `chat.rs`'s "message request from … — accept? y/n"
/// prompt (task 2.10). `establish_ratchet` only ever sets up Bob's X3DH *vault*, never a session
/// entry for Alice, so — mirroring the real `session_connect` flow, whose `ChatState` is fresh per
/// invocation — every test in this file that has Bob receive Alice's opening message needs this
/// once before its own (unrelated) assertions continue. `p2p_first_contact_is_gated_*` below is
/// what actually pins the gate's own behavior end to end.
async fn accept_first_p2p_message<T: meridian_core::transport::Transport>(
    sess: &mut P2pSession<T>,
    store: &MemorySecretStore,
    handle: &KeyHandle,
    chat: &mut ChatState,
    peer_ik: &[u8; 32],
    expected_body: &str,
) {
    match sess.pump(store, handle, chat).await {
        Err(SessionError::Chat(ChatError::MessageRequest)) => {}
        other => panic!(
            "expected the first P2P chat frame to be gated as a message request, got {other:?}"
        ),
    }
    let req = chat
        .pending_request(peer_ik)
        .expect("gated first contact must be held in pending_requests");
    match &req.intro {
        ChatContent::Text { body, .. } => assert_eq!(body, expected_body),
        other => panic!("unexpected intro content: {other:?}"),
    }
    let accepted = chat
        .accept_request(peer_ik)
        .expect("accept the pending request");
    match accepted.intro {
        ChatContent::Text { body, .. } => assert_eq!(body, expected_body),
        other => panic!("unexpected accepted intro: {other:?}"),
    }
}

#[tokio::test]
async fn server_down_chat_continuity() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.expect("dial established");
    let mut bsess = rb.expect("answer established");

    // Fingerprints are bound and agree (§4.6 passed).
    let (a_local, a_remote) = asess.fingerprints();
    let (b_local, b_remote) = bsess.fingerprints();
    assert_eq!(
        a_local, b_remote,
        "alice local fp == bob's negotiated remote"
    );
    assert_eq!(
        b_local, a_remote,
        "bob local fp == alice's negotiated remote"
    );

    // Both advertised chat as mandatory and it opened.
    assert!(asess
        .peer_capabilities()
        .iter()
        .any(|s| s.name == "mrd.chat/1"));

    // The headline demo: the relay (MemRelay) is already dropped inside `connect`. Chat now flows
    // peer-to-peer over the data channel with NO server in the path.
    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // Alice -> Bob. This is Bob's first-ever P2P content from Alice, so it is gated (task 2.14) —
    // accept it (mirroring the CLI's accept/reject UX) before the test's actual subject: continuity
    // once the relay is gone.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hello over p2p")
        .await
        .unwrap();
    accept_first_p2p_message(
        &mut bsess,
        &bob.store,
        &bhandle,
        &mut bob.chat,
        &alice.ik(),
        "hello over p2p",
    )
    .await;

    // Bob -> Alice.
    bsess
        .send_chat(&bob.store, &bhandle, &mut bob.chat, "hi back, no server")
        .await
        .unwrap();
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "hi back, no server");
        }
        other => panic!("alice expected chat, got {other:?}"),
    }

    // A keepalive round-trips over ctrl (drives the >=30-min continuity mechanism), measured with
    // both sides pumping concurrently.
    let (ping, _pumped) = {
        let ahandle = alice.handle();
        let bhandle = bob.handle();
        let a = asess.ping(&alice.store, &ahandle, &mut alice.chat);
        let b = bsess.pump(&bob.store, &bhandle, &mut bob.chat);
        tokio::join!(a, b)
    };
    assert!(ping.unwrap() >= 0.0);

    let info = asess.info().await;
    assert_eq!(info.transport, "loopback");
    assert!(info.streams.iter().any(|s| s == "mrd.ctrl/1"));
    assert!(info.streams.iter().any(|s| s == "mrd.chat/1"));
}

#[tokio::test]
async fn fingerprint_mismatch_tears_down() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    // Both peers are behind a MITM that terminated DTLS: each negotiates a fingerprint that differs
    // from the identity-asserted one. The §4.6 cross-check MUST tear both sides down before any
    // content flows — 100% of the time.
    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new_mitm(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new_mitm(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;

    match ra {
        Err(SessionError::FingerprintMismatch { .. }) => {}
        Err(e) => panic!("dial: expected fp mismatch, got {e}"),
        Ok(_) => panic!("dial must fail closed on fingerprint mismatch"),
    }
    match rb {
        Err(SessionError::FingerprintMismatch { .. }) => {}
        Err(e) => panic!("answer: expected fp mismatch, got {e}"),
        Ok(_) => panic!("answer must fail closed on fingerprint mismatch"),
    }
}

/// 1.33: `recv_sdp`'s wait for the answer is bounded. Reproduces the reachable-with-no-adversary
/// case named in the task — a peer that simply never answers — with the minimum setup that proves
/// it: only Bob's *receiving* half of the relay pair exists; nothing ever sends a reply down it, so
/// `dial`'s wait for an answer would hang forever without 1.33's bound. `answer`/Bob's side is never
/// even run, which is the point: this isolates the dialer's own bound from any responder behavior
/// (in scope for 1.33) rather than re-driving the full 1.28 relay-rewrite scenario (out of scope).
// `start_paused = true`: 1.33 raised `ANSWER_TIMEOUT` to 30s (architect review — it must exceed the
// responder's own ~20s-bounded ICE gather, not undercut it), which would otherwise make this test
// really wait 30 real seconds. Tokio's paused virtual clock auto-advances to the next pending timer
// once every other task is blocked, so `dial`'s internal `tokio::time::timeout(ANSWER_TIMEOUT, ..)`
// still fires for real, just without the test burning 30 real seconds. `tokio::time::Instant` (not
// `std::time::Instant`) is used for the elapsed-time assertions below so they measure the same
// virtual clock the timeout itself runs on.
#[tokio::test(start_paused = true)]
async fn dial_times_out_when_the_peer_never_answers() {
    let mut alice = Peer::new("dialer");
    let mut bob = Peer::new("silent");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric));
    let registry = Arc::new(StreamRegistry::with_builtins());

    // `relay_a` can send (Bob's queue just accumulates, undrained) but nothing ever writes back
    // into it, so `relay_a.recv()` — what `recv_sdp` awaits — never resolves on its own.
    let (mut relay_a, _relay_b_unused) = MemRelay::pair(alice.ik(), bob.ik());

    let start = tokio::time::Instant::now();
    let result = dial(
        ta,
        &alice.store,
        &alice.handle(),
        alice.ik(),
        bob.ik(),
        &mut alice.chat,
        &mut relay_a,
        registry,
    )
    .await;
    let elapsed = start.elapsed();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("dial must not succeed when the peer never answers"),
    };
    // Distinguishable from tampering (`Chat(ChatError::Crypto)` — a byte that *did* arrive but
    // failed the ratchet AEAD) and every other `SessionError` variant — that's the whole
    // diagnosability point of this task.
    assert!(
        matches!(err, SessionError::AnswerTimeout(_)),
        "expected SessionError::AnswerTimeout, got a different variant: {err}"
    );
    // Actually bounded — waited out (approximately) the configured window, not an unrelated
    // near-instant failure that would make the "distinct variant" assertion above vacuous.
    assert!(
        elapsed >= meridian_core::session::ANSWER_TIMEOUT,
        "returned after {elapsed:?}, before the {:?} bound elapsed",
        meridian_core::session::ANSWER_TIMEOUT
    );
    assert!(
        elapsed < meridian_core::session::ANSWER_TIMEOUT + std::time::Duration::from_secs(5),
        "returned after {elapsed:?}, far past the configured {:?} bound — some other, much longer \
         wait fired instead of the answer-timeout",
        meridian_core::session::ANSWER_TIMEOUT
    );
}

/// 2.17: `recv_sdp`'s wait for the offer, on the *answerer* side, is bounded too — the mirror of
/// 1.33's `dial_times_out_when_the_peer_never_answers` above, but for `answer`. Reproduces the
/// federation-era failure mode named in the task: a route can be rejected server-side (closed
/// policy, allowlist miss, rate limit) before any offer ever reaches the answering side, so nothing
/// is ever going to arrive on Bob's relay half — only Bob's *receiving* half of the relay pair
/// exists; nothing ever sends anything down it, so `answer`'s wait for an offer would hang forever
/// without 2.17's bound. Alice/the dialer side is never even run, isolating the answerer's own bound
/// exactly as 1.33's test isolated the dialer's.
#[tokio::test(start_paused = true)]
async fn answer_times_out_when_no_offer_ever_arrives() {
    let mut bob = Peer::new("silent-answerer");

    let fabric = LoopbackFabric::new();
    let tb = Arc::new(LoopbackTransport::new(fabric));
    let registry = Arc::new(StreamRegistry::with_builtins());

    // `_relay_a_unused` could send, but we never call `.send()` on it, so `relay_b.recv()` — what
    // `recv_sdp` awaits inside `answer` — never resolves on its own.
    let alice_ik = *generate_account(&MemorySecretStore::new(), "dialer-never-shows")
        .expect("account")
        .public_key()
        .as_bytes();
    let (_relay_a_unused, mut relay_b) = MemRelay::pair(alice_ik, bob.ik());

    let start = tokio::time::Instant::now();
    let result = answer(
        tb,
        &bob.store,
        &bob.handle(),
        bob.ik(),
        alice_ik,
        &mut bob.chat,
        &mut relay_b,
        registry,
    )
    .await;
    let elapsed = start.elapsed();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("answer must not succeed when no offer ever arrives"),
    };
    // Distinguishable from tampering (`Chat(ChatError::Crypto)`), from `AnswerTimeout` (the
    // opposite side of the handshake), and from every other `SessionError` variant.
    assert!(
        matches!(err, SessionError::OfferTimeout(_)),
        "expected SessionError::OfferTimeout, got a different variant: {err}"
    );
    assert!(
        elapsed >= meridian_core::session::OFFER_TIMEOUT,
        "returned after {elapsed:?}, before the {:?} bound elapsed",
        meridian_core::session::OFFER_TIMEOUT
    );
    assert!(
        elapsed < meridian_core::session::OFFER_TIMEOUT + std::time::Duration::from_secs(5),
        "returned after {elapsed:?}, far past the configured {:?} bound — some other, much longer \
         wait fired instead of the offer-timeout",
        meridian_core::session::OFFER_TIMEOUT
    );
}

// TODO(1.28, flagged during 1.23's split): replace with an active relay-rewrite attack
// test once the real transport backend lands.
#[tokio::test]
async fn relay_path_connects_healthily() {
    // NOTE: despite the surrounding commentary about SDP/fingerprint opacity, this test does not
    // mount an active relay-rewrite attack — it only proves a healthy connect over the loopback
    // transport yields matching, bound fingerprints. The real active-relay-rewrite attack (a
    // malicious relay actively substituting routing metadata or attempting to rewrite the inner
    // SDP) needs a real transport backend and is tracked for 1.28.
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    // Sanity: the loopback SDP the transport hands us is not chat plaintext, and the substrate never
    // routes it in the clear — proven by the opacity test below. Here we just confirm a healthy
    // connect still yields matching, bound fingerprints (the authentic path), which a routing-only
    // attacker cannot subvert.
    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let asess = ra.expect("established");
    let bsess = rb.expect("established");
    let (a_local, a_remote) = asess.fingerprints();
    let (b_local, b_remote) = bsess.fingerprints();
    assert_eq!(a_local, b_remote);
    assert_eq!(b_local, a_remote);
}

/// (task 2.14) The message-request gate now covers the P2P substrate too, closing the gap
/// `p2p_first_chat_content_is_not_yet_gated_known_gap_tracked_as_2_14` used to pin: a first-ever
/// P2P session's chat content lands in the segregated `pending_requests` state instead of
/// delivering (mirroring 2.10's relay-path gate, `ChatState::open_inbound`), a second envelope sent
/// before Bob answers is refused outright — never merged into the held request — and accepting
/// delivers the original intro, after which further content flows normally (not re-gated).
///
/// `session.rs`'s own `ChatState::open_inbound` can't detect this first contact itself (the
/// offer/answer handshake already installed Bob's responder session before any chat frame exists to
/// gate) — this test is what proves `P2pSession`'s own `chat_first_contact_gate` snapshot (taken
/// before that handshake ran) closes exactly that gap end to end, not just at the unit level.
#[tokio::test]
async fn p2p_first_contact_is_gated_second_envelope_refused_accept_delivers() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);
    let alice_ik = alice.ik();

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.expect("established");
    let mut bsess = rb.expect("established");

    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // First content frame: gated, not delivered.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hello over p2p")
        .await
        .unwrap();
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Err(SessionError::Chat(ChatError::MessageRequest)) => {}
        other => panic!("expected the first P2P content frame to be gated, got {other:?}"),
    }
    let req = bob
        .chat
        .pending_request(&alice_ik)
        .expect("gated first contact held in pending_requests");
    assert!(
        !req.safety_number.is_empty(),
        "the held request must carry a safety number to show before accept/reject"
    );
    match &req.intro {
        ChatContent::Text { body, .. } => assert_eq!(body, "hello over p2p"),
        other => panic!("unexpected intro: {other:?}"),
    }

    // Second envelope arriving before Bob decides: refused outright, never merged into the held
    // request (task 2.10 invariant, preserved here).
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "are you there?")
        .await
        .unwrap();
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Err(SessionError::Chat(ChatError::RequestPending)) => {}
        other => panic!("expected the second pre-accept envelope to be refused, got {other:?}"),
    }
    let req = bob
        .chat
        .pending_request(&alice_ik)
        .expect("the original request must still be held, untouched");
    match &req.intro {
        ChatContent::Text { body, .. } => assert_eq!(body, "hello over p2p"),
        other => panic!("the held intro must not have been replaced: {other:?}"),
    }

    // Accept: delivers the original (first) intro.
    let accepted = bob
        .chat
        .accept_request(&alice_ik)
        .expect("accept the pending request");
    match accepted.intro {
        ChatContent::Text { body, .. } => assert_eq!(body, "hello over p2p"),
        other => panic!("unexpected accepted intro: {other:?}"),
    }

    // Post-accept: a fresh envelope now delivers normally — no re-gating.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "welcome back")
        .await
        .unwrap();
    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "welcome back");
        }
        other => panic!("post-accept delivery failed: {other:?}"),
    }
}

#[tokio::test]
async fn unknown_mandatory_capability_rejected_gracefully() {
    struct Exotic;
    impl StreamType for Exotic {
        fn name(&self) -> &'static str {
            "mrd.exotic/9"
        }
        fn version(&self) -> u16 {
            9
        }
        fn channel_cfg(&self) -> ChannelCfg {
            ChannelCfg::reliable_ordered("mrd.exotic/9")
        }
        fn direction(&self) -> meridian_core::envelope::Direction {
            meridian_core::envelope::Direction::Bidir
        }
        fn mandatory(&self) -> bool {
            true
        }
    }

    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    // Bob mandates a stream type Alice does not support. Alice must reject the session gracefully at
    // capability exchange — an error, never a panic — while Bob (who supports everything Alice
    // requires) completes.
    let mut bob_reg = StreamRegistry::with_builtins();
    register_stream_type(&mut bob_reg, Arc::new(Exotic));

    let (ra, _rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(bob_reg),
    )
    .await;

    match ra {
        Err(SessionError::Capability(_)) => {}
        Err(e) => panic!("alice: expected capability rejection, got {e}"),
        Ok(_) => panic!("alice must reject unknown mandatory capability"),
    }
}

#[tokio::test]
async fn ice_restart_preserves_session_and_ratchet() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.unwrap();
    let mut bsess = rb.unwrap();

    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // Send one message, then simulate a Wi-Fi->other-interface switch: ICE restarts, the ratchet is
    // untouched, and the next message decrypts on the SAME session (no re-handshake). This is Bob's
    // first-ever P2P content from Alice, so it's gated (task 2.14) — accept it before the ICE
    // restart this test actually exercises.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "before restart")
        .await
        .unwrap();
    accept_first_p2p_message(
        &mut bsess,
        &bob.store,
        &bhandle,
        &mut bob.chat,
        &alice.ik(),
        "before restart",
    )
    .await;

    // (task 10.22) `ice_restart` now needs a real, symmetric signaling round trip — a fresh
    // restart-scoped relay pair, per ADR 0025 ("used only for the bounded duration of one restart
    // attempt, then dropped again"), and both sides genuinely have to run it concurrently: whoever
    // is on the lexicographically-larger-key side waits (briefly) for the other's offer, so a
    // sequential `asess.ice_restart(..).await; bsess.ice_restart(..).await;` would deadlock the
    // first call waiting on a peer that hasn't even started yet.
    let (mut restart_relay_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (ares, bres) = tokio::join!(
        asess.ice_restart(
            &mut restart_relay_a,
            &alice.store,
            &ahandle,
            &mut alice.chat
        ),
        bsess.ice_restart(&mut restart_relay_b, &bob.store, &bhandle, &mut bob.chat),
    );
    ares.expect("alice ice_restart");
    bres.expect("bob ice_restart");

    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "after restart")
        .await
        .unwrap();
    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "after restart");
        }
        other => panic!("post-restart message lost: {other:?}"),
    }
}

/// (task 10.22, deliverable a) Both sides call [`P2pSession::ice_restart`] **concurrently** — the
/// glare case ADR 0025 names as more likely for a restart than for the one-shot initial dial. The
/// identity-key tie-break must resolve this deterministically (the same, coherent SDP exchange
/// completes) regardless of `tokio::join!`'s own scheduling order between the two futures, which
/// this test does not (and cannot) control — that's the actual point: correctness here comes from
/// the code's own tie-break, not from any accidental ordering.
#[tokio::test]
async fn ice_restart_glare_resolves_deterministically_and_both_sides_return_ok() {
    let mut alice = Peer::new("glare.a");
    let mut bob = Peer::new("glare.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.unwrap();
    let mut bsess = rb.unwrap();

    // Fingerprints agree before the restart (§4.6 already passed once).
    let (a_local_before, a_remote_before) = asess.fingerprints();
    let (b_local_before, b_remote_before) = bsess.fingerprints();
    assert_eq!(a_local_before, b_remote_before);
    assert_eq!(b_local_before, a_remote_before);

    let ahandle = alice.handle();
    let bhandle = bob.handle();
    let (mut restart_relay_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (ares, bres) = tokio::join!(
        asess.ice_restart(
            &mut restart_relay_a,
            &alice.store,
            &ahandle,
            &mut alice.chat
        ),
        bsess.ice_restart(&mut restart_relay_b, &bob.store, &bhandle, &mut bob.chat),
    );
    ares.expect("alice's concurrent ice_restart must resolve to Ok, not deadlock or race");
    bres.expect("bob's concurrent ice_restart must resolve to Ok, not deadlock or race");

    // One coherent, non-conflicting SDP exchange happened — not two independent, split-brained
    // negotiations — proven the same way the original handshake's own coherence is proven
    // elsewhere in this file: the bound fingerprints still cross-check after the restart.
    let (a_local_after, a_remote_after) = asess.fingerprints();
    let (b_local_after, b_remote_after) = bsess.fingerprints();
    assert_eq!(a_local_after, b_remote_after);
    assert_eq!(b_local_after, a_remote_after);

    // The restart is genuinely two-way live, not merely "returned Ok": a message flows each way
    // afterward, over the same session (no re-handshake).
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "still alive: a->b")
        .await
        .unwrap();
    accept_first_p2p_message(
        &mut bsess,
        &bob.store,
        &bhandle,
        &mut bob.chat,
        &alice.ik(),
        "still alive: a->b",
    )
    .await;
    bsess
        .send_chat(&bob.store, &bhandle, &mut bob.chat, "still alive: b->a")
        .await
        .unwrap();
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "still alive: b->a");
        }
        other => panic!("alice expected chat after glare-resolved restart, got {other:?}"),
    }
}

/// (task 10.22) The smaller-key side's own "discard a competing offer, keep waiting for my
/// answer within the remaining budget" branch, isolated deterministically: a bogus
/// `IceRestartOffer` is pre-queued into Alice's restart-relay inbox *before* either side's
/// `ice_restart()` call starts, so it is guaranteed (FIFO `MemRelay`) to be the first thing Alice's
/// own wait-for-answer loop sees — she must discard it and keep waiting, then still pick up Bob's
/// genuine answer that arrives right behind it. Alice's identity key is generated smaller than
/// Bob's (retried until true — the tie-break is on live key bytes, not something this test can
/// otherwise pin) so this exercises the *offerer's* discard branch specifically (mirrors the
/// smaller-key side of `ice_restart_glare_resolves_deterministically_and_both_sides_return_ok`).
#[tokio::test]
async fn ice_restart_smaller_key_discards_a_spurious_incoming_offer_while_awaiting_its_answer() {
    let (mut alice, mut bob) = smaller_and_larger_key_peers("discard.a", "discard.b");
    establish_ratchet(&mut alice, &mut bob);
    assert!(alice.ik() < bob.ik(), "alice must hold the smaller key");

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.unwrap();
    let mut bsess = rb.unwrap();

    let ahandle = alice.handle();
    let bhandle = bob.handle();

    let (mut restart_relay_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());

    // Pre-seed a syntactically-valid-enough (but entirely bogus) `IceRestartOffer` into Alice's
    // inbox, sealed on Bob's real ratchet so it decrypts fine — Alice's discard branch fires on the
    // envelope's *type* alone, never touching the bogus SDP/fingerprint fields inside.
    let bogus_offer = SignalContent::IceRestartOffer {
        sdp: b"v=loopback\ntoken=999999\nfp=sha-256 LOOPBACK:bogus\ngen=0\n".to_vec(),
        dtls_fp: "sha-256 LOOPBACK:bogus".to_string(),
        ice: vec!["candidate:host 1 10.0.0.1".to_string()],
    };
    let bogus_blob = bob
        .chat
        .seal_bytes(
            &bob.store,
            &bhandle,
            &bob.ik(),
            &alice.ik(),
            &bogus_offer.encode().expect("encode bogus offer"),
        )
        .expect("seal bogus offer on bob's real ratchet");
    restart_relay_b
        .send(&alice.ik(), bogus_blob)
        .await
        .expect("pre-seed alice's inbox with the bogus offer");

    let (ares, bres) = tokio::join!(
        asess.ice_restart(
            &mut restart_relay_a,
            &alice.store,
            &ahandle,
            &mut alice.chat
        ),
        bsess.ice_restart(&mut restart_relay_b, &bob.store, &bhandle, &mut bob.chat),
    );
    ares.expect("alice must discard the spurious offer and still complete via bob's real answer");
    bres.expect("bob's ice_restart must complete normally");

    // The session is still genuinely alive on both ends after discarding the spurious offer.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "post-discard")
        .await
        .unwrap();
    accept_first_p2p_message(
        &mut bsess,
        &bob.store,
        &bhandle,
        &mut bob.chat,
        &alice.ik(),
        "post-discard",
    )
    .await;
}

/// (task 10.22, deliverable c) A restart offer whose asserted `dtls_fp` field does not match what
/// the transport actually negotiates from the SDP it carries is rejected exactly like the original
/// handshake's own fingerprint check — the *ordinary*, unweakened §4.6 cross-check
/// ([`SessionError::FingerprintMismatch`]), not the new layered check. Constructed the same way
/// `p2p_session.rs`'s own `relay_only_answer_aborts_before_any_signaling_send_on_a_leaked_host_candidate`
/// crafts a fake envelope by hand: `LoopbackTransport::set_remote_description` negotiates whatever
/// fingerprint is embedded in the SDP text itself (`fp=...`), independent of the envelope's own
/// separate `dtls_fp` field — deliberately making the two disagree here is what proves the check
/// actually reads the transport's own negotiated value rather than merely trusting the assertion.
#[tokio::test]
async fn ice_restart_rejects_a_corrupted_dtls_fp_in_the_restart_offer() {
    let (mut alice, mut bob) = smaller_and_larger_key_peers("corrupt.a", "corrupt.b");
    establish_ratchet(&mut alice, &mut bob);
    assert!(bob.ik() > alice.ik(), "bob must hold the larger key");

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let asess = ra.unwrap();
    let mut bsess = rb.unwrap();
    drop(asess); // alice's live session is never driven in this test; bob processes a hand-crafted offer.

    let bhandle = bob.handle();

    // A syntactically valid SDP whose *embedded* fingerprint (what the transport will actually
    // negotiate) differs from the envelope's own asserted `dtls_fp` field — the deliberate
    // corruption/substitution this test targets.
    let corrupted_offer = SignalContent::IceRestartOffer {
        sdp: b"v=loopback\ntoken=42\nfp=sha-256 LOOPBACK:REAL-NEGOTIATED\ngen=0\n".to_vec(),
        dtls_fp: "sha-256 LOOPBACK:SUBSTITUTED-WRONG".to_string(),
        ice: vec!["candidate:host 1 10.0.0.2".to_string()],
    };
    let blob = alice
        .chat
        .seal_bytes(
            &alice.store,
            &alice.handle(),
            &alice.ik(),
            &bob.ik(),
            &corrupted_offer.encode().expect("encode corrupted offer"),
        )
        .expect("seal corrupted offer on alice's real ratchet");
    // Deliver directly into bob's own inbound queue (bob is the larger key, so his `ice_restart`
    // waits for an incoming offer first — exactly what it will see here). `feeder` plays alice's
    // side of a fresh restart-scoped relay pair, used only to inject this one hand-crafted message.
    let (mut feeder, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    feeder
        .send(&bob.ik(), blob)
        .await
        .expect("deliver the corrupted offer to bob's inbox");

    let result = bsess
        .ice_restart(&mut restart_relay_b, &bob.store, &bhandle, &mut bob.chat)
        .await;
    match result {
        Err(SessionError::FingerprintMismatch { .. }) => {}
        Err(e) => panic!("expected FingerprintMismatch, got a different error: {e}"),
        Ok(()) => panic!("a corrupted restart-offer fingerprint must never be accepted"),
    }
}

/// (task 10.22, deliverable d) The **layered** check's own new arm: the ordinary asserted-vs-
/// negotiated cross-check passes (the envelope's `dtls_fp` matches exactly what
/// `LoopbackTransport` negotiates from the SDP it carries), but the negotiated value no longer
/// equals the session's own cached `remote_fp` from the *original* handshake — simulating exactly
/// the "something rotated the peer's cert unexpectedly" scenario `RestartFingerprintDrift`'s own
/// doc comment describes. `LoopbackTransport::set_remote_description` trusts whatever fingerprint
/// is embedded in the peer's SDP verbatim (no independent negotiation of its own to fake), so
/// asserting a *different* fingerprint than the one cached at the original handshake — while still
/// keeping the envelope's own `dtls_fp` field consistent with that new SDP — is a faithful stand-in
/// for "the DTLS identity actually presented during the restart no longer matches the one bound at
/// handshake time", without needing a real webrtc-rs backend to (mis)implement a real cert
/// rotation bug.
#[tokio::test]
async fn ice_restart_layered_check_flags_fingerprint_drift_against_the_cached_value() {
    let (mut alice, mut bob) = smaller_and_larger_key_peers("drift.a", "drift.b");
    establish_ratchet(&mut alice, &mut bob);
    assert!(bob.ik() > alice.ik(), "bob must hold the larger key");

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let asess = ra.unwrap();
    let mut bsess = rb.unwrap();
    // `bsess`'s own cached `remote_fp` is *alice's* fingerprint (from the original handshake) —
    // this test drifts exactly that cached value, so bob's `ice_restart`'s layered check is what
    // must catch it.
    let (_bob_local_before, cached_alice_fp) = bsess.fingerprints();
    let cached_alice_fp = cached_alice_fp.clone();
    drop(asess); // alice's live session is never driven in this test; bob processes a hand-crafted offer.

    let bhandle = bob.handle();

    // A "restart offer from alice" whose asserted `dtls_fp` matches its own embedded SDP exactly
    // (the ordinary check passes) but is a *different* value than what bob's session originally
    // cached for alice at handshake time (the layered check's own new arm must catch this).
    let drifted_fp = "sha-256 LOOPBACK:DRIFTED-CERT".to_string();
    assert_ne!(
        drifted_fp, cached_alice_fp.0,
        "the drifted fingerprint must genuinely differ from the cached one for this test to prove anything"
    );
    let drifted_offer = SignalContent::IceRestartOffer {
        sdp: format!("v=loopback\ntoken=7\nfp={drifted_fp}\ngen=0\n").into_bytes(),
        dtls_fp: drifted_fp.clone(),
        ice: vec!["candidate:host 1 10.0.0.3".to_string()],
    };
    let blob = alice
        .chat
        .seal_bytes(
            &alice.store,
            &alice.handle(),
            &alice.ik(),
            &bob.ik(),
            &drifted_offer.encode().expect("encode drifted offer"),
        )
        .expect("seal drifted offer on alice's real ratchet");
    let (mut feeder_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    feeder_a
        .send(&bob.ik(), blob)
        .await
        .expect("deliver the drifted offer to bob's inbox");

    let result = bsess
        .ice_restart(&mut restart_relay_b, &bob.store, &bhandle, &mut bob.chat)
        .await;
    match result {
        Err(SessionError::RestartFingerprintDrift {
            local,
            expected,
            negotiated,
        }) => {
            assert!(
                !local,
                "the drift is on the remote (alice's) side, not ours"
            );
            assert_eq!(expected, cached_alice_fp.0);
            assert_eq!(negotiated, drifted_fp);
        }
        Err(e) => panic!("expected RestartFingerprintDrift, got a different error: {e}"),
        Ok(()) => panic!(
            "a negotiated fingerprint that silently drifted from the cached value must never pass"
        ),
    }
}

/// Generates `(smaller, larger)` peers where `smaller.ik() < larger.ik()` — the identity-key
/// tie-break `P2pSession::ice_restart` uses is on live, randomly-generated key bytes, so this
/// retries generation until the desired ordering holds (a coin flip each time; bounded so a broken
/// generator fails loudly instead of spinning forever).
fn smaller_and_larger_key_peers(smaller_hint: &str, larger_hint: &str) -> (Peer, Peer) {
    for _ in 0..64 {
        let a = Peer::new(smaller_hint);
        let b = Peer::new(larger_hint);
        if a.ik() < b.ik() {
            return (a, b);
        }
    }
    panic!("failed to generate a smaller/larger identity-key pair after 64 attempts");
}

#[tokio::test]
async fn additional_stream_type_opens_via_registry() {
    // The registry extension point end-to-end: a second (optional) stream type both peers register
    // opens over mrd.ctrl/1 with OPEN/ACCEPT — the exact path T09/T15/T16 code against, with zero
    // core edits. (T04 keeps a *real* second type out of scope; this proves the mechanism.)
    struct Echo;
    impl StreamType for Echo {
        fn name(&self) -> &'static str {
            "mrd.echo/1"
        }
        fn version(&self) -> u16 {
            1
        }
        fn channel_cfg(&self) -> ChannelCfg {
            ChannelCfg::reliable_ordered("mrd.echo/1")
        }
        fn direction(&self) -> meridian_core::envelope::Direction {
            meridian_core::envelope::Direction::Bidir
        }
        // optional (mandatory defaults to false)
    }

    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let mut reg_a = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_a, Arc::new(Echo));
    let mut reg_b = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_b, Arc::new(Echo));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(reg_a),
        Arc::new(reg_b),
    )
    .await;
    let mut asess = ra.unwrap();
    let mut bsess = rb.unwrap();

    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // Alice opens the echo stream; Bob accepts it; Alice sees the accept.
    let sid = asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.echo/1",
            vec![],
        )
        .await
        .unwrap();
    assert!(
        sid >= 2,
        "echo stream should get a fresh sid past ctrl/chat"
    );

    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(got, ty)) => {
            assert_eq!(got, sid);
            assert_eq!(ty, "mrd.echo/1");
        }
        other => panic!("bob expected StreamOpened, got {other:?}"),
    }
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(got, _)) => assert_eq!(got, sid),
        other => panic!("alice expected accept (StreamOpened), got {other:?}"),
    }
}

#[tokio::test]
async fn open_unregistered_stream_type_is_rejected() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.unwrap();
    let _bsess = rb.unwrap();
    let ahandle = alice.handle();

    // Opening a locally-unregistered type fails fast, without a ctrl round trip.
    match asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.nope/1",
            vec![],
        )
        .await
    {
        Err(SessionError::StreamRejected { code, .. }) => assert_eq!(code, "unsupported"),
        other => panic!("expected local unsupported rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn ctrl_open_gates_on_undecided_message_request_for_a_non_chat_stream_type() {
    // F11 / task 3.11: `decide_open`'s `PolicyCtx.first_contact` must reflect the peer's *live*
    // undecided-`MessageRequest` state instead of the old hardcoded `false` — and must do so
    // uniformly for any registered stream type, never as a chat-specific special case (the
    // stream-registry contract: additive stream types touch the registry only). `Probe` is a
    // throwaway non-chat type whose `on_open` records exactly what `PolicyCtx.first_contact` it was
    // handed, so this test proves the signal reaches an arbitrary registered type's own policy hook.
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Probe(Arc<AtomicBool>);
    impl StreamType for Probe {
        fn name(&self) -> &'static str {
            "mrd.probe/1"
        }
        fn version(&self) -> u16 {
            1
        }
        fn channel_cfg(&self) -> ChannelCfg {
            ChannelCfg::reliable_ordered("mrd.probe/1")
        }
        fn direction(&self) -> meridian_core::envelope::Direction {
            meridian_core::envelope::Direction::Bidir
        }
        fn on_open(
            &self,
            _sid: meridian_core::streams::StreamId,
            _params: &[u8],
            policy: &meridian_core::streams::PolicyCtx,
        ) -> meridian_core::streams::OpenDecision {
            self.0.store(policy.first_contact, Ordering::SeqCst);
            meridian_core::streams::OpenDecision::Accept
        }
    }

    let mut alice = Peer::new("gate.a");
    let mut bob = Peer::new("gate.b");
    establish_ratchet(&mut alice, &mut bob);
    let alice_ik = alice.ik();

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    // Both sides register the non-chat probe type (the opener needs it locally too, to build the
    // OPEN frame's channel config) — only Bob's copy's `on_open` is ever exercised here, since he is
    // the one deciding Alice's OPENs.
    let mut alice_reg = StreamRegistry::with_builtins();
    register_stream_type(
        &mut alice_reg,
        Arc::new(Probe(Arc::new(AtomicBool::new(false)))),
    );
    let seen = Arc::new(AtomicBool::new(false));
    let mut bob_reg = StreamRegistry::with_builtins();
    register_stream_type(&mut bob_reg, Arc::new(Probe(seen.clone())));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(alice_reg),
        Arc::new(bob_reg),
    )
    .await;
    let mut asess = ra.expect("established");
    let mut bsess = rb.expect("established");
    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // Alice's first-ever chat content frame to Bob: gated as a `MessageRequest`, held undecided.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hi bob")
        .await
        .unwrap();
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Err(SessionError::Chat(ChatError::MessageRequest)) => {}
        other => panic!("expected the first content frame to be gated, got {other:?}"),
    }
    assert!(
        bob.chat.pending_request(&alice_ik).is_some(),
        "an undecided MessageRequest must be held for Alice"
    );

    // Alice now opens a completely unrelated, non-chat stream type. Bob's `decide_open` must feed
    // `first_contact: true` into `Probe::on_open` — proving the fix reads *live* `pending_request`
    // state, not just the session-establishment-time `chat_first_contact_gate` flag (which was
    // already cleared by the chat frame above, and would wrongly read `false` here on its own — the
    // exact gap this task closes).
    asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.probe/1",
            vec![],
        )
        .await
        .unwrap();
    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(_, ty)) => assert_eq!(ty, "mrd.probe/1"),
        other => panic!("expected Bob to accept the probe stream open, got {other:?}"),
    }
    assert!(
        seen.load(Ordering::SeqCst),
        "an undecided MessageRequest must feed first_contact: true into a non-chat stream's \
         on_open policy hook — this must never be a chat-specific special case"
    );

    // Once the request is decided (accepted), the same peer opening yet another stream must no
    // longer read as a first contact.
    bob.chat.accept_request(&alice_ik).expect("accept");
    asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.probe/1",
            vec![],
        )
        .await
        .unwrap();
    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(_, ty)) => assert_eq!(ty, "mrd.probe/1"),
        other => panic!("expected Bob to accept the second probe stream open, got {other:?}"),
    }
    assert!(
        !seen.load(Ordering::SeqCst),
        "an already-decided contact must read first_contact: false"
    );
}

#[tokio::test]
async fn relay_only_session_reports_observed_not_assumed_candidates() {
    // F20: `session info`'s `candidates offered` claim must come from what was actually gathered,
    // not merely from the policy label — this drives a real relay-only dial/answer end-to-end
    // (through `dial_with_config`/`answer_with_config`, exactly as the CLI demo does) and checks
    // the *observed* classification, not `relay::gather_classes(policy)` recomputed after the fact.
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let ice_servers = vec![IceServer {
        urls: vec!["turn:turn-a:3478?transport=udp".into()],
        username: Some("1700000000:demo".into()),
        credential: Some("demo-hmac".into()),
    }];
    let cfg_a = relay::ice_config(IcePolicy::RelayOnly, ice_servers.clone(), Vec::new());
    let cfg_b = relay::ice_config(IcePolicy::RelayOnly, ice_servers, Vec::new());

    let (mut relay_a, mut relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let (ahandle, bhandle) = (alice.handle(), bob.handle());
    let (ra, rb) = {
        let achat = &mut alice.chat;
        let bchat = &mut bob.chat;
        tokio::join!(
            dial_with_config(
                ta,
                &alice.store,
                &ahandle,
                alice_ik,
                bob_ik,
                achat,
                &mut relay_a,
                Arc::new(StreamRegistry::with_builtins()),
                cfg_a,
            ),
            answer_with_config(
                tb,
                &bob.store,
                &bhandle,
                bob_ik,
                alice_ik,
                bchat,
                &mut relay_b,
                Arc::new(StreamRegistry::with_builtins()),
                cfg_b,
            ),
        )
    };
    let asess =
        ra.expect("relay-only dial should succeed: LoopbackTransport never leaks host/srflx");
    let bsess = rb.expect("relay-only answer should succeed");

    for sess in [&asess, &bsess] {
        let info = sess.info().await;
        assert!(
            !info.offered.host,
            "relay-only must never observe a host candidate"
        );
        assert!(
            !info.offered.srflx,
            "relay-only must never observe a srflx candidate"
        );
        assert!(
            info.offered.relay,
            "relay-only must observe relay candidates"
        );
        assert!(
            info.candidates_offered_line()
                .contains("peer never saw our host/srflx IPs"),
            "line: {}",
            info.candidates_offered_line()
        );
    }
}

// -- F20 end-to-end abort coverage -----------------------------------------------------------
//
// The pure unit tests in `session.rs` prove `enforce_relay_only` itself aborts on any non-relay
// candidate. `LoopbackTransport` and the webrtc-rs backend are both *built* never to leak
// host/srflx under relay-only, so exercising that abort through a real dial/answer needs a
// transport double that deliberately misbehaves. `LeakyTransport` is exactly that: an honest
// `LoopbackTransport` wrapped to append a leaked host candidate no matter what policy asked for —
// the transport bug `enforce_relay_only` exists to catch. `CountingRelay` then proves the
// *ordering* guarantee: the abort happens strictly before the offer/answer carrying that
// candidate is ever handed to the signaling relay, not merely that `dial_with_config`/
// `answer_with_config` eventually return `Err`.

/// Wraps an honest [`LoopbackTransport`] but deliberately reports one extra leaked host candidate
/// from `local_candidates`, regardless of policy — simulating the exact transport bug F20's
/// observation-based enforcement exists to catch end-to-end, not just at the unit level.
#[derive(Clone)]
struct LeakyTransport(LoopbackTransport);

#[async_trait::async_trait]
impl Transport for LeakyTransport {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    async fn new_session(&self, cfg: IceConfig) -> TransportResult<SessionHandle> {
        self.0.new_session(cfg).await
    }
    async fn add_data_channel(
        &self,
        s: &SessionHandle,
        cfg: ChannelCfg,
    ) -> TransportResult<ChannelId> {
        self.0.add_data_channel(s, cfg).await
    }
    async fn add_transceiver(
        &self,
        s: &SessionHandle,
        kind: MediaKind,
    ) -> TransportResult<TrackId> {
        self.0.add_transceiver(s, kind).await
    }
    fn local_description(&self, s: &SessionHandle) -> TransportResult<Sdp> {
        self.0.local_description(s)
    }
    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> TransportResult<()> {
        self.0.set_remote_description(s, sdp).await
    }
    async fn set_remote_offer_and_answer(
        &self,
        s: &SessionHandle,
        sdp: Sdp,
    ) -> TransportResult<()> {
        self.0.set_remote_offer_and_answer(s, sdp).await
    }
    async fn add_ice_candidate(&self, s: &SessionHandle, c: IceCandidate) -> TransportResult<()> {
        self.0.add_ice_candidate(s, c).await
    }
    async fn local_candidates(&self, s: &SessionHandle) -> TransportResult<Vec<IceCandidate>> {
        // The deliberate leak: a host candidate appended on top of whatever the honest inner
        // transport actually gathered (which, under relay-only, is nothing but relay).
        let mut cands = self.0.local_candidates(s).await?;
        cands.push(IceCandidate(
            "candidate:host 999 10.0.0.99 leaked-by-test-double".to_string(),
        ));
        Ok(cands)
    }
    fn local_fingerprint(&self, s: &SessionHandle) -> TransportResult<Fingerprint> {
        self.0.local_fingerprint(s)
    }
    fn dtls_fingerprint(&self, s: &SessionHandle) -> TransportResult<Fingerprint> {
        self.0.dtls_fingerprint(s)
    }
    async fn ice_restart(&self, s: &SessionHandle) -> TransportResult<()> {
        self.0.ice_restart(s).await
    }
    async fn send(&self, s: &SessionHandle, ch: &ChannelId, data: &[u8]) -> TransportResult<()> {
        self.0.send(s, ch, data).await
    }
    async fn recv(&self, s: &SessionHandle) -> TransportResult<Option<(ChannelId, Vec<u8>)>> {
        self.0.recv(s).await
    }
    async fn buffered_amount(&self, s: &SessionHandle, ch: &ChannelId) -> TransportResult<u64> {
        self.0.buffered_amount(s, ch).await
    }
    async fn selected_path(&self, s: &SessionHandle) -> TransportResult<Path> {
        self.0.selected_path(s).await
    }
    async fn close(&self, s: &SessionHandle) -> TransportResult<()> {
        self.0.close(s).await
    }
}

/// A [`SignalRelay`] wrapper counting outbound sends — proves an abort happened *before* any
/// signaling envelope reached the peer, not just that the call eventually returned `Err`.
struct CountingRelay {
    inner: MemRelay,
    sends: usize,
}

#[async_trait::async_trait]
impl SignalRelay for CountingRelay {
    async fn send(&mut self, to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError> {
        self.sends += 1;
        self.inner.send(to, blob).await
    }
    async fn send_tolerant(
        &mut self,
        to: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<meridian_core::signaling::RouteOutcome, SessionError> {
        self.sends += 1;
        self.inner.send_tolerant(to, blob).await
    }
    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError> {
        self.inner.recv().await
    }
}

fn demo_ice_servers() -> Vec<IceServer> {
    vec![IceServer {
        urls: vec!["turn:turn-a:3478?transport=udp".into()],
        username: Some("1700000000:demo".into()),
        credential: Some("demo-hmac".into()),
    }]
}

#[tokio::test]
async fn relay_only_dial_aborts_before_any_signaling_send_on_a_leaked_host_candidate() {
    // Exercises the `dial_established` call site of `enforce_relay_only` end-to-end: a leaky
    // transport reports a host candidate under relay-only, and the dial must abort with
    // `RelayOnlyViolation` *before* the offer is ever handed to the signaling relay.
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let leaky = Arc::new(LeakyTransport(LoopbackTransport::new(fabric)));
    let cfg = relay::ice_config(IcePolicy::RelayOnly, demo_ice_servers(), Vec::new());

    let (relay_a, _relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let mut counting = CountingRelay {
        inner: relay_a,
        sends: 0,
    };

    let ahandle = alice.handle();
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let dial_result = dial_with_config(
        leaky,
        &alice.store,
        &ahandle,
        alice_ik,
        bob_ik,
        &mut alice.chat,
        &mut counting,
        Arc::new(StreamRegistry::with_builtins()),
        cfg,
    )
    .await;
    let err = match dial_result {
        Err(e) => e,
        Ok(_) => panic!("relay-only dial over a leaky transport must abort, never connect"),
    };

    assert!(
        matches!(err, SessionError::RelayOnlyViolation { .. }),
        "expected RelayOnlyViolation, got {err}"
    );
    assert_eq!(
        counting.sends, 0,
        "the offer must never reach the signaling relay once a leaked candidate is observed"
    );
}

#[tokio::test]
async fn relay_only_answer_aborts_before_any_signaling_send_on_a_leaked_host_candidate() {
    // Exercises the `answer_established` call site of `enforce_relay_only` end-to-end (the dial
    // side is covered by the sibling test above) — Bob's transport is the leaky one this time, so
    // the abort must happen before Bob's *answer* is ever handed to the signaling relay. Alice's
    // offer is crafted directly (rather than driven through a live `dial_with_config`) because
    // `enforce_relay_only` in `answer_established` checks Bob's own observed local candidates, not
    // anything from the offer — a syntactically valid, ratchet-sealed offer is all that's needed
    // to reach the code path under test, and this avoids an unrelated hang were Alice's dial to
    // instead await an answer Bob's abort will never send.
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let leaky = Arc::new(LeakyTransport(LoopbackTransport::new(fabric)));
    let cfg = relay::ice_config(IcePolicy::RelayOnly, demo_ice_servers(), Vec::new());

    let (mut relay_a, relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let ahandle = alice.handle();

    let fake_offer = SignalContent::SdpOffer {
        sdp: b"v=loopback\ntoken=1\nfp=sha-256 LOOPBACK:fake\ngen=0\n".to_vec(),
        dtls_fp: "sha-256 LOOPBACK:fake".to_string(),
        ice: vec!["candidate:relay 1 turn.example.org".to_string()],
    };
    let blob = alice
        .chat
        .seal_bytes(
            &alice.store,
            &ahandle,
            &alice_ik,
            &bob_ik,
            &fake_offer.encode().expect("encode fake offer"),
        )
        .expect("seal fake offer onto the real X3DH-derived ratchet");
    relay_a
        .send(&bob_ik, blob)
        .await
        .expect("deliver the fake offer to bob's relay inbox");

    let mut counting = CountingRelay {
        inner: relay_b,
        sends: 0,
    };
    let bhandle = bob.handle();
    let answer_result = answer_with_config(
        leaky,
        &bob.store,
        &bhandle,
        bob_ik,
        alice_ik,
        &mut bob.chat,
        &mut counting,
        Arc::new(StreamRegistry::with_builtins()),
        cfg,
    )
    .await;
    let err = match answer_result {
        Err(e) => e,
        Ok(_) => panic!("relay-only answer over a leaky transport must abort, never connect"),
    };

    assert!(
        matches!(err, SessionError::RelayOnlyViolation { .. }),
        "expected RelayOnlyViolation, got {err}"
    );
    assert_eq!(
        counting.sends, 0,
        "the answer must never reach the signaling relay once a leaked candidate is observed"
    );
}

// -- task 10.4: generic multi-stream substrate ----------------------------------------------------

/// (task 10.4) End-to-end proof of the generalized substrate over `LoopbackTransport`, driving a
/// registered non-chat/non-ctrl "exotic" stream type — mirroring `apps/core/src/streams.rs`'s own
/// test-only `Exotic` shape (mandatory, `reliable_ordered`, `Bidir`), but with interior state so a
/// received frame is actually observable from outside `on_frame`'s synchronous callback: open,
/// accept (both sides symmetrically open a real data channel — the deliverable this task adds),
/// send a frame each way, confirm `on_frame` fires with correctly decrypted bytes on both ends, and
/// confirm `stream_buffered_amount` reflects a real (loopback-backed) buffered amount right after a
/// send, before the peer's `pump` drains it.
#[tokio::test]
async fn generic_stream_frames_round_trip_with_backpressure_query() {
    use std::sync::Mutex;

    struct Exotic {
        received: Mutex<Vec<Vec<u8>>>,
    }
    impl Exotic {
        fn new() -> Self {
            Self {
                received: Mutex::new(Vec::new()),
            }
        }
        fn frames(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().clone()
        }
    }
    impl StreamType for Exotic {
        fn name(&self) -> &'static str {
            "mrd.exotic/9"
        }
        fn version(&self) -> u16 {
            9
        }
        fn channel_cfg(&self) -> ChannelCfg {
            ChannelCfg::reliable_ordered("mrd.exotic/9")
        }
        fn direction(&self) -> meridian_core::envelope::Direction {
            meridian_core::envelope::Direction::Bidir
        }
        fn mandatory(&self) -> bool {
            true
        }
        fn on_frame(&self, _sid: meridian_core::streams::StreamId, frame: &[u8]) {
            self.received.lock().unwrap().push(frame.to_vec());
        }
    }

    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let alice_exotic = Arc::new(Exotic::new());
    let bob_exotic = Arc::new(Exotic::new());
    let mut reg_a = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_a, alice_exotic.clone());
    let mut reg_b = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_b, bob_exotic.clone());

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(reg_a),
        Arc::new(reg_b),
    )
    .await;
    let mut asess = ra.expect("established");
    let mut bsess = rb.expect("established");

    let ahandle = alice.handle();
    let bhandle = bob.handle();

    // Alice opens the exotic stream; Bob's `decide_open` accepts it — the responder side of the
    // symmetric data-channel open this task adds.
    let sid = asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.exotic/9",
            vec![],
        )
        .await
        .unwrap();

    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(got, ty)) => {
            assert_eq!(got, sid);
            assert_eq!(ty, "mrd.exotic/9");
        }
        other => panic!("bob expected StreamOpened, got {other:?}"),
    }
    // Alice sees the Accept — the initiator side of the symmetric data-channel open.
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::StreamOpened(got, ty)) => {
            assert_eq!(got, sid);
            assert_eq!(ty, "mrd.exotic/9");
        }
        other => panic!("alice expected StreamOpened (accept), got {other:?}"),
    }

    // Alice -> Bob: encrypt-and-send via the new generic outbound path.
    asess
        .send_stream_frame(&mut alice.chat, sid, b"hello from alice")
        .await
        .unwrap();

    // Backpressure query: right after the send and before Bob's `pump` has drained it, the
    // loopback-backed buffered amount must reflect the (ratchet-framed, so larger than the bare
    // plaintext) bytes actually queued — a synthetic buffered-amount reading, task 10.2's primitive
    // exposed through this task's own query.
    let buffered = asess.stream_buffered_amount(sid).await.unwrap();
    assert!(
        buffered > 0,
        "buffered amount must reflect the just-queued frame before the peer drains it, got {buffered}"
    );

    // Bob's generic dispatch: decrypt via task 10.1's export primitive and call `on_frame` — no
    // `SessionEvent` of its own (the substrate never interprets the bytes), so `pump` returns
    // `Ok(None)`.
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Ok(None) => {}
        other => panic!("bob expected a silently-dispatched stream frame, got {other:?}"),
    }
    assert_eq!(bob_exotic.frames(), vec![b"hello from alice".to_vec()]);

    // Draining the frame must bring the sender's own buffered-amount view back down.
    assert_eq!(asess.stream_buffered_amount(sid).await.unwrap(), 0);

    // Bob -> Alice, the mirror direction.
    bsess
        .send_stream_frame(&mut bob.chat, sid, b"hi alice")
        .await
        .unwrap();
    match asess.pump(&alice.store, &ahandle, &mut alice.chat).await {
        Ok(None) => {}
        other => panic!("alice expected a silently-dispatched stream frame, got {other:?}"),
    }
    assert_eq!(alice_exotic.frames(), vec![b"hi alice".to_vec()]);

    // Chat is completely unaffected by any of the above — no behavior change for `mrd.chat/1`.
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "still works")
        .await
        .unwrap();
    accept_first_p2p_message(
        &mut bsess,
        &bob.store,
        &bhandle,
        &mut bob.chat,
        &alice.ik(),
        "still works",
    )
    .await;
}

#[tokio::test]
async fn send_stream_frame_on_an_unknown_stream_is_rejected() {
    // A caller error (no such open, non-chat/ctrl stream), never a protocol round trip.
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.unwrap();
    let _bsess = rb.unwrap();

    match asess.send_stream_frame(&mut alice.chat, 999, b"nope").await {
        Err(SessionError::UnknownStream(999)) => {}
        other => panic!("expected UnknownStream, got {other:?}"),
    }
    match asess.stream_buffered_amount(999).await {
        Err(SessionError::UnknownStream(999)) => {}
        other => panic!("expected UnknownStream, got {other:?}"),
    }
}
