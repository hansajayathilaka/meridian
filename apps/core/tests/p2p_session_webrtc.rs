//! Gated T04 acceptance coverage over the **real** transport backend (1.15, F10 backend):
//! `cargo nextest run -p meridian-core --features webrtc`.
//!
//! Mirrors `p2p_session.rs`'s loopback-based tests, but swaps `LoopbackTransport` for
//! `WebRtcTransport` — real ICE/SCTP/DTLS on localhost — proving the headline "kill the server,
//! chat continues" demo, capability rejection, and ICE restart all hold over a real connection, not
//! only the deterministic simulation. Fingerprint-mismatch fail-closed is proven generically (over
//! any `Transport`) by `p2p_session.rs::fingerprint_mismatch_tears_down` using
//! `LoopbackTransport::new_mitm` — real webrtc-rs enforces SDP/DTLS-certificate binding as a hard
//! precondition of the handshake ever completing, so there is no way to *externally* force a real
//! connection into a mismatched state to re-exercise that same check; what a real backend adds is
//! proof that the fingerprints it reports are real, bound values (see
//! `apps/transport/tests/webrtc_backend.rs::negotiated_fingerprints_agree_and_bind_to_the_real_dtls_cert`),
//! which combined with the generic mismatch test covers the property end to end.

#![cfg(feature = "webrtc")]

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionError, SessionEvent};
use meridian_core::signaling::generate_bundle;
use meridian_core::streams::{register_stream_type, StreamRegistry, StreamType};
use meridian_core::transport::{ChannelCfg, WebRtcTransport};

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
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks);
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

async fn connect(
    ta: Arc<WebRtcTransport>,
    tb: Arc<WebRtcTransport>,
    alice: &mut Peer,
    bob: &mut Peer,
    reg_a: Arc<StreamRegistry>,
    reg_b: Arc<StreamRegistry>,
) -> (
    Result<P2pSession<WebRtcTransport>, SessionError>,
    Result<P2pSession<WebRtcTransport>, SessionError>,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_down_chat_continuity_over_webrtc() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

    let (ra, rb) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(StreamRegistry::with_builtins()),
        Arc::new(StreamRegistry::with_builtins()),
    )
    .await;
    let mut asess = ra.expect("dial established over real webrtc");
    let mut bsess = rb.expect("answer established over real webrtc");

    // Fingerprints are real (SHA-256 over the actual DTLS cert's SDP line) and bound (§4.6 passed).
    let (a_local, a_remote) = asess.fingerprints();
    let (b_local, b_remote) = bsess.fingerprints();
    assert_eq!(a_local, b_remote);
    assert_eq!(b_local, a_remote);
    assert!(a_local.0.starts_with("sha-256 "));

    assert!(asess
        .peer_capabilities()
        .iter()
        .any(|s| s.name == "mrd.chat/1"));

    // The headline demo, over a real connection: the relay (MemRelay) is already dropped inside
    // `connect`. Chat flows peer-to-peer over real ICE/SCTP/DTLS with NO server in the path.
    let ahandle = alice.handle();
    let bhandle = bob.handle();

    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hello over p2p")
        .await
        .unwrap();
    match bsess
        .pump(&bob.store, &bhandle, &mut bob.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "hello over p2p");
        }
        other => panic!("bob expected chat, got {other:?}"),
    }

    bsess
        .send_chat(
            &bob.store,
            &bhandle,
            &mut bob.chat,
            "hi back — no server, real transport",
        )
        .await
        .unwrap();
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .unwrap()
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "hi back — no server, real transport");
        }
        other => panic!("alice expected chat, got {other:?}"),
    }

    // A keepalive round-trips over the real ctrl data channel.
    let (ping, _pumped) = {
        let a = asess.ping(&alice.store, &ahandle, &mut alice.chat);
        let b = bsess.pump(&bob.store, &bhandle, &mut bob.chat);
        tokio::join!(a, b)
    };
    assert!(ping.unwrap() >= 0.0);

    let info = asess.info().await;
    assert_eq!(info.transport, "webrtc-datachannel");
    assert!(info.streams.iter().any(|s| s == "mrd.ctrl/1"));
    assert!(info.streams.iter().any(|s| s == "mrd.chat/1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn additional_stream_type_opens_via_registry_over_webrtc() {
    // The OPEN/ACCEPT half of the ctrl protocol, over a real connection — the loopback suite's
    // `additional_stream_type_opens_via_registry` proves the mechanism deterministically; this
    // proves the same CBOR ctrl frames round-trip correctly over real SCTP.
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

    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_mandatory_capability_rejected_gracefully_over_webrtc() {
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

    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_restart_preserves_session_and_ratchet_over_webrtc() {
    let mut alice = Peer::new("chat.a");
    let mut bob = Peer::new("chat.b");
    establish_ratchet(&mut alice, &mut bob);

    let ta = Arc::new(WebRtcTransport::new());
    let tb = Arc::new(WebRtcTransport::new());

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

    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "before restart")
        .await
        .unwrap();
    assert!(matches!(
        bsess
            .pump(&bob.store, &bhandle, &mut bob.chat)
            .await
            .unwrap(),
        Some(SessionEvent::Chat(ChatContent::Text { .. }))
    ));

    asess.ice_restart().await.unwrap();
    bsess.ice_restart().await.unwrap();

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
