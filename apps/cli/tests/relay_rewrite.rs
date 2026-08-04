//! Task 1.28 — **active relay-rewrite adversarial test**.
//!
//! Closes the gap left open by `harnesses/mitm-sim/run.sh` and `apps/core/src/session.rs`'s module
//! doc: until now, no test drove a real `dial`/`answer` P2P establishment through a rendezvous that
//! was *actively rewriting routed blobs in transit*. The existing coverage was adjacent but not this:
//!
//!   * `meridian-rendezvous`'s `tampered_bundle_is_rejected` attacks **key distribution** (a
//!     substituted `Fetch` bundle), not the routed signaling path.
//!   * `apps/core/tests/p2p_session.rs::fingerprint_mismatch_tears_down` attacks the **transport**
//!     (`LoopbackTransport::new_mitm` forces a DTLS fingerprint mismatch) with an honest relay.
//!
//! This test attacks the **relay itself**: a real `meridian-rendezvous`, built with
//! `test-tamper-hook` and configured with `allow_test_route_tamper`, mutates every routed blob as it
//! passes through. Both peers run in-process over a shared `LoopbackFabric` for the *data* path, but
//! their signaling is real: two `SignalingClient`s over real sockets to that hostile server.
//!
//! **The asserted property:** establishment **fails closed**. The rewrite is detected and no session
//! comes up — never a silently-accepted substituted offer/answer. It cannot come up "differently" or
//! "insecurely"; the only outcomes are no-session or secure-session (threat-model goal 6).
//!
//! **What this does NOT cover, stated so the coverage is not overread:** a byte-level rewrite breaks
//! the Ed25519 envelope signature, so rejection happens at the *signature* check — the ratchet AEAD
//! and the §4.6 fingerprint cross-check are never exercised on this path. A relay's key-material-free
//! attacks that *would* pass the signature check (a forged `Deliver.from`, replay of an earlier valid
//! envelope, reorder, drop, cross-delivery from another session) are not exercised here — they are
//! task **1.32**, and now live in `relay_attacks.rs` next to this file.
//!
//! The control case in `honest_relay_establishes_the_same_session` is load-bearing: it runs the
//! identical flow with route-tampering off and asserts the session *does* establish. Without it, the
//! fail-closed assertion would be satisfied by any unrelated breakage (a port mixup, a missing
//! bundle) and would pass while proving nothing.

use std::sync::mpsc;
use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::identity::{generate_account, AccountId, MemorySecretStore};
use meridian_core::session::{answer, dial, SessionError, ANSWER_TIMEOUT};
use meridian_core::signal_relay::RendezvousRelay;
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_core::streams::StreamRegistry;
use meridian_core::transport::{LoopbackFabric, LoopbackTransport};
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

/// Start a real server on an ephemeral port. `rewrite_routed_blobs` turns on the 1.28 hook.
fn spawn_server(rewrite_routed_blobs: bool) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut config = Config::default();
            config.server.allow_test_tamper = rewrite_routed_blobs;
            config.server.allow_test_route_tamper = rewrite_routed_blobs;
            // Since 1.32 `allow_test_route_tamper` is the umbrella gate for the whole family of
            // route attacks and each has its own mode flag; the in-transit rewrite is this one.
            config.server.allow_test_route_rewrite = rewrite_routed_blobs;
            // Both peers connect from 127.0.0.1 in-process.
            config.limits.auth_per_ip_per_min = 1_000_000;
            let store = Arc::new(MemoryStore::new());
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    format!("ws://{}", rx.recv().unwrap())
}

struct Peer {
    store: MemorySecretStore,
    account: AccountId,
    chat: ChatState,
}

impl Peer {
    fn new(hint: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).unwrap();
        Self {
            store,
            account,
            chat: ChatState::default(),
        }
    }
    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }
}

/// Connect a peer, publish its bundle, and record the matching secrets in its vault.
async fn connect_and_publish(peer: &mut Peer, url: &str) -> SignalingClient {
    let ik = peer.ik();
    let mut client = SignalingClient::connect(url, &peer.store, peer.account.handle(), ik, None, 1)
        .await
        .expect("connect to rendezvous");
    let generated = client
        .publish_bundle(&peer.store, peer.account.handle(), DEFAULT_OTK_COUNT)
        .await
        .expect("publish bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    peer.chat.vault.set_bundle(
        generated.bundle.spk,
        *generated.spk_secret,
        otks,
        1_700_000_000,
    );
    client
}

/// What happened to one side of the handshake.
///
/// `Rejected` keeps the *classified* error, not just its text. Matching on the variant rather than a
/// message substring is deliberate: it is what makes the assertions below non-vacuous (a bare
/// `Relay`/`SignalingEnded` must NOT satisfy "the rewrite was detected"), and it survives
/// [ADR 0016](../../../docs/adr/0016-envelope-deniability.md) — at envelope v2 the detector moves
/// from the Ed25519 signature check to the ratchet AEAD, which is still a `Chat` error, whereas a
/// string assertion on "signature verification failed" would go stale.
#[derive(Debug)]
enum Outcome {
    /// A session came up. In the adversarial case this is the security failure.
    Established,
    /// Explicitly rejected — the *detection* the task asks for, when the class is right.
    Rejected(SessionError),
    /// Neither established nor rejected within `SIDE_TIMEOUT`. Before 1.33 this was the dialer's
    /// expected (if undiagnosed) fate on this test; since 1.33 bounds `dial`'s own wait well inside
    /// `SIDE_TIMEOUT`, seeing this here means the *production* bound failed to fire — a regression,
    /// not a benign residual.
    StillWaiting,
}

impl Outcome {
    /// Did this side reject at the **envelope-authentication** layer? `SessionError::Chat` wraps
    /// `ChatError`, which is where a tampered blob is caught (signature today, ratchet AEAD at
    /// envelope v2). A `Relay`/`SignalingEnded`/`Transport` error is explicitly NOT this: those are
    /// the signature of an unrelated regression, and treating them as "detected" is exactly how this
    /// test could go green while the property it asserts is broken.
    fn is_envelope_rejection(&self) -> bool {
        matches!(self, Outcome::Rejected(SessionError::Chat(_)))
    }

    /// (1.33) Did this side hit the dialer's bounded answer-wait specifically? Distinct from
    /// [`Outcome::is_envelope_rejection`] — this is "the peer never answered" (here, because the
    /// responder rejected and so never produced one), not "the envelope itself was tampered".
    fn is_answer_timeout(&self) -> bool {
        matches!(self, Outcome::Rejected(SessionError::AnswerTimeout(_)))
    }
}

/// How long a side may wait before we call it `StillWaiting`. Before 1.33 this was the *only* thing
/// bounding the dialer's wait at all (production `recv_sdp` had no timeout of its own), so it had to
/// be picked independently and generously. Now that `dial` bounds itself internally
/// ([`ANSWER_TIMEOUT`]), this only needs enough headroom above that real bound to let it fire and be
/// observed as `SessionError::AnswerTimeout` rather than being preempted by this outer test-only
/// cutoff — comfortably smaller than the old fixed 10s, and it tracks the production constant instead
/// of duplicating a number that could silently drift out of sync with it.
const SIDE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5).saturating_add(ANSWER_TIMEOUT);

/// Drive a full dial/answer through the given server, timing out **each side independently** so the
/// two outcomes stay distinguishable. Joining them under a single timeout hides detection: the
/// responder rejects a rewritten offer immediately, and (since 1.33) the dialer now reliably reports
/// its own `AnswerTimeout` rather than the pair being reduced to "the responder rejected and the
/// dialer's outcome is unknown".
async fn establish_through(url: &str) -> (Outcome, Outcome) {
    let mut alice = Peer::new("relay.a");
    let mut bob = Peer::new("relay.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    let mut alice_client = connect_and_publish(&mut alice, url).await;
    let mut bob_client = connect_and_publish(&mut bob, url).await;

    // Alice initiates: fetch + verify Bob's bundle, then X3DH.
    let bob_bundle = alice_client
        .fetch_bundle(bob_ik, None, false)
        .await
        .expect("fetch bob's bundle");
    alice
        .chat
        .start_initiator_session(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &bob_ik,
            &bob_bundle.spk,
            bob_bundle.otks.first().copied(),
        )
        .expect("x3dh");

    // Shared loopback fabric for the DATA path; the SIGNALING path is the real hostile server.
    let fabric = LoopbackFabric::new();
    let alice_tp = Arc::new(LoopbackTransport::new(fabric.clone()));
    let bob_tp = Arc::new(LoopbackTransport::new(fabric));
    let registry = Arc::new(StreamRegistry::with_builtins());

    // Same server for both peers in this test — no cross-org hint in play.
    let mut alice_relay = RendezvousRelay::new(&mut alice_client, None);
    let mut bob_relay = RendezvousRelay::new(&mut bob_client, None);

    let alice_fut = dial(
        alice_tp,
        &alice.store,
        alice.account.handle(),
        alice_ik,
        bob_ik,
        &mut alice.chat,
        &mut alice_relay,
        registry.clone(),
    );
    let bob_fut = answer(
        bob_tp,
        &bob.store,
        bob.account.handle(),
        bob_ik,
        alice_ik,
        &mut bob.chat,
        &mut bob_relay,
        registry,
    );

    let (a, b) = tokio::join!(
        tokio::time::timeout(SIDE_TIMEOUT, alice_fut),
        tokio::time::timeout(SIDE_TIMEOUT, bob_fut),
    );

    async fn classify<T: meridian_core::transport::Transport>(
        r: Result<
            Result<meridian_core::session::P2pSession<T>, SessionError>,
            tokio::time::error::Elapsed,
        >,
    ) -> Outcome {
        match r {
            Ok(Ok(mut s)) => {
                let _ = s.close().await;
                Outcome::Established
            }
            Ok(Err(e)) => Outcome::Rejected(e),
            Err(_) => Outcome::StillWaiting,
        }
    }
    (classify(a).await, classify(b).await)
}

/// **The adversarial case.** Two properties, asserted separately:
///   1. **Fail-closed:** neither side establishes a session. This is the security property.
///   2. **Detected:** at least one side rejects *explicitly*, with a reason — the rewrite is not
///      merely absorbed into a silent stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_rewriting_routed_blobs_is_detected_and_fails_closed() {
    let url = spawn_server(true);
    let (alice, bob) = establish_through(&url).await;
    eprintln!("[1.28] hostile relay → dialer: {alice:?} / responder: {bob:?}");

    // (1) Fail-closed. Neither side may come up.
    for (who, outcome) in [("dialer", &alice), ("responder", &bob)] {
        assert!(
            !matches!(outcome, Outcome::Established),
            "SECURITY FAILURE: the {who} established a P2P session through a rendezvous that was \
             actively rewriting routed signaling blobs. A relay-rewrite attempt must fail closed — \
             never be silently accepted (threat-model goal 6: no 'weaker session')."
        );
    }

    // (2) Detected — by the RESPONDER specifically, at the envelope-authentication layer.
    //
    // Pinning both the side and the error class is what stops this test passing vacuously. Accepting
    // "either side rejected with any message" would go green in a scenario where the hook had become
    // inert and an unrelated signaling regression made the dialer error out with
    // `Relay(..)`/`SignalingEnded`: nobody establishes (so (1) passes) and something errored (so a
    // loose (2) passes) — green test, untested property. The control case cannot catch that, since it
    // runs against an honest server.
    assert!(
        bob.is_envelope_rejection(),
        "the RESPONDER must reject the rewritten offer at the envelope-authentication layer \
         (SessionError::Chat). Anything else — Relay, SignalingEnded, Transport, or a stall — means \
         the rewrite was not actually detected and this test would otherwise pass vacuously. \
         Got: {bob:?}"
    );

    // (3) Detected on the dialer's side too, now that 1.33 bounds its wait: it must report
    // `SessionError::AnswerTimeout` — never a silent, undiagnosed stall (`StillWaiting`, which would
    // mean `SIDE_TIMEOUT` fired instead of the production bound) and never an unrelated
    // Relay/SignalingEnded/Transport error, which would mean this test is measuring something other
    // than the rewrite. `is_envelope_rejection` remains an accepted alternative only in case a future
    // change makes the dialer itself observe the tampering directly rather than merely outliving an
    // answer that never arrives — either is a real, explicit detection; a bare stall is not.
    assert!(
        alice.is_answer_timeout() || alice.is_envelope_rejection(),
        "the dialer must explicitly detect this — either its bounded answer-wait expires \
         (SessionError::AnswerTimeout, the expected outcome since 1.33) or it rejects at the \
         envelope layer — never an unrelated relay/transport error or an undiagnosed stall. \
         Got: {alice:?}"
    );
}

/// **Control.** The identical flow through an honest relay must establish on both sides, or the
/// assertions above are vacuous — they would pass on any unrelated breakage (a port mixup, a missing
/// bundle, a signaling regression).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_relay_establishes_the_same_session() {
    let url = spawn_server(false);
    let (alice, bob) = establish_through(&url).await;
    for (who, outcome) in [("dialer", &alice), ("responder", &bob)] {
        assert!(
            matches!(outcome, Outcome::Established),
            "control case: the {who} must establish through an HONEST relay, else the adversarial \
             assertions prove nothing. Got: {outcome:?}"
        );
    }
}
