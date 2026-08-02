//! Task 1.32 — **malicious-relay attacks that PASS the envelope signature check.**
//!
//! [`relay_rewrite.rs`](./relay_rewrite.rs) (task 1.28) drives the *cheapest* relay attack: flipping
//! a byte of a routed blob. That attack is provably stopped at the Ed25519 envelope signature —
//! `MessageEnvelope` has four fields and its signing input covers `sender_pub + prekey + ct` with
//! `sig` the remainder, so every byte is either signed or is the signature. It therefore never
//! reaches the ratchet.
//!
//! A routing-only relay has strictly *stronger* attacks that need **no key material at all** and do
//! **not** touch the bytes, so the signature check waves them straight through:
//!
//! | mode | attack | asserted here |
//! |---|---|---|
//! | `spoof_from` | forge `Deliver.from`, which the server asserts itself | `ChatError::SenderMismatch`, on the recipient |
//! | `replay` | re-deliver a blob byte-identically | the duplicate is refused by the ratchet |
//! | `reorder` | release blobs out of order | tolerated: both open, nothing forged |
//! | `drop` | swallow a blob while acking `delivered: true` | message lost (conceded DoS), nothing forged |
//! | `cross_deliver` | hand a valid envelope to the wrong recipient | `ChatError::UnknownPrekey` |
//!
//! Each cell runs against a **real** in-process `meridian-rendezvous` built with
//! `test-tamper-hook`, with exactly one mode flag armed, and each pins the *specific* error variant
//! on the *specific* side. That precision is the point: 1.28's security review found that accepting
//! "somebody errored somehow" is exactly how these tests go green vacuously. Every adversarial cell
//! is paired with a control through an honest relay ([`honest_relay_delivers_faithfully`], plus the
//! in-test controls noted per cell), without which the fail-closed assertions would be satisfied by
//! any unrelated breakage.
//!
//! **Scope note.** These are the *routing*-layer attacks. Preamble mutation (`used_opk`,
//! `used_spk`) is deliberately NOT here: a relay cannot mount it — mutating the preamble is
//! mutating signed bytes, and the server has no envelope types to mutate them with — so it is driven
//! client-side in `apps/core/tests/preamble_mutation.rs`, which also carries the anti-DoS
//! (OTK-depth) assertions ADR 0016 asks for.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, AccountId, MemorySecretStore};
use meridian_core::signaling::{SignalingClient, DEFAULT_OTK_COUNT};
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

/// Long enough that it never bites a delivery that is actually coming (loopback deliveries land in
/// microseconds), short enough that a *swallowed* blob is diagnosed rather than hanging the suite.
const DELIVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Start a real server on an ephemeral port with `arm` applied to its config.
fn spawn_server(arm: impl FnOnce(&mut Config) + Send + 'static) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut config = Config::default();
            // All peers connect from 127.0.0.1 in-process.
            config.limits.auth_per_ip_per_min = 1_000_000;
            arm(&mut config);
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

/// Arm one 1.32 route-attack mode: both umbrella flags plus that mode's own flag.
fn arm_route(config: &mut Config, mode: fn(&mut meridian_rendezvous::config::Server)) {
    config.server.allow_test_tamper = true;
    config.server.allow_test_route_tamper = true;
    mode(&mut config.server);
}

struct Peer {
    store: MemorySecretStore,
    account: AccountId,
    chat: ChatState,
    client: SignalingClient,
}

impl Peer {
    /// Connect, publish a bundle, and record the matching prekey secrets in the vault.
    async fn join(hint: &str, url: &str) -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, hint).unwrap();
        let ik = *account.public_key().as_bytes();
        let mut client = SignalingClient::connect(url, &store, account.handle(), ik, None, 1)
            .await
            .expect("connect to rendezvous");
        let generated = client
            .publish_bundle(&store, account.handle(), DEFAULT_OTK_COUNT)
            .await
            .expect("publish bundle");
        let otks: Vec<([u8; 32], [u8; 32])> = generated
            .bundle
            .otks
            .iter()
            .zip(generated.otk_secrets.iter())
            .map(|(p, s)| (*p, **s))
            .collect();
        let mut chat = ChatState::default();
        chat.vault.set_bundle(
            generated.bundle.spk,
            *generated.spk_secret,
            otks,
            1_700_000_000,
        );
        Self {
            store,
            account,
            chat,
            client,
        }
    }

    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }

    /// Fetch + verify `peer`'s bundle and run X3DH against it.
    async fn start_session_with(&mut self, peer_ik: [u8; 32]) {
        let bundle = self
            .client
            .fetch_bundle(peer_ik, false)
            .await
            .expect("fetch peer bundle");
        let ik = self.ik();
        self.chat
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                &peer_ik,
                &bundle.spk,
                bundle.otks.first().copied(),
            )
            .expect("x3dh");
    }

    /// Seal `body` for `peer_ik` and route it. Returns `(blob, server's delivered ack)`.
    async fn send(&mut self, peer_ik: [u8; 32], id: u8, body: &str) -> (Vec<u8>, bool) {
        let ik = self.ik();
        let blob = self
            .chat
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                &peer_ik,
                &ChatContent::Text {
                    id: [id; 16],
                    body: body.into(),
                },
            )
            .expect("seal");
        let acked = self
            .client
            .route(peer_ik, blob.clone())
            .await
            .expect("route");
        (blob, acked)
    }

    /// Await the next delivery and try to open it *exactly as a real client would*: with the
    /// routing origin the SERVER claimed, which under `spoof_from` is a lie.
    ///
    /// This file exercises routing-layer attacks, not the task-2.10 request-queue UX (see
    /// `apps/core/tests/message_request_gate.rs` for that): a first contact is transparently
    /// auto-accepted so a genuine first envelope still reads as `Opened`, matching the pre-2.10
    /// behaviour every assertion below was written against.
    async fn recv(&mut self) -> Received {
        let deliver = match tokio::time::timeout(DELIVER_TIMEOUT, self.client.next_deliver()).await
        {
            Err(_) => return Received::Nothing,
            Ok(Err(e)) => panic!("signaling error while awaiting a delivery: {e:?}"),
            Ok(Ok(d)) => d,
        };
        let ik = self.ik();
        let blob = deliver.blob.as_bytes().to_vec();
        let outcome = self.chat.open_inbound(
            &self.store,
            self.account.handle(),
            &ik,
            &deliver.from,
            &blob,
        );
        match outcome {
            Ok(content) => Received::Opened { content, blob },
            Err(ChatError::MessageRequest) => {
                let content = self
                    .chat
                    .accept_request(&deliver.from)
                    .expect("just gated by open_inbound")
                    .intro;
                Received::Opened { content, blob }
            }
            Err(e) => Received::Rejected(e),
        }
    }
}

/// What happened to one delivered blob. `Rejected` keeps the classified [`ChatError`], not its text:
/// matching on the variant is what makes the assertions below non-vacuous, and it survives ADR 0016
/// moving the detector from the signature to the ratchet AEAD.
enum Received {
    Opened {
        content: ChatContent,
        blob: Vec<u8>,
    },
    Rejected(ChatError),
    /// Nothing arrived within [`DELIVER_TIMEOUT`] — the relay swallowed it.
    Nothing,
}

/// Hand-written so a failure message stays readable: the derived `Debug` would dump ~400 bytes of
/// envelope per outcome, which buries the assertion text these cells rely on for diagnosability.
impl std::fmt::Debug for Received {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Received::Opened { content, blob } => {
                write!(f, "Opened({content:?}, {} blob bytes)", blob.len())
            }
            Received::Rejected(e) => write!(f, "Rejected({e:?})"),
            Received::Nothing => f.write_str("Nothing"),
        }
    }
}

impl Received {
    fn body(&self) -> Option<&str> {
        match self {
            Received::Opened {
                content: ChatContent::Text { body, .. },
                ..
            } => Some(body),
            _ => None,
        }
    }
}

// -- control ------------------------------------------------------------------

/// **The control for every cell below.** The identical flow through an honest relay delivers both
/// messages, in order, exactly once, and both open. Without this, "the message did not open" would
/// be satisfied by a port mixup, a missing bundle, or any signaling regression, and every
/// adversarial assertion here would prove nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_relay_delivers_faithfully() {
    let url = spawn_server(|_| {});
    let mut alice = Peer::join("attack.a", &url).await;
    let mut bob = Peer::join("attack.b", &url).await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start_session_with(bob_ik).await;

    let (_, acked) = alice.send(bob_ik, 1, "one").await;
    assert!(acked);
    alice.send(bob_ik, 2, "two").await;

    let first = bob.recv().await;
    assert_eq!(first.body(), Some("one"), "control: got {first:?}");
    let second = bob.recv().await;
    assert_eq!(second.body(), Some("two"), "control: got {second:?}");
    assert!(
        bob.chat.has_session(&alice_ik),
        "control: the responder session must be installed"
    );
    assert!(
        matches!(bob.recv().await, Received::Nothing),
        "control: an honest relay delivers nothing extra"
    );
}

// -- 1. forged Deliver.from ---------------------------------------------------

/// **`spoof_from`.** The server sets `Deliver.from` itself, so forging it costs nothing and leaves
/// the signed envelope untouched — the signature check passes. `ChatState::open_bytes` catches it by
/// comparing the *signed* `sender_pub` against the routing origin.
///
/// Pinned precisely: the RECIPIENT must reject with [`ChatError::SenderMismatch`] specifically.
/// `BadSignature` or `Crypto` would mean something *else* stopped the blob and this cell is measuring
/// the wrong thing; `Opened` would be the security failure. Also asserts the two properties the task
/// calls fail-closed: no session is installed, and nothing is accepted.
///
/// This is also ADR 0016's "forged prekey envelope claiming `from = Alice`" obligation, mounted by a
/// real hostile server rather than by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_deliver_from_is_rejected_as_sender_mismatch() {
    let url = spawn_server(|c| arm_route(c, |s| s.allow_test_route_spoof_from = true));
    let mut alice = Peer::join("spoof.a", &url).await;
    let mut bob = Peer::join("spoof.b", &url).await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start_session_with(bob_ik).await;

    alice.send(bob_ik, 1, "hello bob").await;
    let got = bob.recv().await;
    eprintln!("[1.32/spoof_from] responder: {got:?}");

    match got {
        Received::Rejected(ChatError::SenderMismatch) => {}
        other => panic!(
            "the RECIPIENT must reject a forged routing origin with ChatError::SenderMismatch. \
             Anything else means this cell is not measuring the `from` check — and `Opened` would \
             be a SECURITY FAILURE: a relay would be able to attribute any envelope to any account. \
             Got: {other:?}"
        ),
    }
    assert!(
        !bob.chat.has_session(&alice_ik),
        "a rejected envelope must install NO session (fail closed)"
    );
    // COUPLED, DELIBERATELY: this recomputes the hook's forging scheme (`spoofed[0] ^= 0x01`) from
    // `meridian_rendezvous::route_tamper::RouteTamper::plan`. Keep the two in step — if the hook ever
    // flips a different byte and this is not updated, the assertion silently goes vacuous: it would
    // assert the absence of a session under a key nobody ever claimed, which is trivially true.
    // (The coupling-free alternative — "no session under ANY key" — would need a `session_count()`
    // accessor on `ChatState`, i.e. new public API, which task 1.32's `Out:` puts out of scope.)
    assert!(
        !bob.chat.has_session(&{
            let mut spoofed = alice_ik;
            spoofed[0] ^= 0x01;
            spoofed
        }),
        "and certainly no session under the FORGED identity"
    );
}

// -- 2. replay ----------------------------------------------------------------

/// **`replay`.** The relay re-delivers a byte-identical copy of a blob it already forwarded. Nothing
/// is mutated, so the Ed25519 signature verifies on the duplicate exactly as it did on the original:
/// this attack reaches the **ratchet**, which is precisely what 1.28 could not do.
///
/// Asserted: the first copy opens (that is the built-in control — it proves the flow works and that
/// the second copy really is a duplicate of a *delivered* message), and the second copy is
/// **refused**, not accepted a second time. The rejection class is pinned to
/// [`ChatError::Crypto`]/[`ChatError::Desync`] — the ratchet layer — because that is where replay
/// protection has to live; a `SenderMismatch`/`BadSignature` here would mean the duplicate was not
/// actually byte-identical and the cell is vacuous.
///
/// **Session survival (task 2.13).** A single replay must degrade exactly the one duplicate
/// message, not the session: `DoubleRatchet::decrypt` (`apps/crypto/src/ratchet.rs`) is now
/// failure-atomic (stages its mutations on a scratch clone and only commits them once `aead_open`
/// succeeds), so a rejected duplicate leaves `ckr`/`nr` untouched and a genuine subsequent message
/// from the same sender still opens. Before that fix `ckr`/`nr` were advanced before `aead_open`
/// ran and never rolled back on failure, permanently wedging the chain one step ahead of the
/// sender — an unauthenticated, key-material-free, permanent session DoS mountable by any relay
/// (and by benign duplicate delivery too). See `apps/crypto/tests/ratchet_replay.rs` for the
/// ratchet-level regression coverage of that property; this cell is the end-to-end proof through a
/// real relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_delivery_is_not_accepted_twice() {
    let url = spawn_server(|c| arm_route(c, |s| s.allow_test_route_replay = true));
    let mut alice = Peer::join("replay.a", &url).await;
    let mut bob = Peer::join("replay.b", &url).await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start_session_with(bob_ik).await;

    let (sent_blob, _) = alice.send(bob_ik, 1, "only once").await;

    let first = bob.recv().await;
    assert_eq!(
        first.body(),
        Some("only once"),
        "the original must open — otherwise there is no replay to test. Got: {first:?}"
    );
    let Received::Opened { blob, .. } = &first else {
        unreachable!()
    };
    assert_eq!(
        blob, &sent_blob,
        "the relay must forward the original unmodified — this cell tests replay, not rewrite"
    );

    let second = bob.recv().await;
    eprintln!("[1.32/replay] duplicate: {second:?}");
    match second {
        Received::Rejected(ChatError::Crypto(_)) | Received::Rejected(ChatError::Desync) => {}
        Received::Nothing => panic!(
            "the hook did not actually replay anything — this cell would be vacuous. Check that \
             allow_test_route_replay is armed."
        ),
        other => panic!(
            "a byte-identical replay must be refused BY THE RATCHET (ChatError::Crypto/Desync — the \
             message key for that counter is gone). `Opened` would be a SECURITY FAILURE: the \
             application would see the same message twice from one send. A signature/sender error \
             would mean the duplicate was not byte-identical, making this cell vacuous. Got: {other:?}"
        ),
    }

    // SESSION SURVIVAL (task 2.13): the rejected duplicate must not have wedged the ratchet. A
    // genuine subsequent message from alice must still open normally.
    assert!(
        bob.chat.has_session(&alice_ik),
        "a rejected replay must not tear down the session"
    );
    alice.send(bob_ik, 2, "still works").await;
    let third = bob.recv().await;
    assert_eq!(
        third.body(),
        Some("still works"),
        "a genuine message after a rejected replay must still decrypt — before task 2.13's fix, \
         the ratchet's `ckr`/`nr` were left advanced past what the sender actually rides, and every \
         subsequent genuine message from that sender failed with ChatError::Crypto forever. \
         Got: {third:?}"
    );
}

// -- 3. reorder ---------------------------------------------------------------

/// **`reorder`.** The relay holds one blob and releases it *behind* the next one. Unlike the other
/// cells this one must **succeed**: reordering is a pure permutation of authentic messages, it is
/// exactly what a lossy network does, and the Double Ratchet's skipped-message keys exist to
/// tolerate it. Failing closed here would be a bug (a trivially-mountable relay DoS), not a defence.
///
/// So the asserted property is: **nothing is forged and nothing is lost** — both messages open, with
/// their correct bodies, despite arriving 2-then-1.
///
/// Non-vacuity is enforced *inside* the test: it asserts the arrival order really was swapped
/// against the send order (comparing blob bytes), so if the hook became inert this cell fails rather
/// than silently degenerating into the honest control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reordered_delivery_is_tolerated_without_forgery() {
    let url = spawn_server(|c| arm_route(c, |s| s.allow_test_route_reorder = true));
    let mut alice = Peer::join("reorder.a", &url).await;
    let mut bob = Peer::join("reorder.b", &url).await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start_session_with(bob_ik).await;

    let (blob1, acked1) = alice.send(bob_ik, 1, "first").await;
    assert!(
        acked1,
        "a relay that withholds a blob still acks it as delivered — the client cannot tell"
    );
    let (blob2, _) = alice.send(bob_ik, 2, "second").await;

    let a = bob.recv().await;
    let b = bob.recv().await;
    eprintln!("[1.32/reorder] arrival: {a:?} then {b:?}");

    let (Received::Opened { blob: got1, .. }, Received::Opened { blob: got2, .. }) = (&a, &b)
    else {
        panic!(
            "both reordered messages must open: reorder is a network condition the ratchet's \
             skipped-key handling must tolerate, not an attack to fail closed on. Got {a:?} / {b:?}"
        )
    };
    assert!(
        got1 == &blob2 && got2 == &blob1,
        "NON-VACUITY: the relay must actually have swapped the two blobs. If they arrived in send \
         order the hook is inert and this cell is just the honest control."
    );
    assert_eq!(a.body(), Some("second"));
    assert_eq!(b.body(), Some("first"));
    assert!(bob.chat.has_session(&alice_ik));

    // A permutation must not DUPLICATE. Without this, a hook that reordered *and* replayed would
    // satisfy every assertion above (both blobs opened, order swapped) and this cell would go green
    // on an attack it does not model. Mirrors the same tail in the drop and cross-deliver cells.
    assert!(
        matches!(bob.recv().await, Received::Nothing),
        "a reorder must permute deliveries, never add one: a third delivery means the relay \
         duplicated a blob, which is the replay attack and is asserted separately."
    );

    // ...and must not WEDGE the session. The swap leaves msg 1 opened from the skipped-key store —
    // the only cell in this suite that exercises that path — so the receiving chain's head is now
    // ahead of a message that was opened out of band. A SECOND round proves the ratchet recovered
    // rather than merely survived the two it was handed. This is deliberately pinned here for
    // contrast with the adjacent replay cell: reorder is a permutation of authentic messages and is
    // tolerated outright (nothing is ever rejected); replay is a duplicate and its second copy IS
    // rejected — but (task 2.13) rejecting it no longer wedges the session either, so both cells now
    // prove "session survives", just via different mechanisms (skipped-key recovery vs. a
    // failure-atomic `decrypt` that discards its would-be state changes on the rejected copy).
    //
    // It takes a *pair*, not a single message: the mode holds one blob and releases it behind the
    // next, so a lone msg 3 would sit in the hook's buffer and this would assert a hook property,
    // not a ratchet one.
    alice.send(bob_ik, 3, "third").await;
    alice.send(bob_ik, 4, "fourth").await;
    let (c, d) = (bob.recv().await, bob.recv().await);
    assert_eq!(
        (c.body(), d.body()),
        (Some("fourth"), Some("third")),
        "after a tolerated reorder the session must keep working: a second reordered pair must \
         still open, both messages, correct bodies. Got {c:?} / {d:?}"
    );
}

// -- 4. drop ------------------------------------------------------------------

/// **`drop`.** The relay swallows the first blob and still replies `route_ok{delivered:true}`.
///
/// Threat-model goal 6 concedes that a malicious server can deny service, so the asserted property
/// is *not* "the message arrives". It is that denial stays denial: the lost message is **never**
/// delivered (not late, not substituted), the session that does come up is authentic, and the sender
/// gets no cryptographic assurance from the ack — which is why `acked` being `true` here is asserted
/// rather than treated as a bug. It is the lie, reproduced faithfully.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_delivery_is_lost_but_never_forged() {
    let url = spawn_server(|c| arm_route(c, |s| s.allow_test_route_drop = true));
    let mut alice = Peer::join("drop.a", &url).await;
    let mut bob = Peer::join("drop.b", &url).await;
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    alice.start_session_with(bob_ik).await;

    let (_, acked) = alice.send(bob_ik, 1, "swallowed").await;
    assert!(
        acked,
        "NON-VACUITY / the attack itself: the server must claim delivery for a blob it swallowed. \
         If this were false the client could simply believe the ack, and the cell below would be \
         measuring an honest 'not delivered' response instead of a silent drop."
    );
    alice.send(bob_ik, 2, "arrives").await;

    let got = bob.recv().await;
    eprintln!("[1.32/drop] responder: {got:?}");
    assert_eq!(
        got.body(),
        Some("arrives"),
        "the surviving message must open normally — a dropping relay cannot corrupt what it does \
         forward. Got: {got:?}"
    );
    assert!(bob.chat.has_session(&alice_ik));
    assert!(
        matches!(bob.recv().await, Received::Nothing),
        "the swallowed message must be GONE — never delivered late, and never substituted by \
         anything the relay made up"
    );
}

// -- 5. cross-delivery --------------------------------------------------------

/// **`cross_deliver`.** The relay captures a genuine, correctly-signed Alice→Bob envelope and hands
/// it to **Carol**, with its original `from` intact. Nothing is forged: the signature verifies and
/// the routing origin matches the signed sender, so both of the checks that stop the other cells
/// wave this through. What stops it is that the X3DH preamble names *Bob's* signed prekey, which
/// Carol does not hold the secret for → [`ChatError::UnknownPrekey`].
///
/// The cell carries its own control: the very next delivery is Alice's *real* envelope to Carol,
/// which must open. So "Carol rejects everything" cannot pass this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_delivered_envelope_is_rejected_as_unknown_prekey() {
    let url = spawn_server(|c| arm_route(c, |s| s.allow_test_route_cross_deliver = true));
    let mut alice = Peer::join("cross.a", &url).await;
    let mut bob = Peer::join("cross.b", &url).await;
    let mut carol = Peer::join("cross.c", &url).await;
    let (alice_ik, bob_ik, carol_ik) = (alice.ik(), bob.ik(), carol.ik());

    // Session 1: Alice → Bob. This is the envelope the relay captures.
    alice.start_session_with(bob_ik).await;
    alice.send(bob_ik, 1, "for bob only").await;
    let bobs = bob.recv().await;
    assert_eq!(
        bobs.body(),
        Some("for bob only"),
        "the captured envelope must be a genuine, openable one — otherwise the cross-delivery below \
         proves nothing. Got: {bobs:?}"
    );

    // Session 2: Alice → Carol. The relay injects the captured Alice→Bob envelope first.
    alice.start_session_with(carol_ik).await;
    alice.send(carol_ik, 2, "for carol").await;

    let injected = carol.recv().await;
    eprintln!("[1.32/cross_deliver] carol, injected: {injected:?}");
    match injected {
        Received::Rejected(ChatError::UnknownPrekey) => {}
        Received::Nothing => panic!(
            "nothing was injected — the hook is inert and this cell would be vacuous. Check that \
             allow_test_route_cross_deliver is armed."
        ),
        other => panic!(
            "an envelope belonging to a DIFFERENT session must be rejected with \
             ChatError::UnknownPrekey: it is correctly signed and its `from` matches, so only the \
             prekey preamble — which names Bob's SPK, not Carol's — can stop it. `Opened` would be a \
             SECURITY FAILURE. Got: {other:?}"
        ),
    }
    assert!(
        !carol.chat.has_session(&alice_ik),
        "the rejected cross-delivery must install NO session — otherwise it would poison the real \
         one that follows"
    );

    // Built-in control: Alice's real envelope to Carol still opens, right behind the rejected one.
    let real = carol.recv().await;
    assert_eq!(
        real.body(),
        Some("for carol"),
        "the genuine envelope must still open after the cross-delivered one was refused — proving \
         the rejection above is specific to the misrouted envelope and not a blanket failure. \
         Got: {real:?}"
    );
    assert!(carol.chat.has_session(&alice_ik));
}
