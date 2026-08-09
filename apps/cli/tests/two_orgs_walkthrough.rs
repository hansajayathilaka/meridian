//! Task 2.12 deliverable 2: the `demo/two-orgs/run-walkthrough.sh` acceptance walkthrough (Feature
//! 06, §7.1) as a proper `cargo test` — CI-wired, in-process, no docker — **complementing**, not
//! replacing, the shell demo (which additionally proves the docker-compose topology, the private
//! CA bootstrap, air-gap network isolation, and real coturn TURN; see that script's own header).
//!
//! Two acceptance properties, each requiring bidirectional federation (both orgs dial each other —
//! unlike `federation_route_hint.rs`'s one-way harness, this needs the receiving side to route an
//! auto-ack/answer BACK across the same boundary):
//!
//! 1. [`cli_walkthrough_message_request_gate_then_delivery`] — two real `meridian chat --json`
//!    processes, one per org, driven exactly like the shell script's step 3: alice sends first,
//!    bob's first-contact gate (task 2.10) fires, accepting delivers the held intro.
//! 2. [`killing_both_rendezvous_servers_after_p2p_established_does_not_interrupt_the_data_channel`]
//!    — task 2.12 deliverable 6, the T04 "servers out of the data path" property, now proven
//!    cross-org: a real P2P session is established via signaling that genuinely crosses TWO real,
//!    federated `meridian-rendezvous` instances, both of which are then **killed** (their listener
//!    tasks aborted, not merely a `MemRelay` dropped), and the already-established data channel
//!    must keep carrying chat.

use std::sync::Arc;
use std::time::Duration;

mod support;
use support::{wait_until, Client};

// -- 1. CLI-level walkthrough: message-request gate then delivery, cross-org --------------------

/// Mirrors `demo/two-orgs/run-walkthrough.sh` step 3 exactly (bob online first, alice sends,
/// bob's first-contact gate fires, accepting delivers the intro) as an in-process `cargo test` —
/// this is the "CLI-level acceptance walkthrough as a proper cargo test" task 2.12 deliverable 2
/// calls for, complementing (not replacing) the shell demo.
#[test]
fn cli_walkthrough_message_request_gate_then_delivery() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let rig = rt.block_on(support::boot_federated_pair_bidirectional());

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");
    let alice_id = alice.id();
    let alice_ik = *meridian_core::identity::parse_id(&alice_id)
        .unwrap()
        .pubkey();

    // `chat.rs` decides the X3DH initiator by key order (`account_pub <= peer_ik`), independent of
    // who types first — this walkthrough's flow below hardcodes "alice sends first, bob is the one
    // who gets gated," so alice must actually BE the initiator. Regenerate bob's account (a fresh
    // `Client`, i.e. a fresh keypair) until that holds, exactly like
    // `federation_route_hint.rs`'s identical `loop { ... }` for the same reason.
    let bob = loop {
        let candidate = Client::new();
        candidate.new_account("bob.key", "org-b.test");
        let candidate_id = candidate.id();
        let candidate_ik = *meridian_core::identity::parse_id(&candidate_id)
            .unwrap()
            .pubkey();
        if alice_ik.as_slice() <= candidate_ik.as_slice() {
            break candidate;
        }
    };
    let bob_id = bob.id();

    // Bob must be online (connected + publishing) before alice's first message, exactly like the
    // shell script's ordering ("must be online before initiator sends the opening message").
    let mut b = bob.spawn_chat(&rig.b_c2s_url, &alice_id);
    std::thread::sleep(Duration::from_millis(500));

    let mut a = alice.spawn_chat(&rig.a_c2s_url, &bob_id);
    std::thread::sleep(Duration::from_millis(500));

    let msg = format!("hello-across-orgs-{}", std::process::id());
    let sent = wait_until(Duration::from_secs(15), || {
        a.send(&msg);
        std::thread::sleep(Duration::from_millis(400));
        a.out().contains("\"event\":\"sent\"")
    });
    assert!(
        sent,
        "alice never reported a 'sent' event.\nstdout: {}\nstderr: {}",
        a.out(),
        a.err()
    );
    assert!(
        a.out().contains("\"delivered\":true"),
        "alice's route to bob must report delivered:true (bob is online).\nstdout: {}\nstderr: {}",
        a.out(),
        a.err()
    );

    // The first-contact gate (task 2.10, §3.5): bob's FIRST envelope from alice must land as a
    // message_request, never an immediate `recv`.
    let gated = wait_until(Duration::from_secs(15), || {
        b.out().contains("\"event\":\"message_request\"")
    });
    assert!(
        gated,
        "bob never saw a message_request event — the first-contact gate did not fire.\n\
         stdout: {}\nstderr: {}",
        b.out(),
        b.err()
    );
    assert!(
        !b.out().contains("\"event\":\"recv\""),
        "bob must NOT see a bare recv before accepting the request: {}",
        b.out()
    );

    // Accept — the auto-ack this triggers (chat.rs's `deliver_content`) must cross BACK from
    // org-b to org-a, which is exactly why this harness federates bidirectionally.
    b.send("y");
    let accepted = wait_until(Duration::from_secs(10), || {
        b.out().contains("\"event\":\"request_accepted\"")
    });
    assert!(
        accepted,
        "bob's accept did not register: {}\n{}",
        b.out(),
        b.err()
    );
    let delivered = wait_until(Duration::from_secs(10), || {
        b.out().contains(&format!("\"body\":\"{msg}\""))
    });
    assert!(
        delivered,
        "bob never received the plaintext body after accepting: {}\n{}",
        b.out(),
        b.err()
    );

    a.finish();
    b.finish();
    rig.kill_both_servers();
}

// -- 2. Continuity: kill both rendezvous servers, the P2P data channel survives ------------------
//
// Task 2.12 deliverable 6 — the T04 property (`apps/core/tests/p2p_session.rs::
// server_down_chat_continuity`), now proven cross-org: the SIGNALING (SDP offer/answer) genuinely
// crosses two real, federated `meridian-rendezvous` instances (real sockets, real mTLS s2s link,
// real federated route/reachability checks) — the DATA plane uses `LoopbackTransport` (the same
// deterministic substrate `p2p_session.rs` uses), so the property under test — "does chat keep
// flowing once the servers are gone" — is isolated from real-network flakiness while the signaling
// half is still fully real. Both rendezvous servers are then genuinely KILLED (their listener
// tasks aborted — see `TwoOrgs::kill_both_servers` — not merely an in-process channel dropped),
// and the already-established P2P session must keep carrying chat both ways.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killing_both_rendezvous_servers_after_p2p_established_does_not_interrupt_the_data_channel()
{
    use meridian_core::chat::{ChatError, ChatState};
    use meridian_core::envelope::ChatContent;
    use meridian_core::identity::{generate_account, AccountId, KeyHandle, MemorySecretStore};
    use meridian_core::session::{answer, dial, SessionError, SessionEvent};
    use meridian_core::signal_relay::RendezvousRelay;
    use meridian_core::signaling::{generate_bundle, SignalingClient};
    use meridian_core::streams::StreamRegistry;
    use meridian_core::transport::{LoopbackFabric, LoopbackTransport};

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

    let rig = support::boot_federated_pair_bidirectional().await;

    let mut alice = Peer::new("continuity.a");
    let mut bob = Peer::new("continuity.b");
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

    // X3DH established directly (like `p2p_session.rs::establish_ratchet`) — this is not the
    // property under test (that's `federation_fetch.rs`'s job); what must be real here is the
    // SIGNALING transport the dial/answer handshake itself uses.
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
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks, 1_700_000_000);
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

    // REAL signaling connections to each org's OWN server (alice only ever talks to org-a, bob
    // only ever talks to org-b) — the cross-org hop happens entirely inside the two rendezvous
    // servers' federation link, never on the client side.
    let mut alice_client = SignalingClient::connect(
        &rig.a_c2s_url,
        &alice.store,
        &alice.handle(),
        alice_ik,
        None,
        1,
    )
    .await
    .expect("alice connects to org-a");
    let mut bob_client =
        SignalingClient::connect(&rig.b_c2s_url, &bob.store, &bob.handle(), bob_ik, None, 1)
            .await
            .expect("bob connects to org-b");

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric));
    let reg_a = Arc::new(StreamRegistry::with_builtins());
    let reg_b = Arc::new(StreamRegistry::with_builtins());

    let (ra, rb) = {
        let mut relay_a = RendezvousRelay::new(&mut alice_client, Some("org-b.test".to_string()));
        let mut relay_b = RendezvousRelay::new(&mut bob_client, Some("org-a.test".to_string()));
        let (astore, ahandle) = (&alice.store, alice.handle());
        let (bstore, bhandle) = (&bob.store, bob.handle());
        tokio::join!(
            dial(
                ta.clone(),
                astore,
                &ahandle,
                alice_ik,
                bob_ik,
                &mut alice.chat,
                &mut relay_a,
                reg_a,
            ),
            answer(
                tb.clone(),
                bstore,
                &bhandle,
                bob_ik,
                alice_ik,
                &mut bob.chat,
                &mut relay_b,
                reg_b,
            ),
        )
    };
    let mut asess = ra.expect("dial established across a REAL federated signaling path");
    let mut bsess = rb.expect("answer established across a REAL federated signaling path");

    // Fingerprints bound and agree — §4.6 passed over the real cross-org signaling hop.
    let (a_local, a_remote) = asess.fingerprints();
    let (b_local, b_remote) = bsess.fingerprints();
    assert_eq!(a_local, b_remote);
    assert_eq!(b_local, a_remote);

    // Servers no longer needed for the data plane (T04's property) — drop the still-open
    // signaling sockets, then KILL BOTH RENDEZVOUS SERVERS OUTRIGHT (task 2.12 deliverable 6).
    let _ = alice_client.close().await;
    let _ = bob_client.close().await;
    rig.kill_both_servers();
    // Give the aborted tasks a moment to actually unwind and drop their listening sockets, so a
    // regression that left a server half-alive would have a real chance to show up below rather
    // than racing a not-yet-cancelled task.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Chat now flows peer-to-peer over the LoopbackTransport data channel with NO rendezvous
    // server reachable at all — both orgs' listeners are gone.
    let ahandle = alice.handle();
    let bhandle = bob.handle();
    asess
        .send_chat(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "hello after both servers are dead",
        )
        .await
        .expect("send must still work with both rendezvous servers killed");
    // (task 2.14) This is Bob's first-ever P2P content from Alice, so it's gated exactly like the
    // relay path (2.10) — accept it (mirroring the CLI's accept/reject UX) before asserting this
    // test's actual subject, continuity after both servers are killed.
    match bsess.pump(&bob.store, &bhandle, &mut bob.chat).await {
        Err(SessionError::Chat(ChatError::MessageRequest)) => {
            let req = bob
                .chat
                .accept_request(&alice_ik)
                .expect("open_inbound_gated just inserted this request");
            match req.intro {
                ChatContent::Text { body, .. } => {
                    assert_eq!(body, "hello after both servers are dead");
                }
                other => panic!("unexpected gated intro: {other:?}"),
            }
        }
        Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
            assert_eq!(body, "hello after both servers are dead");
        }
        other => panic!("pump must still work with both rendezvous servers killed: {other:?}"),
    }

    bsess
        .send_chat(
            &bob.store,
            &bhandle,
            &mut bob.chat,
            "confirmed — still no server in the path",
        )
        .await
        .expect("reply must still work with both rendezvous servers killed");
    match asess
        .pump(&alice.store, &ahandle, &mut alice.chat)
        .await
        .expect("pump must still work with both rendezvous servers killed")
    {
        Some(SessionEvent::Chat(ChatContent::Text { body, .. })) => {
            assert_eq!(body, "confirmed — still no server in the path");
        }
        other => panic!("alice expected chat after server kill, got {other:?}"),
    }
}
