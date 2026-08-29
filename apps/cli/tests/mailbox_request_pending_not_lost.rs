//! Task 8.17 regression: three offline messages queued to a **new** contact — the feature spec's
//! own headline demo scenario — must all eventually arrive, never silently lost. Before this task,
//! only the first (which triggers `ChatError::MessageRequest`, task 2.10's first-contact gate) was
//! ever shown: the second and third arrived in the same drain, hit `ChatError::RequestPending`
//! ("already gated... never merged into the pending request"), and were unconditionally acked and
//! deleted in the same loop iteration that dropped them — durably queued, successfully drained,
//! then silently, permanently discarded. This proves the fix: rows 2 and 3 survive un-acked past
//! the first reconnect (still present in the server's mailbox, verified via
//! `Store::mailbox_list_for_recipient` directly — the same technique task 8.13's own federation
//! test uses), and a second reconnect delivers both, correctly ordered.

use std::sync::Arc;
use std::time::Duration;

mod support;
use support::Client;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore, Store};

fn spawn_server() -> (String, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let store_for_server = store.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let state = AppState::new(Config::default(), store_for_server);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    (format!("ws://{}", rx.recv().unwrap()), store)
}

#[test]
fn three_offline_messages_to_a_new_contact_are_never_silently_lost() {
    let (server, store) = spawn_server();

    let alice = Client::new();
    alice.new_account("alice.key", "localhost");
    let alice_id = alice.id();
    let alice_ik = *meridian_core::identity::parse_id(&alice_id)
        .unwrap()
        .pubkey();

    // Deterministic-initiator requirement: alice sends first, so alice's key must be the smaller
    // one — mirrors `two_orgs_walkthrough.rs`/`federation_route_hint.rs`'s own identical loop.
    let bob = loop {
        let candidate = Client::new();
        candidate.new_account("bob.key", "localhost");
        let candidate_id = candidate.id();
        let candidate_ik = *meridian_core::identity::parse_id(&candidate_id)
            .unwrap()
            .pubkey();
        if alice_ik.as_slice() <= candidate_ik.as_slice() {
            break candidate;
        }
    };
    let bob_id = bob.id();
    let bob_ik = *meridian_core::identity::parse_id(&bob_id).unwrap().pubkey();

    // Bob publishes a bundle (task 8.16's fix makes this durable across processes), then never
    // connects again until explicitly reconnected below — genuinely offline throughout.
    let reg = bob.run(&["register", "--server", &server]);
    assert!(
        reg.status.success(),
        "bob register: {}",
        String::from_utf8_lossy(&reg.stderr)
    );

    // Alice sends three messages while bob is offline — the default (non-zero ttl_days) mailbox
    // durably queues all three.
    let mut alice_chat = alice.spawn_chat(&server, &bob_id);
    for i in 1..=3 {
        alice_chat.send(&format!("msg {i}"));
        std::thread::sleep(Duration::from_millis(300));
    }
    let (alice_out, alice_err) = alice_chat.finish();
    assert_eq!(
        alice_out.matches("\"event\":\"sent\"").count(),
        3,
        "all three sends must complete: stdout={alice_out:?} stderr={alice_err:?}"
    );

    let queued = tokio_test_block_on(store.mailbox_list_for_recipient(&bob_ik)).unwrap();
    assert_eq!(
        queued.len(),
        3,
        "all three messages must be durably queued before bob ever reconnects"
    );

    // Bob reconnects for the first time, accepts the first-contact request. Only message 1 is
    // decryptable at this point (it carries the X3DH opening prekey); 2 and 3 arrive in the same
    // drain but hit `ChatError::RequestPending` since the request is not yet accepted.
    let mut bob_chat = bob.spawn_chat(&server, &alice_id);
    support::wait_until(Duration::from_secs(10), || {
        bob_chat.out().contains("\"event\":\"message_request\"")
    });
    bob_chat.send("y");
    support::wait_until(Duration::from_secs(10), || {
        bob_chat.out().contains("\"event\":\"recv\"")
    });
    let (bob_out1, bob_err1) = bob_chat.finish();
    assert!(
        bob_out1.contains("\"event\":\"recv\"") && bob_out1.contains("msg 1"),
        "message 1 must decrypt on first accept: stdout={bob_out1:?} stderr={bob_err1:?}"
    );
    assert!(
        !bob_out1.contains("msg 2") && !bob_out1.contains("msg 3"),
        "messages 2 and 3 are not yet decryptable on this same connection (task 2.10's own \
         'never merged into the pending request' behavior, unchanged by this fix): {bob_out1:?}"
    );

    // The load-bearing assertion this task exists for: rows 2 and 3 must still be sitting in the
    // mailbox, un-acked — not silently deleted despite never having been shown to bob.
    let still_queued = tokio_test_block_on(store.mailbox_list_for_recipient(&bob_ik)).unwrap();
    assert_eq!(
        still_queued.len(),
        2,
        "messages 2 and 3 must survive, unacked, since they arrived before the request was \
         accepted — not silently lost: {still_queued:?}"
    );

    // Bob reconnects again — now that the request is accepted, both preserved rows redeliver,
    // correctly ordered. Polled (not a fixed sleep): draining+decrypting two ratchet messages
    // takes a variable amount of wall time under shared CI/sandbox load.
    let bob_chat2 = bob.spawn_chat(&server, &alice_id);
    support::wait_until(Duration::from_secs(10), || {
        bob_chat2.out().contains("msg 3")
    });
    let (bob_out2, bob_err2) = bob_chat2.finish();
    let msg2_pos = bob_out2.find("msg 2");
    let msg3_pos = bob_out2.find("msg 3");
    assert!(
        msg2_pos.is_some() && msg3_pos.is_some(),
        "both preserved messages must arrive on the next reconnect: stdout={bob_out2:?} \
         stderr={bob_err2:?}"
    );
    assert!(
        msg2_pos < msg3_pos,
        "must arrive in original order: {bob_out2:?}"
    );

    let final_queued = tokio_test_block_on(store.mailbox_list_for_recipient(&bob_ik)).unwrap();
    assert!(
        final_queued.is_empty(),
        "all three messages must be acked+deleted once genuinely delivered: {final_queued:?}"
    );
}

/// Small helper: block on a `Store` future from this file's plain (non-`#[tokio::test]`)
/// `#[test]` functions, which need a real OS thread each for the CLI subprocess I/O above (a
/// `#[tokio::test]` here would fight the CLI subprocess's own child process I/O for the runtime).
fn tokio_test_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}
