//! Task 8.16 regression: `meridian register` ("Register the current account with a rendezvous
//! server and publish a prekey bundle") must durably persist the *secret* scalars matching the
//! *public* bundle it publishes — not just discard them after reading `otk_count()` off the
//! result, which is what `cmd_register` did before this task. A peer who X3DH-initiates against a
//! bundle published only via `register` must be decryptable by a **separate, later** `meridian
//! chat` process invocation against the same account — not merely within the same long-running
//! process, which would never have exposed the bug (`chat.rs::run`'s own inline publish call
//! already persisted correctly; only the standalone `register` subcommand did not).

use std::time::Duration;

mod support;
use support::Client;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

fn spawn_server() -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let store = std::sync::Arc::new(MemoryStore::new());
            let state = AppState::new(Config::default(), store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    format!("ws://{}", rx.recv().unwrap())
}

/// `bob` publishes a bundle via a standalone `meridian register` process, then genuinely exits
/// (the process is gone — nothing about its in-memory state can leak into what happens next).
/// `alice`, in a completely independent process, X3DH-initiates against that published bundle.
/// `bob`, in a **third**, separate process, must be able to decrypt it — proving `register`'s own
/// publish durably persisted the matching secrets to `bob`'s on-disk keystore, not merely to the
/// now-dead `register` process's memory.
#[test]
fn register_then_a_separate_chat_process_can_decrypt_against_it() {
    let server = spawn_server();

    let alice = Client::new();
    alice.new_account("alice.key", "localhost");
    let alice_id = alice.id();
    let alice_ik = *meridian_core::identity::parse_id(&alice_id)
        .unwrap()
        .pubkey();

    // Deterministic-initiator requirement (`chat.rs`'s own module doc): alice needs to be the one
    // who sends first here, so alice's key must be the smaller one — mirrors
    // `two_orgs_walkthrough.rs`/`federation_route_hint.rs`'s own identical loop.
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

    // Bob: standalone `register`, then the process exits — nothing further about this run is
    // reachable.
    let reg = bob.run(&["register", "--server", &server]);
    assert!(
        reg.status.success(),
        "meridian register failed: {}",
        String::from_utf8_lossy(&reg.stderr)
    );

    // Alice: a fresh process, X3DH-initiates against bob's published bundle.
    let mut alice_chat = alice.spawn_chat(&server, &bob_id);
    alice_chat.send("can you read this?");
    std::thread::sleep(Duration::from_millis(600));
    let (alice_out, alice_err) = alice_chat.finish();
    assert!(
        alice_out.contains("\"event\":\"sent\""),
        "alice's send must succeed: stdout={alice_out:?} stderr={alice_err:?}"
    );

    // Bob: a THIRD, separate process — the only thing connecting it to the `register` process
    // above is bob's own on-disk `MERIDIAN_HOME` (`Client::home`, reused by both calls).
    let mut bob_chat = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(800));
    // First contact — accept it, then the intro should be visible.
    bob_chat.send("y");
    std::thread::sleep(Duration::from_millis(600));
    let (bob_out, bob_err) = bob_chat.finish();
    assert!(
        bob_out.contains("\"event\":\"recv\"") && bob_out.contains("can you read this?"),
        "bob (a separate later process) must decrypt alice's message against the bundle \
         `register` published — got stdout={bob_out:?} stderr={bob_err:?}"
    );
}
