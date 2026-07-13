//! End-to-end acceptance test for the T02 demo script
//! (docs/architecture/features/02-rendezvous-mvp.md "Working output").
//!
//! Runs the real `meridian-rendezvous` server in-process on an ephemeral port, then drives the
//! `meridian` CLI as a subprocess: `id new` → `register` (×2) → `fetch-bundle` (OK) →
//! `fetch-bundle --tamper` (FATAL, non-zero exit). Uses `ws://` (TLS is a proxy/VIP concern per
//! ADR-8); the demo in the docs shows `wss://`.

use std::process::{Command, Output};
use std::sync::mpsc;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Start the server on a background thread; returns its `ws://host:port` URL.
fn spawn_server(allow_tamper: bool) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut config = Config::default();
            config.server.allow_test_tamper = allow_tamper;
            let store = std::sync::Arc::new(MemoryStore::new());
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    format!("ws://{}", rx.recv().unwrap())
}

struct Client {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Client {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .output()
            .expect("failed to run meridian binary")
    }

    fn new_account(&self, keyfile: &str) {
        let out = self.run(&[
            "id",
            "new",
            "--store",
            "file",
            "--out",
            keyfile,
            "--hint",
            "localhost",
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn full_rendezvous_demo() {
    let server = spawn_server(true);

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let bob_id = bob.id();

    // Both register + publish a bundle.
    for (who, client) in [("bob", &bob), ("alice", &alice)] {
        let out = client.run(&["register", "--server", &server]);
        assert!(out.status.success(), "{who} register: {}", stderr(&out));
        assert!(
            stdout(&out).contains("published bundle with 100 one-time prekeys"),
            "{who} register output: {}",
            stdout(&out)
        );
    }

    // Alice fetches Bob's bundle and it verifies.
    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &server]);
    assert!(out.status.success(), "fetch-bundle: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("bundle OK"), "unexpected: {text}");
    assert!(text.contains("100 OTKs"), "unexpected: {text}");

    // With --tamper the server substitutes a key; the client must fail closed, non-zero exit.
    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &server, "--tamper"]);
    assert!(
        !out.status.success(),
        "tampered fetch must exit non-zero; stdout={}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("FATAL: bundle signature does not match requested identity"),
        "expected FATAL abort, got: {}",
        stderr(&out)
    );
}
