//! End-to-end acceptance test for the T03 demo script
//! (docs/architecture/features/03-e2ee-messaging-relayed.md "Working output").
//!
//! Runs the real `meridian-rendezvous` in-process, then drives two `meridian chat --json` clients
//! as subprocesses whose messages are relayed through the server. Asserts messages flow both ways
//! with delivery receipts, and that a killed-and-restarted client resumes the session from its
//! encrypted store (no re-handshake). It also runs the opacity-audit subcommand and checks it
//! reports zero leaks.

use std::io::Write;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

fn spawn_server() -> String {
    let (tx, rx) = mpsc::channel();
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
            .expect("run meridian")
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
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
    /// Spawn a `chat --json` process with piped stdin/stdout.
    fn spawn_chat(&self, server: &str, peer_id: &str) -> Child {
        Command::new(BIN)
            .args(["chat", peer_id, "--server", server, "--json"])
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn chat")
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn chat_relayed_both_ways_with_receipts_and_restart() {
    let server = spawn_server();
    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let alice_id = alice.id();
    let bob_id = bob.id();

    // Start both chat clients. Startup ordering is handled by the client (responder waits, the
    // initiator retries the bundle fetch), so we can launch them together.
    let mut a_proc = alice.spawn_chat(&server, &bob_id);
    let mut b_proc = bob.spawn_chat(&server, &alice_id);
    let mut a_in = a_proc.stdin.take().unwrap();
    let mut b_in = b_proc.stdin.take().unwrap();

    // Give both a moment to connect, publish, and (for the initiator) establish the session.
    std::thread::sleep(Duration::from_millis(1500));

    // Messages both ways.
    writeln!(a_in, "hello from alice").unwrap();
    a_in.flush().unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    writeln!(b_in, "hi alice, bob here").unwrap();
    b_in.flush().unwrap();
    std::thread::sleep(Duration::from_millis(1200));

    // EOF both → clean exit.
    drop(a_in);
    drop(b_in);
    let a_out = a_proc.wait_with_output().unwrap();
    let b_out = b_proc.wait_with_output().unwrap();
    let a_stdout = String::from_utf8_lossy(&a_out.stdout);
    let b_stdout = String::from_utf8_lossy(&b_out.stdout);

    // Bob received Alice's message; Alice received Bob's; both saw delivery receipts.
    assert!(
        b_stdout.contains("hi alice, bob here") || b_stdout.contains("\"event\":\"recv\""),
        "bob stdout: {b_stdout}\nstderr: {}",
        String::from_utf8_lossy(&b_out.stderr)
    );
    assert!(
        b_stdout.contains("hello from alice"),
        "bob did not receive alice's message. stdout: {b_stdout}\nstderr: {}",
        String::from_utf8_lossy(&b_out.stderr)
    );
    assert!(
        a_stdout.contains("hi alice, bob here"),
        "alice did not receive bob's message. stdout: {a_stdout}\nstderr: {}",
        String::from_utf8_lossy(&a_out.stderr)
    );
    assert!(
        a_stdout.contains("\"event\":\"receipt\""),
        "alice saw no delivery receipt. stdout: {a_stdout}"
    );

    // Restart Alice's client: the session store persists, so re-opening chat resumes the ratchet
    // (no re-handshake). Bob reconnects too so he's online to receive.
    let mut b_proc2 = bob.spawn_chat(&server, &alice_id);
    let b_in2 = b_proc2.stdin.take().unwrap();
    let mut a_proc2 = alice.spawn_chat(&server, &bob_id);
    let mut a_in2 = a_proc2.stdin.take().unwrap();
    std::thread::sleep(Duration::from_millis(1500));

    writeln!(a_in2, "back after restart").unwrap();
    a_in2.flush().unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    drop(a_in2);
    drop(b_in2);
    let a_out2 = a_proc2.wait_with_output().unwrap();
    let b_out2 = b_proc2.wait_with_output().unwrap();
    let a_stderr2 = String::from_utf8_lossy(&a_out2.stderr);
    let b_stdout2 = String::from_utf8_lossy(&b_out2.stdout);

    // The restarted client must NOT have re-run a handshake (it loaded the existing session), and
    // Bob must decrypt the post-restart message on the continued ratchet.
    assert!(
        !a_stderr2.contains("establishing session"),
        "restart re-handshook instead of resuming: {a_stderr2}"
    );
    assert!(
        b_stdout2.contains("back after restart"),
        "bob did not receive the post-restart message. stdout: {b_stdout2}\nstderr: {}",
        String::from_utf8_lossy(&b_out2.stderr)
    );
}

#[test]
fn opacity_audit_subcommand_reports_no_leaks() {
    let client = Client::new();
    let out = client.run(&[
        "demo",
        "opacity-audit",
        "transcript.pcapish",
        "--rounds",
        "20",
    ]);
    assert!(
        out.status.success(),
        "opacity audit failed: {}",
        stderr(&out)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("0 plaintext leaks"),
        "unexpected audit output: {text}"
    );
    assert!(
        client.work.path().join("transcript.pcapish").exists(),
        "transcript file not written"
    );
}
