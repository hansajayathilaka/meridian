//! End-to-end acceptance test for the T03 demo script
//! (docs/architecture/features/03-e2ee-messaging-relayed.md "Working output").
//!
//! Runs the real `meridian-rendezvous` in-process, then drives two `meridian chat --json` clients
//! as subprocesses whose messages are relayed through the server. Asserts messages flow both ways
//! with delivery receipts, and that a killed-and-restarted client resumes the session from its
//! encrypted store (no re-handshake). It also runs the opacity-audit subcommand and checks it
//! reports zero leaks.
//!
//! Delivery is driven by live output readers + bounded resends rather than fixed sleeps, so the
//! test is robust to subprocess/connection startup timing under CI load. Resends are safe: message
//! ids are unique and assertions match on substrings, and the client treats a momentarily-offline
//! peer (`not_connected`) as "not delivered" rather than a fatal error.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    fn spawn_chat(&self, server: &str, peer_id: &str) -> ChatProc {
        let mut child = Command::new(BIN)
            .args(["chat", peer_id, "--server", server, "--json"])
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn chat");
        let stdin = child.stdin.take().unwrap();
        let out = drain(child.stdout.take().unwrap());
        let err = drain(child.stderr.take().unwrap());
        ChatProc {
            child,
            stdin: Some(stdin),
            out,
            err,
        }
    }
}

/// A running `chat` subprocess with its stdout/stderr accumulated by reader threads.
struct ChatProc {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ChatProc {
    fn send(&mut self, line: &str) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "{line}");
            let _ = stdin.flush();
        }
    }
    fn out(&self) -> String {
        self.out.lock().unwrap().clone()
    }
    fn err(&self) -> String {
        self.err.lock().unwrap().clone()
    }
    fn finish(mut self) -> (String, String) {
        self.stdin.take(); // drop stdin → EOF → clean exit
        let _ = self.child.wait();
        (self.out(), self.err())
    }
}

/// Spawn a thread draining a child stream into a shared string buffer.
fn drain<R: std::io::Read + Send + 'static>(stream: R) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let sink = buf.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => sink.lock().unwrap().push_str(&line),
            }
        }
    });
    buf
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Poll `cond` until true or `timeout` elapses; returns whether it succeeded.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    cond()
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

    let mut a = alice.spawn_chat(&server, &bob_id);
    let mut b = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(800)); // let both connect + publish

    // Drive delivery with bounded resends (robust to startup ordering). The initiator's messages
    // send immediately; the responder buffers until the opening message establishes its session.
    let ok = wait_until(Duration::from_secs(20), || {
        a.send("hello from alice");
        b.send("hi alice, bob here");
        std::thread::sleep(Duration::from_millis(600));
        b.out().contains("hello from alice")
            && a.out().contains("hi alice, bob here")
            && a.out().contains("\"event\":\"receipt\"")
    });

    let (a_out, a_err) = a.finish();
    let (b_out, b_err) = b.finish();
    assert!(
        ok,
        "did not converge.\nA stdout: {a_out}\nA stderr: {a_err}\nB stdout: {b_out}\nB stderr: {b_err}"
    );
    // Explicit acceptance assertions (both ways + receipts).
    assert!(
        b_out.contains("hello from alice"),
        "bob missed alice's message"
    );
    assert!(
        a_out.contains("hi alice, bob here"),
        "alice missed bob's message"
    );
    assert!(
        a_out.contains("\"event\":\"receipt\""),
        "alice saw no receipt"
    );

    // Restart both clients: the session store persists, so re-opening chat resumes the ratchet with
    // no re-handshake, and a post-restart message decrypts on the continued session.
    let b2 = bob.spawn_chat(&server, &alice_id);
    let mut a2 = alice.spawn_chat(&server, &bob_id);
    std::thread::sleep(Duration::from_millis(800));

    let ok2 = wait_until(Duration::from_secs(20), || {
        a2.send("back after restart");
        std::thread::sleep(Duration::from_millis(600));
        b2.out().contains("back after restart")
    });

    let (a2_out, a2_err) = a2.finish();
    let (b2_out, b2_err) = b2.finish();
    assert!(
        ok2,
        "post-restart message not delivered.\nA2 stdout: {a2_out}\nA2 stderr: {a2_err}\nB2 stdout: {b2_out}\nB2 stderr: {b2_err}"
    );
    // Resuming must NOT re-run a handshake — the existing session was loaded from the sealed store.
    assert!(
        !a2_err.contains("establishing session"),
        "restart re-handshook instead of resuming: {a2_err}"
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
