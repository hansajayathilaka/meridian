//! Real-process acceptance test for `meridian session connect` (1.24, F11 wire prerequisite):
//! `cargo nextest run -p meridian-cli --features webrtc`.
//!
//! Unlike `session_demo_webrtc.rs` (one process simulating both sides of a P2P session
//! in-process), this spawns **two separate `meridian` child processes** against a real
//! `meridian-rendezvous` instance started by the test on localhost, each running `session connect
//! <other-peer-id> --server <url> --transport webrtc` concurrently. This is what proves the
//! `SignalRelay`-over-`SignalingClient` adapter actually lets two OS processes rendezvous and dial
//! a real P2P session — `session demo`'s in-process `LoopbackTransport`/`MemRelay` simulation can
//! never exercise that path.

#![cfg(feature = "webrtc")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
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
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Spawn `session connect <peer_id> --server <server> --transport webrtc --json` as a real
    /// child process (not run to completion here — the caller waits for both sides concurrently).
    fn spawn_connect(&self, server: &str, peer_id: &str) -> ConnectProc {
        let mut child = Command::new(BIN)
            .args([
                "session",
                "connect",
                peer_id,
                "--server",
                server,
                "--transport",
                "webrtc",
                "--json",
            ])
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn session connect");
        let out = drain(child.stdout.take().unwrap());
        let err = drain(child.stderr.take().unwrap());
        ConnectProc { child, out, err }
    }
}

/// A running `session connect` subprocess with its stdout/stderr accumulated by reader threads.
struct ConnectProc {
    child: Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl ConnectProc {
    /// Wait for the process to exit (bounded), returning `(success, stdout, stderr)`.
    fn wait(mut self, timeout: Duration) -> (bool, String, String) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return (
                    status.success(),
                    self.out.lock().unwrap().clone(),
                    self.err.lock().unwrap().clone(),
                );
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return (
                    false,
                    self.out.lock().unwrap().clone(),
                    format!(
                        "{}\n[test] timed out waiting for process to exit",
                        self.err.lock().unwrap()
                    ),
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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

#[test]
fn two_processes_establish_a_real_p2p_session_over_the_rendezvous() {
    let server = spawn_server();

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let alice_id = alice.id();
    let bob_id = bob.id();

    // Both sides must be live on the rendezvous at the same time (there is no mailbox for the
    // offer/answer exchange — see `signal_relay.rs`'s module docs), so spawn both concurrently and
    // wait for both, rather than running them one after another.
    let a = alice.spawn_connect(&server, &bob_id);
    let b = bob.spawn_connect(&server, &alice_id);

    let (a_ok, a_out, a_err) = a.wait(Duration::from_secs(30));
    let (b_ok, b_out, b_err) = b.wait(Duration::from_secs(30));

    assert!(
        a_ok,
        "alice's session connect failed.\nstdout: {a_out}\nstderr: {a_err}"
    );
    assert!(
        b_ok,
        "bob's session connect failed.\nstdout: {b_out}\nstderr: {b_err}"
    );

    let combined = format!("{a_out}\n{b_out}");

    // The real WebRtcTransport backend was used, not a simulation. Both sides run with
    // `--json`, so the headline event's `"transport":"..."` field is what actually gets
    // printed (the plain-text `transport=...` `Display` line only appears without `--json`).
    assert!(
        combined.contains("\"transport\":\"webrtc-datachannel\""),
        "expected a \"transport\":\"webrtc-datachannel\" field in combined output: {combined}"
    );
    // Both sides established the session ("p2p_connect" is the --json headline event).
    assert!(
        a_out.contains("\"event\":\"p2p_connect\"") && a_out.contains("\"established\":true"),
        "alice did not report an established session: {a_out}"
    );
    assert!(
        b_out.contains("\"event\":\"p2p_connect\"") && b_out.contains("\"established\":true"),
        "bob did not report an established session: {b_out}"
    );
    // One side dialed, the other answered (role decided by key order, no race).
    let roles = format!(
        "{}{}",
        a_out.contains("\"role\":\"initiator\""),
        b_out.contains("\"role\":\"initiator\"")
    );
    assert!(
        roles == "truefalse" || roles == "falsetrue",
        "expected exactly one initiator: alice_out={a_out} bob_out={b_out}"
    );
}
