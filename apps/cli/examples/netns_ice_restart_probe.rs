//! Task 10.15 companion probe: does the P2P **session itself** (chat-level, not file-transfer)
//! survive a real veth down/up cycle across a real netns network cut, once
//! `P2pSession::ice_restart()` is called on both sides?
//!
//! Built after `kill_resume_netns_drive`'s own file-transfer path hit an unrelated, pre-existing
//! defect independent of kill/resume (see this task's report): the real `WebRtcTransport` backend's
//! default SCTP `max_message_size` (65536 bytes, `webrtc-sctp`'s own `DEFAULT_MAX_MESSAGE_SIZE`) is
//! smaller than a single sealed `mrd.file/1` chunk frame at the crate's `CHUNK_SIZE` (also exactly
//! 65536 raw bytes, before AEAD/CBOR/ratchet-envelope overhead) — so *any* full-size file chunk
//! fails outbound before this task's own kill/resume logic is even reached. That is a real,
//! separately-tracked defect (`apps/transport/src/webrtc_backend.rs` / `apps/streams/src/merkle.rs`),
//! out of this task's own scope to fix. This much smaller, chat-only probe sidesteps it entirely (a
//! chat message is a few dozen bytes, nowhere near the SCTP limit) to answer the specific, narrower
//! question this task cares about most: does the *substrate itself* — not file-transfer chunking —
//! actually recover from a genuine network interruption once `ice_restart()` is called, or whether
//! the documented no-op (`webrtc_backend.rs`'s own module doc) manifests here too.
//!
//! **CONFIRMED, live, on this sandbox's own real netns/veth rig (root, no NAT, direct host-candidate
//! path both before and after)**: it does. Cutting the veth for 15s (past `webrtc_backend.rs`'s own
//! `ICE_FAILED_TIMEOUT` of 9s), restoring it, then calling `ice_restart()` on both sides: the local
//! `send_chat()` call on the still-"connected"-looking session returns `Ok(())` with **no error and
//! no hang** (the local data-channel object never tore down), but the peer's `pump()` never observes
//! that message even after a further 25s wait. This matches the module doc's own prediction almost
//! exactly, with one precision correction worth recording: it is not the *local send call* that
//! "hangs forever" — it returns immediately, successfully, as far as this side can tell — it is
//! *delivery* that silently never happens. A caller relying solely on `ice_restart()`'s `Ok(())` and
//! a subsequent `send_*` call's own `Ok(())` would have **no local signal at all** that the message
//! was lost. This is a real, reproduced-firsthand defect in `meridian-transport`'s current
//! `WebRtcTransport::ice_restart`, independent of anything this task (10.15) built, and out of this
//! task's scope to fix (per that module's own doc: needs a ctrl-channel renegotiation message, ADR/
//! architect-review territory). Flagged here for a follow-up task rather than silently worked around.
//!
//! Usage: `netns_ice_restart_probe a <rundir>` / `netns_ice_restart_probe b <rundir>` — driven by
//! `tools/netns-kill-resume.sh probe` the same way the file-transfer driver is.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{generate_account, MemorySecretStore};
use meridian_core::session::{answer, dial, SessionError, SessionEvent, SignalRelay};
use meridian_core::streams::StreamRegistry;
use meridian_core::transport::WebRtcTransport;
use meridian_signaling::generate_bundle;

const MARKER_TIMEOUT: Duration = Duration::from_secs(90);
const POST_RESTORE_TIMEOUT: Duration = Duration::from_secs(25);

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: netns_ice_restart_probe <a|b> <rundir>");
        std::process::exit(2);
    }
    let role = args[1].as_str();
    let rundir = PathBuf::from(&args[2]);
    let result = match role {
        "a" => run_a(&rundir).await,
        "b" => run_b(&rundir).await,
        other => {
            eprintln!("unknown role '{other}' — expected 'a' or 'b'");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("[probe:{role}] FATAL: {e}");
        std::process::exit(1);
    }
    println!("[probe:{role}] PASS");
}

async fn wait_for_file(path: &Path, what: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    while !path.exists() {
        if start.elapsed() > MARKER_TIMEOUT {
            return Err(format!(
                "timed out after {MARKER_TIMEOUT:?} waiting for {what} ({})",
                path.display()
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn touch(path: &Path) {
    File::create(path).unwrap_or_else(|e| panic!("creating marker {}: {e}", path.display()));
}

fn read_exact_file(path: &Path, n: usize) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|e| panic!("opening {}: {e}", path.display()));
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    buf
}

/// Identical shape to `kill_resume_netns_drive.rs`'s own `FileRelay` — see that file's module doc.
struct FileRelay {
    outbox: PathBuf,
    inbox: PathBuf,
    peer_ik: [u8; 32],
    read_pos: u64,
}

impl FileRelay {
    fn new(outbox: PathBuf, inbox: PathBuf, peer_ik: [u8; 32]) -> Self {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&outbox)
            .expect("create outbox");
        Self {
            outbox,
            inbox,
            peer_ik,
            read_pos: 0,
        }
    }
}

#[async_trait::async_trait]
impl SignalRelay for FileRelay {
    async fn send(&mut self, _to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError> {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&self.outbox)
            .map_err(|_| SessionError::SignalingEnded)?;
        let len = (blob.len() as u32).to_le_bytes();
        f.write_all(&len)
            .map_err(|_| SessionError::SignalingEnded)?;
        f.write_all(&blob)
            .map_err(|_| SessionError::SignalingEnded)?;
        Ok(())
    }

    /// This probe's `FileRelay` has no mailbox concept (an append-only file pair, not a rendezvous)
    /// — like `MemRelay` (`meridian_core::session`), the only honest outcomes are "delivered" (the
    /// write succeeded) or a genuine I/O failure, never a fabricated `queued: true`.
    async fn send_tolerant(
        &mut self,
        to: &[u8; 32],
        blob: Vec<u8>,
    ) -> Result<meridian_core::signaling::RouteOutcome, SessionError> {
        self.send(to, blob).await?;
        Ok(meridian_core::signaling::RouteOutcome {
            delivered: true,
            queued: false,
        })
    }

    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError> {
        loop {
            let mut f = OpenOptions::new()
                .read(true)
                .open(&self.inbox)
                .unwrap_or_else(|_| File::open("/dev/null").expect("/dev/null always openable"));
            let mut all = Vec::new();
            let _ = f.read_to_end(&mut all);
            let pos = self.read_pos as usize;
            if all.len() >= pos + 4 {
                let len = u32::from_le_bytes(all[pos..pos + 4].try_into().unwrap()) as usize;
                if all.len() >= pos + 4 + len {
                    let blob = all[pos + 4..pos + 4 + len].to_vec();
                    self.read_pos = (pos + 4 + len) as u64;
                    return Ok((self.peer_ik, blob));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn run_a(rundir: &Path) -> Result<(), String> {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "kr-probe.a").map_err(|e| e.to_string())?;
    let our_ik = *account.public_key().as_bytes();
    let handle = account.handle().clone();

    std::fs::write(rundir.join("a_ik.bin"), our_ik).map_err(|e| e.to_string())?;
    wait_for_file(&rundir.join("b_bundle.bin"), "b's prekey bundle").await?;
    let bundle_bytes = std::fs::read(rundir.join("b_bundle.bin")).map_err(|e| e.to_string())?;
    let bundle: meridian_core::proto::PrekeyBundle =
        meridian_proto::decode(&bundle_bytes).map_err(|e| e.to_string())?;
    let peer_ik = bundle.account_pub;

    let mut chat = ChatState::default();
    chat.start_initiator_session(
        &store,
        &handle,
        &our_ik,
        &peer_ik,
        &bundle.spk,
        bundle.otks.first().copied(),
    )
    .map_err(|e| e.to_string())?;

    let mut relay = FileRelay::new(
        rundir.join("a_to_b.bin"),
        rundir.join("b_to_a.bin"),
        peer_ik,
    );
    let transport = std::sync::Arc::new(WebRtcTransport::new());
    println!("[probe:a] dialing…");
    let mut sess = dial(
        transport,
        &store,
        &handle,
        our_ik,
        peer_ik,
        &mut chat,
        &mut relay,
        std::sync::Arc::new(StreamRegistry::with_builtins()),
    )
    .await
    .map_err(|e| format!("dial: {e}"))?;
    let info = sess.info().await;
    println!(
        "[probe:a] connected: path={:?} reason={}",
        info.path, info.reason
    );
    // The very first chat message on a session clears the responder's first-contact gate
    // (`ChatError::MessageRequest`) rather than surfacing as an ordinary `SessionEvent::Chat` — its
    // own content is consumed by `accept_request`, not delivered a second time. Send a throwaway
    // HELLO first (mirrors `apps/cli/src/send.rs`'s own identical `HELLO` convention) so the actual
    // probe payload below is a genuine, independently-observable second message.
    sess.send_chat(&store, &handle, &mut chat, "netns-ice-restart-probe hello")
        .await
        .map_err(|e| e.to_string())?;
    println!("[probe:a] sending ping-before-cut");
    sess.send_chat(&store, &handle, &mut chat, "ping-before-cut")
        .await
        .map_err(|e| e.to_string())?;

    touch(&rundir.join("a_ready_for_cut"));
    wait_for_file(&rundir.join("cut_restored"), "the veth restore marker").await?;
    println!("[probe:a] link restored — calling ice_restart()…");
    // (task 10.22) Reusing the already-in-scope `relay` is the minimal, reasonable update for this
    // test-only probe's new signature (ADR 0025's "reconnect transiently" pattern; a genuinely
    // fresh reconnect here is 10.23's job).
    sess.ice_restart(&mut relay, &store, &handle, &mut chat)
        .await
        .map_err(|e| format!("ice_restart: {e}"))?;
    println!("[probe:a] ice_restart() returned Ok — sending ping-after-cut…");

    tokio::time::timeout(
        POST_RESTORE_TIMEOUT,
        sess.send_chat(&store, &handle, &mut chat, "ping-after-cut"),
    )
    .await
    .map_err(|_| {
        format!(
            "timed out after {POST_RESTORE_TIMEOUT:?} sending a post-restore chat message — the \
             data channel did not survive the real network cut"
        )
    })?
    .map_err(|e| e.to_string())?;
    println!("[probe:a] post-restore chat message sent successfully");
    let _ = sess.close().await;
    touch(&rundir.join("a_done"));
    Ok(())
}

async fn run_b(rundir: &Path) -> Result<(), String> {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "kr-probe.b").map_err(|e| e.to_string())?;
    let our_ik = *account.public_key().as_bytes();
    let handle = account.handle().clone();

    let generated = generate_bundle(&store, &handle, our_ik, 5).map_err(|e| e.to_string())?;
    let mut chat = ChatState::default();
    let otks: Vec<([u8; 32], [u8; 32])> = generated
        .bundle
        .otks
        .iter()
        .zip(generated.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    chat.vault.set_bundle(
        generated.bundle.spk,
        *generated.spk_secret,
        otks,
        1_700_000_000,
    );
    let bundle_bytes = meridian_proto::encode(&generated.bundle).map_err(|e| e.to_string())?;
    std::fs::write(rundir.join("b_bundle.bin"), bundle_bytes).map_err(|e| e.to_string())?;

    wait_for_file(&rundir.join("a_ik.bin"), "a's identity key").await?;
    let peer_ik: [u8; 32] = read_exact_file(&rundir.join("a_ik.bin"), 32)
        .try_into()
        .expect("exactly 32 bytes");

    let mut relay = FileRelay::new(
        rundir.join("b_to_a.bin"),
        rundir.join("a_to_b.bin"),
        peer_ik,
    );
    let transport = std::sync::Arc::new(WebRtcTransport::new());
    println!("[probe:b] awaiting dial…");
    let mut sess = answer(
        transport,
        &store,
        &handle,
        our_ik,
        peer_ik,
        &mut chat,
        &mut relay,
        std::sync::Arc::new(StreamRegistry::with_builtins()),
    )
    .await
    .map_err(|e| format!("answer: {e}"))?;
    let info = sess.info().await;
    println!(
        "[probe:b] connected: path={:?} reason={} — waiting for ping-before-cut",
        info.path, info.reason
    );

    loop {
        match sess.pump(&store, &handle, &mut chat).await {
            Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
                println!("[probe:b] received chat: {body:?}");
                if body == "ping-before-cut" {
                    break;
                }
            }
            Ok(_) => {}
            Err(SessionError::Chat(ChatError::MessageRequest)) => {
                chat.accept_request(&peer_ik)
                    .ok_or("accepting inbound session: no pending request")?;
            }
            Err(e) => return Err(format!("phase 1 pump: {e}")),
        }
    }

    touch(&rundir.join("b_ready_for_cut"));
    wait_for_file(&rundir.join("cut_restored"), "the veth restore marker").await?;
    println!("[probe:b] link restored — calling ice_restart()…");
    sess.ice_restart(&mut relay, &store, &handle, &mut chat)
        .await
        .map_err(|e| format!("ice_restart: {e}"))?;
    println!("[probe:b] ice_restart() returned Ok — waiting for ping-after-cut…");

    tokio::time::timeout(POST_RESTORE_TIMEOUT, async {
        loop {
            match sess.pump(&store, &handle, &mut chat).await {
                Ok(Some(SessionEvent::Chat(ChatContent::Text { body, .. }))) => {
                    println!("[probe:b] received chat: {body:?}");
                    if body == "ping-after-cut" {
                        return Ok::<(), String>(());
                    }
                }
                Ok(_) => {}
                Err(e) => return Err(format!("phase 2 pump: {e}")),
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "timed out after {POST_RESTORE_TIMEOUT:?} waiting for the post-restore chat message — \
             the data channel did not survive the real network cut"
        )
    })??;

    let _ = sess.close().await;
    touch(&rundir.join("b_done"));
    Ok(())
}
