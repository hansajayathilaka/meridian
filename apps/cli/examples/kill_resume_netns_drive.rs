//! Task 10.15 real-netns driver: a standalone, test-only binary that plays the "session-lifecycle
//! layer" `apps/streams/src/resume.rs`'s own module doc says must exist outside `meridian-streams`
//! to call `P2pSession::ice_restart()` + the resume primitives on a redial. This is deliberately
//! **not** `meridian send` (`apps/cli/src/send.rs`) — see this task's own report for why wiring
//! automatic drop-detection + reconnect + resume into the real production CLI binary was judged out
//! of this task's scope (no `SessionEvent`/`StreamType` hook exists to detect a drop without a
//! `meridian-core` change, which task 10.9's own module doc already flags as a tracked, separate
//! carry-forward). This driver instead calls the exact same real primitives
//! (`P2pSession::ice_restart`, `send_resume_bitmap`-equivalent, `send_missing_chunks`,
//! `FileStream::watch_resume`) a production integration eventually would, with the **timing** of
//! "when to call `ice_restart`" driven explicitly by the harness script
//! (`tools/netns-kill-resume.sh`) via marker files — since the harness itself is the one cutting the
//! veth, it already knows exactly when a redial should be attempted, so this driver does not need to
//! invent a heartbeat/timeout-based drop detector of its own (that heuristic, if ever wired into the
//! real CLI, is exactly the "larger change" this task chose not to make).
//!
//! Signaling substrate: a trivial file-based [`FileRelay`] implementing
//! `meridian_core::session::SignalRelay` over two append-only files in the shared rundir (network
//! namespaces share the host mount namespace, so both `sender`/`receiver` processes — each launched
//! inside its own netns via `ip netns exec` — can see the same rundir even though their *network*
//! stacks are isolated). This is a **test-only substitute for the rendezvous WS relay**: it carries
//! only the pre-P2P offer/answer/ICE-candidate envelope exchange, exactly the same job `MemRelay`
//! plays in every other in-process test in this codebase, just made to work across two OS processes.
//! It has nothing to do with the actual thing under test (the `mrd.file/1` data channel's survival
//! across a real veth cut), matching how the real rendezvous server is also outside the data path in
//! production (`docs/architecture/system-design.md`'s "servers only rendezvous").
//!
//! Usage: `kill_resume_netns_drive sender <rundir> <input-file> <split-chunks>` /
//! `kill_resume_netns_drive receiver <rundir> <output-file> <split-chunks>` — see
//! `tools/netns-kill-resume.sh` for how these are actually invoked (inside `ip netns exec`, with a
//! veth cut synchronized via marker files in `<rundir>` between the two `split-chunks`-chunk marks).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use meridian_core::chat::{ChatError, ChatState};
use meridian_core::identity::{generate_account, MemorySecretStore};
use meridian_core::session::{answer, dial, SessionError, SessionEvent, SignalRelay};
use meridian_core::streams::{register_stream_type, StreamId, StreamRegistry};
use meridian_core::transport::WebRtcTransport;
use meridian_signaling::generate_bundle;
use meridian_streams::merkle::CHUNK_SIZE;
use meridian_streams::resume::{tag_frame, ResumeRequest, FRAME_TAG_RESUME};
use meridian_streams::sender::{send_chunk_frame, send_missing_chunks, SenderConfig};
use meridian_streams::{open_chunk, ChunkFrame, FileManifest, FileMeta, FileStream, MerkleTree};

/// How long a marker-file poll waits before giving up entirely — generous enough to absorb the
/// harness's own veth-cut sleep (see `tools/netns-kill-resume.sh`'s `CUT_SECS`) plus real ICE/DTLS
/// setup time, but bounded so a genuinely stuck run fails within a CI-reasonable time rather than
/// hanging the job forever.
const MARKER_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound on the post-restore `pump`/`send_stream_frame` calls this driver makes. If the real
/// `WebRtcTransport::ice_restart` no-op gap (`apps/transport/src/webrtc_backend.rs`'s own module
/// doc) means the data channel never actually recovers after a genuine network cut, this driver
/// must fail loud and fast with a clear message here, never hang indefinitely.
const POST_RESTORE_TIMEOUT: Duration = Duration::from_secs(25);

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <sender|receiver> <rundir> <input-or-output-file> <split-chunks>",
            args.first()
                .map(String::as_str)
                .unwrap_or("kill_resume_netns_drive")
        );
        std::process::exit(2);
    }
    let role = args[1].as_str();
    let rundir = PathBuf::from(&args[2]);
    let file_arg = PathBuf::from(&args[3]);
    let split: usize = args[4].parse().expect("split-chunks must be a number");

    let result = match role {
        "sender" => run_sender(&rundir, &file_arg, split).await,
        "receiver" => run_receiver(&rundir, &file_arg, split).await,
        other => {
            eprintln!("unknown role '{other}' — expected 'sender' or 'receiver'");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("[drive:{role}] FATAL: {e}");
        std::process::exit(1);
    }
}

// --------------------------------------------------------------------------------------------
// File-based marker/handshake plumbing — see module doc.
// --------------------------------------------------------------------------------------------

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

/// A [`SignalRelay`] over two append-only files: `outbox` is written only by this side, `inbox` only
/// by the peer — so no cross-process write interleaving is possible on either file. Frames are
/// length-prefixed (`u32` LE) raw envelope blobs, read back by polling for a full frame's worth of
/// bytes past the last-consumed offset.
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

    /// This driver's `FileRelay` has no mailbox concept (an append-only file pair, not a
    /// rendezvous) — like `MemRelay` (`meridian_core::session`), the only honest outcomes are
    /// "delivered" (the write succeeded) or a genuine I/O failure, never a fabricated
    /// `queued: true`.
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
                .unwrap_or_else(|_| {
                    // Peer hasn't created its outbox (== our inbox) yet.
                    File::open("/dev/null").expect("/dev/null always openable")
                });
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

// --------------------------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------------------------

fn leaf_count_for_size(size: u64) -> usize {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_SIZE as u64) as usize
    }
}

/// Mirrors `apps/cli/src/send.rs::distinct_chunk_indices` exactly: the set of distinct chunk indices
/// actually arrived so far, from raw arrival-order `pending_chunks` — this driver's receiver side
/// deliberately reuses `send.rs`'s own real-production bookkeeping approach (not `FileReceiver`'s
/// per-chunk-proof API, whose wire delivery mechanism is a separate, upstream `TODO: confirm` this
/// task does not solve — see `apps/streams/src/receiver.rs`'s module doc) rather than inventing a
/// third convention.
fn distinct_chunk_indices(pending_chunks: &[Vec<u8>]) -> std::collections::BTreeSet<u64> {
    pending_chunks
        .iter()
        .filter_map(|raw| ChunkFrame::decode(raw).ok())
        .map(|frame| frame.i)
        .collect()
}

/// Whole-file reassembly + BLAKE3 verification, mirroring `send.rs::finalize_transfer`'s real
/// production approach (per-chunk AEAD open, whole-file merkle check) minus the on-disk sanity cap
/// (this driver's test files are always small).
fn finalize(manifest: &FileManifest, k_f: &[u8; 32], pending_chunks: &[Vec<u8>]) -> Vec<u8> {
    let leaf_count = leaf_count_for_size(manifest.size);
    let mut buf = vec![0u8; manifest.size as usize];
    for raw in pending_chunks {
        let frame = ChunkFrame::decode(raw).expect("valid chunk frame");
        if frame.i as usize >= leaf_count {
            continue;
        }
        let plaintext = open_chunk(k_f, frame.i, &frame.data).expect("chunk must authenticate");
        let start = frame.i as usize * CHUNK_SIZE;
        let end = start + plaintext.len();
        buf[start..end].copy_from_slice(&plaintext);
    }
    let root = MerkleTree::from_bytes(&buf).root();
    assert_eq!(
        root, manifest.root,
        "reassembled file's BLAKE3 root does not match the manifest — corrupted transfer"
    );
    buf
}

// --------------------------------------------------------------------------------------------
// Sender (alice / initiator)
// --------------------------------------------------------------------------------------------

async fn run_sender(rundir: &Path, input: &Path, split: usize) -> Result<(), String> {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "kill-resume.alice").map_err(|e| e.to_string())?;
    let our_ik = *account.public_key().as_bytes();
    let handle = account.handle().clone();

    std::fs::write(rundir.join("alice_ik.bin"), our_ik).map_err(|e| e.to_string())?;
    println!("[drive:sender] identity ready, waiting for bob's bundle…");
    wait_for_file(&rundir.join("bob_bundle.bin"), "bob's prekey bundle").await?;
    let bundle_bytes = std::fs::read(rundir.join("bob_bundle.bin")).map_err(|e| e.to_string())?;
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
    let file_stream = std::sync::Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let mut registry = StreamRegistry::with_builtins();
    register_stream_type(&mut registry, file_stream.clone());

    let transport = std::sync::Arc::new(WebRtcTransport::new());
    println!("[drive:sender] dialing over the real WebRTC transport…");
    let mut sess = dial(
        transport,
        &store,
        &handle,
        our_ik,
        peer_ik,
        &mut chat,
        &mut relay,
        std::sync::Arc::new(registry),
    )
    .await
    .map_err(|e| format!("dial: {e}"))?;
    println!("[drive:sender] connected.");

    sess.send_chat(&store, &handle, &mut chat, "kill-resume-drive hello")
        .await
        .map_err(|e| e.to_string())?;

    let data = std::fs::read(input).map_err(|e| e.to_string())?;
    let tree = MerkleTree::from_bytes(&data);
    let root = tree.root();
    let (params, k_f) = FileStream::build_open_params(
        &mut chat,
        &store,
        &handle,
        &our_ik,
        &peer_ik,
        FileMeta {
            name: "kill-resume.bin".to_string(),
            size: data.len() as u64,
            root,
        },
    )
    .map_err(|e| e.to_string())?;

    let sid = sess
        .open_stream(
            &store,
            &handle,
            &mut chat,
            meridian_streams::file::NAME,
            params,
        )
        .await
        .map_err(|e| format!("open_stream: {e}"))?;
    loop {
        match sess.pump(&store, &handle, &mut chat).await {
            Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
            Ok(_) => {}
            Err(e) => return Err(format!("waiting for accept: {e}")),
        }
    }
    println!("[drive:sender] transfer accepted, sid={sid}");

    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    let total_chunks = chunks.len();
    let split = split.min(total_chunks);
    let mut sent_bytes: u64 = 0;
    for (i, chunk) in chunks.iter().enumerate().take(split) {
        send_chunk_frame(&mut sess, &mut chat, sid, &k_f, i as u64, chunk)
            .await
            .map_err(|e| e.to_string())?;
        sent_bytes += chunk.len() as u64;
    }
    println!(
        "[drive:sender] sent {split}/{total_chunks} chunks ({sent_bytes} bytes) — waiting for the harness to cut the network"
    );
    touch(&rundir.join("alice_ready_for_cut"));

    wait_for_file(&rundir.join("cut_restored"), "the veth restore marker").await?;
    println!("[drive:sender] link restored per the harness — calling ice_restart()…");
    // (task 10.22) `ice_restart` now needs a real, symmetric signaling round trip — reusing the
    // same `relay` this side dialed with is the minimal, reasonable choice here (ADR 0025's
    // "reconnect transiently" pattern doesn't require a *fresh* relay, only that the connection not
    // be held open for the session's entire remaining lifetime "just in case"; this driver's
    // file-based `FileRelay` costs nothing to keep around between the dial and this one restart
    // attempt). Wiring a genuinely fresh reconnect here is 10.23's job, not this task's.
    sess.ice_restart(&mut relay, &store, &handle, &mut chat)
        .await
        .map_err(|e| format!("ice_restart: {e}"))?;
    println!("[drive:sender] ice_restart() returned Ok — waiting for bob's resume bitmap…");

    let mut resume_rx = file_stream.watch_resume(sid);
    let resume = tokio::time::timeout(POST_RESTORE_TIMEOUT, async {
        loop {
            match sess.pump(&store, &handle, &mut chat).await {
                Ok(_) => {
                    if let Ok(r) = resume_rx.try_recv() {
                        return Ok(r);
                    }
                }
                Err(e) => return Err(format!("post-restore pump: {e}")),
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "timed out after {POST_RESTORE_TIMEOUT:?} waiting for bob's resume bitmap post-restore \
             — the data channel likely did not survive the real network cut (see \
             apps/transport/src/webrtc_backend.rs's `ice_restart` module doc: it resets only local \
             candidate-gathering bookkeeping and does not renegotiate with the peer)"
        )
    })??;

    println!(
        "[drive:sender] resume bitmap received: {} missing chunk(s)",
        resume.missing_indices(total_chunks).len()
    );

    let cfg = SenderConfig::default();
    let resent = tokio::time::timeout(
        POST_RESTORE_TIMEOUT,
        send_missing_chunks(&mut sess, &mut chat, sid, &k_f, &data, &resume, &cfg),
    )
    .await
    .map_err(|_| format!("timed out after {POST_RESTORE_TIMEOUT:?} resending missing chunks"))?
    .map_err(|e| e.to_string())?;

    // Deliverable 2: the ≤2% re-send bound, measured against the bytes already delivered before the
    // cut — identical framing to `apps/streams/tests/resume_protocol.rs`'s own in-process assertion,
    // now measured across a real netns network cut instead of a simulated one. `send_missing_chunks`
    // only ever resends chunks the bitmap marks missing (never an already-delivered index — the
    // in-process test proves this unconditionally), so `resent_already_delivered_bytes` is always 0
    // here too; this line makes that explicit and machine-checkable rather than merely implied.
    let resent_already_delivered_bytes: u64 = resent
        .iter()
        .filter(|&&i| (i as usize) < split)
        .map(|&i| chunks[i as usize].len() as u64)
        .sum();
    let ratio = resent_already_delivered_bytes as f64 / sent_bytes.max(1) as f64;

    println!(
        "{{\"event\":\"sender_done\",\"total_chunks\":{total_chunks},\"sent_before_cut\":{split},\
         \"sent_before_cut_bytes\":{sent_bytes},\"resent\":{},\"resent_already_delivered_bytes\":{resent_already_delivered_bytes},\
         \"resend_ratio\":{ratio}}}",
        resent.len()
    );

    let _ = sess.close().await;
    touch(&rundir.join("sender_done"));
    Ok(())
}

// --------------------------------------------------------------------------------------------
// Receiver (bob / responder)
// --------------------------------------------------------------------------------------------

async fn run_receiver(rundir: &Path, output: &Path, split: usize) -> Result<(), String> {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "kill-resume.bob").map_err(|e| e.to_string())?;
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
    std::fs::write(rundir.join("bob_bundle.bin"), bundle_bytes).map_err(|e| e.to_string())?;

    println!("[drive:receiver] bundle published, waiting for alice's identity…");
    wait_for_file(&rundir.join("alice_ik.bin"), "alice's identity key").await?;
    let peer_ik: [u8; 32] = read_exact_file(&rundir.join("alice_ik.bin"), 32)
        .try_into()
        .expect("exactly 32 bytes");

    let mut relay = FileRelay::new(
        rundir.join("b_to_a.bin"),
        rundir.join("a_to_b.bin"),
        peer_ik,
    );
    let file_stream = std::sync::Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let mut registry = StreamRegistry::with_builtins();
    register_stream_type(&mut registry, file_stream.clone());

    let transport = std::sync::Arc::new(WebRtcTransport::new());
    println!("[drive:receiver] awaiting the real WebRTC dial…");
    let mut sess = answer(
        transport,
        &store,
        &handle,
        our_ik,
        peer_ik,
        &mut chat,
        &mut relay,
        std::sync::Arc::new(registry),
    )
    .await
    .map_err(|e| format!("answer: {e}"))?;
    println!("[drive:receiver] connected.");

    let mut sid: Option<StreamId> = None;
    let mut manifest: Option<FileManifest> = None;
    let mut k_f: Option<[u8; 32]> = None;

    // Phase 1: accept the chat/file-open handshake and drain exactly `split` chunks.
    loop {
        match sess.pump(&store, &handle, &mut chat).await {
            Ok(Some(SessionEvent::StreamOpened(got, ty))) if ty == meridian_streams::file::NAME => {
                let transfer = file_stream.transfer(got).expect("tracked transfer");
                let m = transfer.manifest.expect("manifest present on accept");
                let key = chat
                    .open_bytes(&store, &handle, &our_ik, &peer_ik, &m.key, false)
                    .map_err(|e| format!("unsealing k_f: {e}"))?;
                k_f = Some(<[u8; 32]>::try_from(key.as_slice()).expect("32-byte k_f"));
                manifest = Some(m);
                sid = Some(got);
                println!("[drive:receiver] transfer accepted, sid={got}");
            }
            Ok(_) => {
                if let Some(sid) = sid {
                    let transfer = file_stream.transfer(sid).expect("tracked transfer");
                    if distinct_chunk_indices(&transfer.pending_chunks).len() >= split {
                        break;
                    }
                }
            }
            Err(SessionError::Chat(ChatError::MessageRequest)) => {
                chat.accept_request(&peer_ik)
                    .ok_or("accepting inbound session: no pending request")?;
            }
            Err(e) => return Err(format!("phase 1 pump: {e}")),
        }
    }
    let sid = sid.expect("sid set once accepted");
    let manifest = manifest.expect("manifest set once accepted");
    let k_f = k_f.expect("k_f set once accepted");
    println!("[drive:receiver] received the pre-cut burst ({split} chunks) — waiting for the harness to cut the network");
    touch(&rundir.join("bob_ready_for_cut"));

    // Phase 2: wait for the harness's veth restore (no pump() during the cut — nothing can arrive,
    // and we don't want to block this side's own ability to notice the marker).
    wait_for_file(&rundir.join("cut_restored"), "the veth restore marker").await?;
    println!("[drive:receiver] link restored per the harness — calling ice_restart()…");
    // (task 10.22) See the sender's own matching comment: reusing the already-in-scope `relay` is
    // the minimal, reasonable update for this test-only driver's new signature.
    sess.ice_restart(&mut relay, &store, &handle, &mut chat)
        .await
        .map_err(|e| format!("ice_restart: {e}"))?;

    // Phase 3: send the resume bitmap directly (task 10.9's real wire shape — the receiver-side half
    // of `send_resume_bitmap`, built from this driver's own real-production-style bookkeeping rather
    // than `FileReceiver`, per this module's doc).
    let leaf_count = leaf_count_for_size(manifest.size);
    let received = {
        let transfer = file_stream.transfer(sid).expect("tracked transfer");
        distinct_chunk_indices(&transfer.pending_chunks)
    };
    let resume = ResumeRequest::from_received(&received, leaf_count);
    let resume_body = resume.encode().map_err(|e| e.to_string())?;
    tokio::time::timeout(
        POST_RESTORE_TIMEOUT,
        sess.send_stream_frame(&mut chat, sid, &tag_frame(FRAME_TAG_RESUME, resume_body)),
    )
    .await
    .map_err(|_| {
        format!("timed out after {POST_RESTORE_TIMEOUT:?} sending the resume bitmap post-restore")
    })?
    .map_err(|e| e.to_string())?;
    println!(
        "[drive:receiver] resume bitmap sent: {} missing of {leaf_count} chunks",
        resume.missing_indices(leaf_count).len()
    );

    // Phase 4: receive the resent chunks until complete.
    tokio::time::timeout(POST_RESTORE_TIMEOUT, async {
        loop {
            let transfer = file_stream.transfer(sid).expect("tracked transfer");
            if distinct_chunk_indices(&transfer.pending_chunks).len() >= leaf_count {
                return Ok::<(), String>(());
            }
            match sess.pump(&store, &handle, &mut chat).await {
                Ok(_) => {}
                Err(e) => return Err(format!("phase 4 pump: {e}")),
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "timed out after {POST_RESTORE_TIMEOUT:?} receiving the resent chunks post-restore — \
             the data channel likely did not survive the real network cut"
        )
    })??;

    let pending = file_stream
        .transfer(sid)
        .expect("tracked transfer")
        .pending_chunks;
    let buf = finalize(&manifest, &k_f, &pending);
    std::fs::write(output, &buf).map_err(|e| e.to_string())?;

    let root = MerkleTree::from_bytes(&buf).root();
    println!(
        "{{\"event\":\"receiver_done\",\"root\":\"b3:{}\",\"bytes\":{}}}",
        hex::encode(root),
        buf.len()
    );

    let _ = sess.close().await;
    touch(&rundir.join("receiver_done"));
    Ok(())
}
