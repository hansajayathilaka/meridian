//! Task 10.15's in-process validation of its own real-netns harness's orchestration/assertion logic
//! (`tools/netns-kill-resume.sh` + `apps/cli/examples/kill_resume_netns_drive.rs`), run with **no
//! real network at all** — per this task's own requirement to "validate your harness's own
//! orchestration/assertion logic works correctly by whatever means are available... separately from
//! the real-netns end-to-end harness".
//!
//! This is deliberately **not** a re-run of `resume_protocol.rs` (task 10.9's own thorough in-process
//! ice_restart+resume+2%-bound coverage, using [`meridian_streams::FileReceiver`]'s per-chunk-proof
//! bookkeeping). This test instead exercises the *specific* bookkeeping shape the real-netns driver
//! actually uses — reused from `apps/cli/src/send.rs`'s own real-production convention (distinct
//! chunk indices tracked from raw `pending_chunks`, whole-file BLAKE3 verification at the end, no
//! per-chunk merkle proof) — since that is the path this task's own driver binary drives over the
//! real rig, not `FileReceiver`'s. It also adds the two checks the demo script's own acceptance
//! wording calls for that 10.9's test doesn't: a literal `sha256` comparison (`sha256sum on both
//! ends → identical`) alongside the BLAKE3 root check, and the re-send ratio computed the exact way
//! the real harness's shell script parses it from the driver's own JSON summary line
//! (`resent_already_delivered_bytes / sent_before_cut_bytes`).
//!
//! Sequence (mirrors `kill_resume_netns_drive.rs`'s own phases, minus the marker-file/veth-cut
//! synchronization, which needs a real rig):
//! 1. Real two-party `P2pSession<LoopbackTransport>`, real ratchet, real `mrd.file/1` open.
//! 2. Alice sends a prefix of chunks; Bob's `FileStream` buffers them (`pending_chunks`).
//! 3. Both sides call the real `P2pSession::ice_restart` (task 4's substrate).
//! 4. Bob computes his own resume bitmap from `distinct_chunk_indices(pending_chunks)` (not
//!    `FileReceiver`) and sends it as a raw `FRAME_TAG_RESUME` frame directly via
//!    `send_stream_frame` — the exact wire bytes `send_resume_bitmap` would produce, built by hand
//!    the way the real driver does it.
//! 5. Alice's `watch_resume` receiver picks it up; she resends only the missing chunks.
//! 6. Bob reassembles via whole-file AEAD-open + BLAKE3 check (mirrors `send.rs::finalize_transfer`),
//!    and the result must match the source: same BLAKE3 root need not be recomputed twice (BLAKE3
//!    verification is *how* `finalize` accepts the buffer at all) but is asserted again explicitly,
//!    plus a literal `sha256` digest comparison on both ends' bytes.

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionEvent};
use meridian_core::streams::{register_stream_type, StreamRegistry};
use meridian_core::transport::{LoopbackFabric, LoopbackTransport, Transport};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use meridian_streams::merkle::CHUNK_SIZE;
use meridian_streams::resume::{tag_frame, ResumeRequest, FRAME_TAG_RESUME};
use meridian_streams::sender::{send_chunk_frame, send_missing_chunks, SenderConfig};
use meridian_streams::{open_chunk, ChunkFrame, FileManifest, FileMeta, FileStream, MerkleTree};

const TEST_NOW_UNIX: u64 = 1_700_000_000;

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
}

fn establish_ratchet(alice: &mut Peer, bob: &mut Peer) {
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let bundle = generate_bundle(&bob.store, bob.account.handle(), bob_ik, 5).expect("bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = bundle
        .bundle
        .otks
        .iter()
        .zip(bundle.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob.chat
        .vault
        .set_bundle(bundle.bundle.spk, *bundle.spk_secret, otks, TEST_NOW_UNIX);
    alice
        .chat
        .start_initiator_session(
            &alice.store,
            alice.account.handle(),
            &alice_ik,
            &bob_ik,
            &bundle.bundle.spk,
            bundle.bundle.otks.first().copied(),
        )
        .expect("start session");
}

async fn connect<T: Transport>(
    ta: Arc<T>,
    tb: Arc<T>,
    alice: &mut Peer,
    bob: &mut Peer,
    reg_a: Arc<StreamRegistry>,
    reg_b: Arc<StreamRegistry>,
) -> (P2pSession<T>, P2pSession<T>) {
    let (mut relay_a, mut relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let (astore, ahandle) = (&alice.store, alice.account.handle().clone());
    let (bstore, bhandle) = (&bob.store, bob.account.handle().clone());
    let achat = &mut alice.chat;
    let bchat = &mut bob.chat;
    let (ra, rb) = tokio::join!(
        dial(
            ta,
            astore,
            &ahandle,
            alice_ik,
            bob_ik,
            achat,
            &mut relay_a,
            reg_a
        ),
        answer(
            tb,
            bstore,
            &bhandle,
            bob_ik,
            alice_ik,
            bchat,
            &mut relay_b,
            reg_b
        ),
    );
    (
        ra.expect("dial established"),
        rb.expect("answer established"),
    )
}

async fn clear_first_contact<T: Transport>(
    asess: &mut P2pSession<T>,
    alice: &mut Peer,
    bsess: &mut P2pSession<T>,
    bob: &mut Peer,
) {
    let ahandle = alice.account.handle().clone();
    asess
        .send_chat(&alice.store, &ahandle, &mut alice.chat, "hi")
        .await
        .expect("send opening chat message");
    match bsess
        .pump(&bob.store, bob.account.handle(), &mut bob.chat)
        .await
    {
        Err(meridian_core::session::SessionError::Chat(_)) => {}
        other => panic!("expected the opening chat message to be gated, got {other:?}"),
    }
    bob.chat
        .accept_request(&alice.ik())
        .expect("accept the pending request");
}

fn sample_file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Mirrors `apps/cli/src/send.rs::distinct_chunk_indices` / `kill_resume_netns_drive.rs`'s identical
/// helper exactly — the real driver's own bookkeeping shape, not `FileReceiver`'s.
fn distinct_chunk_indices(pending_chunks: &[Vec<u8>]) -> std::collections::BTreeSet<u64> {
    pending_chunks
        .iter()
        .filter_map(|raw| ChunkFrame::decode(raw).ok())
        .map(|frame| frame.i)
        .collect()
}

/// Mirrors `kill_resume_netns_drive.rs::finalize` / `send.rs::finalize_transfer` exactly: whole-file
/// AEAD-open + BLAKE3 check, no per-chunk merkle proof.
fn finalize(manifest: &FileManifest, k_f: &[u8; 32], pending_chunks: &[Vec<u8>]) -> Vec<u8> {
    let leaf_count = manifest.size.div_ceil(CHUNK_SIZE as u64).max(1) as usize;
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
        "reassembled BLAKE3 root must match the manifest"
    );
    buf
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[tokio::test]
async fn kill_resume_harness_orchestration_matches_the_real_driver_exactly() {
    let mut alice = Peer::new("kr-sim.a");
    let mut bob = Peer::new("kr-sim.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));

    let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let mut reg_a = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_a, alice_file.clone());
    let mut reg_b = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_b, bob_file.clone());

    let (mut asess, mut bsess) = connect(
        ta,
        tb,
        &mut alice,
        &mut bob,
        Arc::new(reg_a),
        Arc::new(reg_b),
    )
    .await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    // 24 chunks, split at 15 before the "cut" — identical shape to `tools/netns-kill-resume.sh`'s
    // own constants, so this test is a faithful stand-in for the real rig's own scenario.
    const TOTAL_CHUNKS: usize = 24;
    const SPLIT_CHUNKS: usize = 15;
    let data = sample_file(TOTAL_CHUNKS * CHUNK_SIZE - 12345);
    let root = MerkleTree::from_bytes(&data).root();

    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let ahandle = alice.account.handle().clone();
    let (params, k_f) = FileStream::build_open_params(
        &mut alice.chat,
        &alice.store,
        &ahandle,
        &alice_ik,
        &bob_ik,
        FileMeta {
            name: "kill-resume-sim.bin".to_string(),
            size: data.len() as u64,
            root,
        },
    )
    .expect("build_open_params");
    let manifest = FileManifest::decode(&params).expect("decode manifest");

    let sid = asess
        .open_stream(
            &alice.store,
            &ahandle,
            &mut alice.chat,
            "mrd.file/1",
            params,
        )
        .await
        .expect("open mrd.file/1");
    match bsess
        .pump(&bob.store, bob.account.handle(), &mut bob.chat)
        .await
    {
        Ok(Some(SessionEvent::StreamOpened(got, _))) => assert_eq!(got, sid),
        other => panic!("bob expected StreamOpened, got {other:?}"),
    }
    match asess.pump(&alice.store, &ahandle, &mut alice.chat).await {
        Ok(Some(SessionEvent::StreamOpened(got, _))) => assert_eq!(got, sid),
        other => panic!("alice expected StreamOpened, got {other:?}"),
    }

    let mut resume_rx = alice_file.watch_resume(sid);

    // --- Phase 1: pre-cut burst. ---
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    assert_eq!(chunks.len(), TOTAL_CHUNKS);
    let mut sent_before_cut_bytes: u64 = 0;
    for (i, chunk) in chunks.iter().enumerate().take(SPLIT_CHUNKS) {
        send_chunk_frame(&mut asess, &mut alice.chat, sid, &k_f, i as u64, chunk)
            .await
            .expect("phase 1 send must succeed");
        sent_before_cut_bytes += chunk.len() as u64;
    }
    for _ in 0..SPLIT_CHUNKS {
        match bsess
            .pump(&bob.store, bob.account.handle(), &mut bob.chat)
            .await
        {
            Ok(None) => {}
            other => panic!("expected a silently-dispatched chunk frame, got {other:?}"),
        }
    }
    let received_before_cut = {
        let transfer = bob_file.transfer(sid).expect("bob tracks the transfer");
        distinct_chunk_indices(&transfer.pending_chunks)
    };
    assert_eq!(received_before_cut.len(), SPLIT_CHUNKS);

    // --- Phase 2: the "cut" — real `ice_restart()` on both sides, exactly like the real driver
    // calls once the harness script's `cut_restored` marker appears. ---
    asess.ice_restart().await.expect("alice ice_restart");
    bsess.ice_restart().await.expect("bob ice_restart");

    // --- Phase 3: bob computes his resume bitmap the way the real driver does (from
    // `distinct_chunk_indices`, not `FileReceiver`) and sends it as a raw tagged frame — the exact
    // wire bytes `send_resume_bitmap` would build, reproduced by hand. ---
    let leaf_count = TOTAL_CHUNKS;
    let resume = ResumeRequest::from_received(&received_before_cut, leaf_count);
    let resume_body = resume.encode().expect("encode resume request");
    bsess
        .send_stream_frame(
            &mut bob.chat,
            sid,
            &tag_frame(FRAME_TAG_RESUME, resume_body),
        )
        .await
        .expect("bob sends the resume bitmap");

    match asess.pump(&alice.store, &ahandle, &mut alice.chat).await {
        Ok(None) => {}
        other => panic!("alice expected the resume frame to dispatch silently, got {other:?}"),
    }
    let resume = resume_rx
        .try_recv()
        .expect("alice's resume watcher must have received the bitmap");
    assert_eq!(
        resume.missing_indices(leaf_count),
        (SPLIT_CHUNKS as u64..leaf_count as u64).collect::<Vec<_>>(),
        "the bitmap must mark exactly the undelivered suffix missing"
    );

    // --- Phase 4: alice resends only the missing chunks. ---
    let cfg = SenderConfig::default();
    let resent = send_missing_chunks(&mut asess, &mut alice.chat, sid, &k_f, &data, &resume, &cfg)
        .await
        .expect("send_missing_chunks must succeed");
    assert_eq!(
        resent,
        (SPLIT_CHUNKS as u64..leaf_count as u64).collect::<Vec<_>>(),
        "resume must resend exactly the missing suffix"
    );
    for _ in 0..resent.len() {
        match bsess
            .pump(&bob.store, bob.account.handle(), &mut bob.chat)
            .await
        {
            Ok(None) => {}
            other => panic!("expected a silently-dispatched resent chunk, got {other:?}"),
        }
    }

    // --- Deliverable 2: the ≤2% re-send bound, computed the exact way the real harness's shell
    // script parses it from the driver's own JSON summary line. ---
    let resent_already_delivered_bytes: u64 = resent
        .iter()
        .filter(|&&i| (i as usize) < SPLIT_CHUNKS)
        .map(|&i| chunks[i as usize].len() as u64)
        .sum();
    let ratio = resent_already_delivered_bytes as f64 / sent_before_cut_bytes as f64;
    assert_eq!(
        resent_already_delivered_bytes, 0,
        "resume must never resend a single byte of an already-delivered chunk"
    );
    assert!(
        ratio <= 0.02,
        "resend ratio {:.4}% exceeds the 2% acceptance bound",
        ratio * 100.0
    );

    // --- Final assertions: reassemble (whole-file AEAD-open + BLAKE3, the real driver's own
    // `finalize`), then the demo script's own literal dual check: BLAKE3 root AND `sha256sum`. ---
    let pending = bob_file
        .transfer(sid)
        .expect("bob tracks the transfer")
        .pending_chunks;
    let reassembled = finalize(&manifest, &k_f, &pending);
    assert_eq!(
        MerkleTree::from_bytes(&reassembled).root(),
        root,
        "BLAKE3 root must match on both ends"
    );
    assert_eq!(
        sha256_hex(&reassembled),
        sha256_hex(&data),
        "sha256 must match on both ends — the demo script's own literal final check"
    );
    assert_eq!(reassembled, data, "byte-for-byte identical to the source");
}
