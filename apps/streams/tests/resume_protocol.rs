//! End-to-end resume protocol test (task 10.9): a mid-transfer disconnect + redial + resume,
//! driven over a real two-party P2P session (`LoopbackTransport`), mirroring
//! `sender_engine.rs` (task 10.7)'s own harness.
//!
//! Sequence:
//! 1. Alice opens a `mrd.file/1` transfer to Bob and sends only a *prefix* of the file's chunks
//!    (simulating "some chunks landed before the connection dropped").
//! 2. Bob reassembles what arrived so far into a real [`FileReceiver`] (task 10.8), the authoritative
//!    bookkeeping [`ResumeRequest::from_received`] is defined against.
//! 3. Both sides call the real [`P2pSession::ice_restart`] (task 4's session substrate) — the actual
//!    redial signal this task found in `apps/core` (`apps/core/tests/p2p_session.rs`'s own
//!    `ice_restart_preserves_session_and_ratchet` exercises the identical call shape). ICE restart
//!    renegotiates candidate pairs only; the `mrd.file/1` data channel and all crypto/ratchet state
//!    survive untouched, matching invariant 5 and this task's own "stream is live again" framing.
//! 4. Bob sends the current resume bitmap ([`send_resume_bitmap`]) over the same still-open channel.
//! 5. Alice, watching for it via [`FileStream::watch_resume`], resends only the missing chunks
//!    ([`send_missing_chunks`]).
//! 6. Bob finishes reassembling and the file matches byte-for-byte.
//!
//! The acceptance criterion this test actually measures (not merely "resume completes"): of the
//! bytes Alice resends in step 5, how many belong to a chunk index Bob had *already* received in
//! step 1 — i.e. genuinely wasted, re-sent-already-delivered bytes — as a fraction of the bytes
//! already delivered before the drop. The task's bound is "never more than 2%"; this harness proves
//! the real number is exactly 0% (resume addresses precisely the missing complement, never
//! re-touching an already-verified offset), a strictly stronger result than the bound requires.

use std::collections::HashSet;
use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionEvent};
use meridian_core::streams::{register_stream_type, StreamRegistry};
use meridian_core::transport::{LoopbackFabric, LoopbackTransport, Transport};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use meridian_streams::merkle::{MerkleTree, CHUNK_SIZE};
use meridian_streams::sender::{send_chunk_frame, send_missing_chunks, send_resume_bitmap};
use meridian_streams::{ChunkFrame, FileManifest, FileMeta, FileReceiver, FileStream};

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

/// Mirrors `sender_engine.rs`'s own identical helper.
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

fn file_registries() -> (
    Arc<StreamRegistry>,
    Arc<StreamRegistry>,
    Arc<FileStream>,
    Arc<FileStream>,
) {
    let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
    let mut reg_a = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_a, alice_file.clone());
    let mut reg_b = StreamRegistry::with_builtins();
    register_stream_type(&mut reg_b, bob_file.clone());
    (Arc::new(reg_a), Arc::new(reg_b), alice_file, bob_file)
}

async fn open_file_transfer<T: Transport>(
    asess: &mut P2pSession<T>,
    alice: &mut Peer,
    bsess: &mut P2pSession<T>,
    bob: &mut Peer,
    name: &str,
    data: &[u8],
) -> (u64, [u8; 32], FileManifest) {
    let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
    let root = MerkleTree::from_bytes(data).root();
    let ahandle = alice.account.handle().clone();
    let (params, k_f) = FileStream::build_open_params(
        &mut alice.chat,
        &alice.store,
        &ahandle,
        &alice_ik,
        &bob_ik,
        FileMeta {
            name: name.to_string(),
            size: data.len() as u64,
            root,
        },
    )
    .expect("build_open_params over an established session");
    let manifest = FileManifest::decode(&params).expect("decode manifest we just built");

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
        Ok(Some(SessionEvent::StreamOpened(got, ty))) => {
            assert_eq!(got, sid);
            assert_eq!(ty, "mrd.file/1");
        }
        other => panic!("bob expected StreamOpened, got {other:?}"),
    }
    match asess.pump(&alice.store, &ahandle, &mut alice.chat).await {
        Ok(Some(SessionEvent::StreamOpened(got, _))) => assert_eq!(got, sid),
        other => panic!("alice expected StreamOpened (accept), got {other:?}"),
    }

    (sid, *k_f, manifest)
}

async fn drain_frames<T: Transport>(sess: &mut P2pSession<T>, peer: &mut Peer, n: usize) {
    for _ in 0..n {
        match sess
            .pump(&peer.store, peer.account.handle(), &mut peer.chat)
            .await
        {
            Ok(None) => {}
            other => panic!("expected a silently-dispatched stream frame, got {other:?}"),
        }
    }
}

fn sample_file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Feeds every buffered raw `pending_chunks` entry (bare `ChunkFrame` bytes, post-tag-stripping —
/// `FileStream::on_frame`'s own contract) into `receiver`, using `tree` to produce each chunk's own
/// merkle proof (the test harness's own stand-in for however a real proof-delivery mechanism
/// eventually reaches the receiver — `TODO: confirm`, `crate::receiver`'s own module doc).
fn feed_into_receiver(receiver: &mut FileReceiver, pending: &[Vec<u8>], tree: &MerkleTree) {
    for raw in pending {
        let frame = ChunkFrame::decode(raw).expect("valid chunk frame");
        let proof = tree.proof(frame.i as usize).expect("index in range");
        receiver
            .receive_frame(raw, &proof)
            .expect("chunk must pass AEAD + merkle verification");
    }
}

#[tokio::test]
async fn resume_after_ice_restart_completes_the_transfer_resending_zero_already_delivered_bytes() {
    let mut alice = Peer::new("resume.a");
    let mut bob = Peer::new("resume.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    // 12 full CHUNK_SIZE chunks + one short final chunk = 13 chunks total.
    let data = sample_file(12 * CHUNK_SIZE + 999);
    let tree = MerkleTree::from_bytes(&data);
    let leaf_count = tree.leaf_count();
    assert_eq!(leaf_count, 13);

    let (sid, k_f, manifest) = open_file_transfer(
        &mut asess,
        &mut alice,
        &mut bsess,
        &mut bob,
        "movie.bin",
        &data,
    )
    .await;

    // Alice registers a resume watcher for this transfer *before* sending anything — mirrors what a
    // real sender engine call site does right after `open_stream` succeeds (task 10.9's own doc on
    // `FileStream::watch_resume`).
    let mut resume_rx = alice_file.watch_resume(sid);

    // --- Phase 1: send a prefix of chunks (0..DELIVERED), simulating "some chunks landed before the
    // connection dropped". ---
    const DELIVERED: u64 = 8; // chunks 0..8 "arrive"; chunks 8..13 never get a first attempt.
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    assert_eq!(chunks.len() as u64, leaf_count as u64);

    let mut first_attempt_bytes_by_index: Vec<(u64, usize)> = Vec::new();
    for i in 0..DELIVERED {
        send_chunk_frame(
            &mut asess,
            &mut alice.chat,
            sid,
            &k_f,
            i,
            chunks[i as usize],
        )
        .await
        .expect("phase 1 send must succeed");
        first_attempt_bytes_by_index.push((i, chunks[i as usize].len()));
    }
    drain_frames(&mut bsess, &mut bob, DELIVERED as usize).await;

    let mut receiver = FileReceiver::new(manifest, k_f);
    {
        let transfer = bob_file.transfer(sid).expect("bob tracks the transfer");
        feed_into_receiver(&mut receiver, &transfer.pending_chunks, &tree);
    }
    assert_eq!(receiver.received_offsets().len(), DELIVERED as usize);
    assert!(!receiver.is_complete());

    let already_delivered_bytes: u64 = first_attempt_bytes_by_index
        .iter()
        .map(|(_, len)| *len as u64)
        .sum();
    let delivered_indices: HashSet<u64> = (0..DELIVERED).collect();

    // --- Phase 2: simulate the drop + redial via the real signal this task found in `apps/core`:
    // `P2pSession::ice_restart` (mirrors `apps/core/tests/p2p_session.rs`'s own
    // `ice_restart_preserves_session_and_ratchet`). Ratchet + stream-level state (the open
    // `mrd.file/1` data channel, `alice_file`'s resume watcher, `receiver`'s own bookkeeping) all
    // survive untouched — this is exactly invariant 5. (task 10.22) The signature now needs a real,
    // symmetric signaling round trip — a fresh restart-scoped relay pair, run concurrently (the
    // lexicographically-larger-key side waits briefly for the other's offer, so a sequential
    // await/await here would deadlock the first call). ---
    let (mut restart_relay_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (ares, bres) = tokio::join!(
        asess.ice_restart(
            &mut restart_relay_a,
            &alice.store,
            alice.account.handle(),
            &mut alice.chat
        ),
        bsess.ice_restart(
            &mut restart_relay_b,
            &bob.store,
            bob.account.handle(),
            &mut bob.chat
        ),
    );
    ares.expect("alice ice_restart");
    bres.expect("bob ice_restart");

    // "Once the stream is live again": bob sends the current resume bitmap over the same,
    // still-open `mrd.file/1` channel.
    send_resume_bitmap(&mut bsess, &mut bob.chat, sid, &receiver)
        .await
        .expect("bob sends the resume bitmap");

    // Alice's session must process that inbound frame (one `pump`) before her watcher sees it.
    match asess
        .pump(&alice.store, alice.account.handle(), &mut alice.chat)
        .await
    {
        Ok(None) => {}
        other => panic!("alice expected the resume frame to dispatch silently, got {other:?}"),
    }
    let resume = resume_rx
        .try_recv()
        .expect("alice's resume watcher must have received the bitmap");
    assert_eq!(
        resume.missing_indices(leaf_count),
        (DELIVERED..leaf_count as u64).collect::<Vec<_>>(),
        "the bitmap must mark exactly the undelivered suffix missing"
    );

    // --- Phase 3: resume — alice resends only the missing chunks. ---
    let cfg = meridian_streams::sender::SenderConfig::default();
    let resent_indices =
        send_missing_chunks(&mut asess, &mut alice.chat, sid, &k_f, &data, &resume, &cfg)
            .await
            .expect("send_missing_chunks must succeed");
    assert_eq!(
        resent_indices,
        (DELIVERED..leaf_count as u64).collect::<Vec<_>>(),
        "resume must resend exactly the missing suffix, nothing already delivered"
    );

    drain_frames(&mut bsess, &mut bob, resent_indices.len()).await;
    {
        let transfer = bob_file.transfer(sid).expect("bob tracks the transfer");
        // `pending_chunks` only ever grows (task 10.6's own contract) — feed just the newly-arrived
        // tail rather than re-feeding what phase 1 already verified.
        let new_frames = &transfer.pending_chunks[DELIVERED as usize..];
        feed_into_receiver(&mut receiver, new_frames, &tree);
    }

    assert!(
        receiver.is_complete(),
        "the transfer must be complete after resume"
    );
    assert_eq!(
        receiver.reassemble().unwrap(),
        data,
        "the reassembled file must match the source exactly"
    );

    // --- The acceptance criterion, measured precisely (not just "resume completes") ---
    // Bytes resent that duplicate an *already-delivered* chunk index (the wasted work resume exists
    // to eliminate), as a fraction of the bytes already delivered before the drop.
    let resent_already_delivered_bytes: u64 = resent_indices
        .iter()
        .filter(|i| delivered_indices.contains(i))
        .map(|&i| chunks[i as usize].len() as u64)
        .sum();
    let ratio = resent_already_delivered_bytes as f64 / already_delivered_bytes as f64;

    assert_eq!(
        resent_already_delivered_bytes, 0,
        "resume must never resend a single byte of an already-delivered chunk"
    );
    assert!(
        ratio <= 0.02,
        "resume must re-send no more than 2% of already-delivered data; measured {:.4}% \
         ({resent_already_delivered_bytes} of {already_delivered_bytes} already-delivered bytes)",
        ratio * 100.0
    );
}

/// Same real end-to-end pipeline (real `ice_restart()`, real `send_missing_chunks`) as the test
/// above, but exercising the case that test structurally cannot: a **non-contiguous** missing set.
/// `ResumeRequest`/`missing_indices`/`send_missing_chunks` are documented and designed to handle an
/// arbitrary scattered set of missing chunk indices — the bitmap-encoding unit tests in
/// `resume.rs` already cover non-contiguous sets at the encoding level (e.g.
/// `from_received_marks_exactly_the_unreceived_indices_missing`), but until this test, the full
/// send/resume pipeline (`send_missing_chunks` actually walking `data.chunks(CHUNK_SIZE)` and
/// resending only the addressed indices) had never been exercised end to end against a scattered
/// missing set, which could hide an off-by-one or range-based bug in the real resend path (e.g. a
/// buggy implementation that resent a contiguous range spanning `min..=max` of the missing set,
/// rather than exactly the missing indices, would still pass the prefix/suffix test above).
#[tokio::test]
async fn resume_after_ice_restart_resends_exactly_a_scattered_non_contiguous_missing_set() {
    let mut alice = Peer::new("resume.scatter.a");
    let mut bob = Peer::new("resume.scatter.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    // 12 full CHUNK_SIZE chunks + one short final chunk = 13 chunks total (same file-size setup as
    // the prefix/suffix test above, for an identical, already-validated chunk count).
    let data = sample_file(12 * CHUNK_SIZE + 999);
    let tree = MerkleTree::from_bytes(&data);
    let leaf_count = tree.leaf_count();
    assert_eq!(leaf_count, 13);

    let (sid, k_f, manifest) = open_file_transfer(
        &mut asess,
        &mut alice,
        &mut bsess,
        &mut bob,
        "movie.bin",
        &data,
    )
    .await;

    let mut resume_rx = alice_file.watch_resume(sid);

    // --- Phase 1: deliver a *scattered* subset of chunks: {2, 5, 9} never arrive; every other
    // index in 0..13 does. Not a contiguous prefix or suffix. ---
    const MISSING: [u64; 3] = [2, 5, 9];
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    assert_eq!(chunks.len() as u64, leaf_count as u64);

    let delivered_indices: Vec<u64> = (0..leaf_count as u64)
        .filter(|i| !MISSING.contains(i))
        .collect();
    for &i in &delivered_indices {
        send_chunk_frame(
            &mut asess,
            &mut alice.chat,
            sid,
            &k_f,
            i,
            chunks[i as usize],
        )
        .await
        .expect("phase 1 send must succeed");
    }
    drain_frames(&mut bsess, &mut bob, delivered_indices.len()).await;

    let mut receiver = FileReceiver::new(manifest, k_f);
    {
        let transfer = bob_file.transfer(sid).expect("bob tracks the transfer");
        feed_into_receiver(&mut receiver, &transfer.pending_chunks, &tree);
    }
    assert_eq!(receiver.received_offsets().len(), delivered_indices.len());
    assert!(!receiver.is_complete());

    // --- Phase 2: drop + redial, exactly as the prefix/suffix test does (task 10.22: real,
    // symmetric signaling round trip over a fresh restart-scoped relay pair, run concurrently). ---
    let (mut restart_relay_a, mut restart_relay_b) = MemRelay::pair(alice.ik(), bob.ik());
    let (ares, bres) = tokio::join!(
        asess.ice_restart(
            &mut restart_relay_a,
            &alice.store,
            alice.account.handle(),
            &mut alice.chat
        ),
        bsess.ice_restart(
            &mut restart_relay_b,
            &bob.store,
            bob.account.handle(),
            &mut bob.chat
        ),
    );
    ares.expect("alice ice_restart");
    bres.expect("bob ice_restart");

    send_resume_bitmap(&mut bsess, &mut bob.chat, sid, &receiver)
        .await
        .expect("bob sends the resume bitmap");

    match asess
        .pump(&alice.store, alice.account.handle(), &mut alice.chat)
        .await
    {
        Ok(None) => {}
        other => panic!("alice expected the resume frame to dispatch silently, got {other:?}"),
    }
    let resume = resume_rx
        .try_recv()
        .expect("alice's resume watcher must have received the bitmap");
    assert_eq!(
        resume.missing_indices(leaf_count),
        MISSING.to_vec(),
        "the bitmap must mark exactly the scattered missing set, not a superset spanning it"
    );

    // --- Phase 3: resume — alice resends only the missing chunks. ---
    let cfg = meridian_streams::sender::SenderConfig::default();
    let resent_indices =
        send_missing_chunks(&mut asess, &mut alice.chat, sid, &k_f, &data, &resume, &cfg)
            .await
            .expect("send_missing_chunks must succeed");

    // (a) exactly {2, 5, 9} — not a superset like the contiguous range 2..=9 that happens to
    // contain them.
    let resent_set: HashSet<u64> = resent_indices.iter().copied().collect();
    assert_eq!(
        resent_set,
        MISSING.iter().copied().collect::<HashSet<u64>>(),
        "resume must resend exactly the scattered missing set {{2, 5, 9}}, nothing more and \
         nothing less"
    );

    drain_frames(&mut bsess, &mut bob, resent_indices.len()).await;
    {
        let transfer = bob_file.transfer(sid).expect("bob tracks the transfer");
        // `pending_chunks` only ever grows (task 10.6's own contract): the first
        // `delivered_indices.len()` entries are phase 1's; feed just the newly-arrived tail.
        let new_frames = &transfer.pending_chunks[delivered_indices.len()..];
        feed_into_receiver(&mut receiver, new_frames, &tree);
    }

    // (c) the final reassembled file is byte-identical to the original.
    assert!(
        receiver.is_complete(),
        "the transfer must be complete after resume"
    );
    assert_eq!(
        receiver.reassemble().unwrap(),
        data,
        "the reassembled file must match the source exactly"
    );

    // (b) nothing already-delivered gets re-sent.
    let delivered_set: HashSet<u64> = delivered_indices.iter().copied().collect();
    let resent_already_delivered_bytes: u64 = resent_indices
        .iter()
        .filter(|i| delivered_set.contains(i))
        .map(|&i| chunks[i as usize].len() as u64)
        .sum();
    assert_eq!(
        resent_already_delivered_bytes, 0,
        "resume must never resend a single byte of an already-delivered chunk, even against a \
         scattered missing set"
    );
}
