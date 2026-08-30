//! End-to-end sender engine tests (task 10.7), driven over a real two-party P2P session
//! (`LoopbackTransport`) — the actual `P2pSession::send_stream_frame`/`stream_buffered_amount`
//! substrate, not a stub, exactly like `manifest_seal_round_trip.rs` drives the real ratchet for
//! task 10.6.
//!
//! Covers:
//! - a small multi-chunk file sent via [`meridian_streams::send_file`] arrives completely and its
//!   chunks decode/open/reassemble byte-for-byte identical to the source, with progress events
//!   observed along the way;
//! - a multi-file batch via [`meridian_streams::send_files`] sends strictly sequentially (every
//!   progress event for file 0 precedes every event for file 1);
//! - [`meridian_streams::send_chunk_frame`] — the per-chunk primitive the whole-file loop is built
//!   on — does not assume call order reflects file order: calling it for chunks in a deliberately
//!   scrambled index order still produces frames that reassemble correctly once decoded by their
//!   own `i` field, proving the engine's own logic never relies on send/arrival order. (The channel
//!   itself is reliable + unordered per `FileStream::channel_cfg`; `LoopbackTransport`'s in-process
//!   fabric happens to deliver strictly FIFO in call order, so this test reorders *at the call
//!   level* rather than the wire level — see that test's own comment for why that is a meaningful
//!   proxy for "the engine never assumes order" even though this harness can't literally scramble
//!   in-flight bytes.)

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionError, SessionEvent};
use meridian_core::streams::{register_stream_type, StreamRegistry};
use meridian_core::transport::{LoopbackFabric, LoopbackTransport, Transport};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use meridian_streams::chunk::open_chunk;
use meridian_streams::merkle::{MerkleTree, CHUNK_SIZE};
use meridian_streams::sender::{send_chunk_frame, send_file, send_files, FileSend, SenderConfig};
use meridian_streams::{ChunkFrame, FileMeta, FileStream};

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

/// Establish the T03 ratchet between Alice (initiator) and Bob (responder), mirroring
/// `manifest_seal_round_trip.rs`/`apps/core/tests/p2p_session.rs`'s own harness.
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

/// Run dial+answer concurrently and return the two established sessions.
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

/// Clears the first-contact gate on `bsess`'s side for `alice` — every `mrd.file/1` OPEN this test
/// sends is otherwise rejected outright (`decide_file_offer`'s first-contact precedence), mirroring
/// `apps/core/tests/p2p_session.rs`'s own `accept_first_p2p_message` helper.
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
        Err(SessionError::Chat(_)) => {}
        other => panic!("expected the opening chat message to be gated, got {other:?}"),
    }
    bob.chat
        .accept_request(&alice.ik())
        .expect("accept the pending request");
}

/// Registers a `FileStream` (always-accept, via `ask_user`) on both sides, returning the registries
/// to hand to `connect` plus each side's own `Arc<FileStream>` handle — kept around so this test can
/// later read back Bob's received frames via `FileStream::transfer`, mirroring
/// `apps/core/tests/p2p_session.rs`'s `Exotic`/`Probe` test pattern of holding onto the concrete
/// type registered rather than only the trait-object registry.
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

/// Opens a `mrd.file/1` transfer for `data` from `alice` to `bob`, driving both sides' `pump` until
/// each has observed the stream open, and returns the shared `sid` plus alice's `k_f`.
async fn open_file_transfer<T: Transport>(
    asess: &mut P2pSession<T>,
    alice: &mut Peer,
    bsess: &mut P2pSession<T>,
    bob: &mut Peer,
    name: &str,
    data: &[u8],
) -> (u64, [u8; 32]) {
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

    (sid, *k_f)
}

/// Drains exactly `n` inbound stream frames on `sess` via `pump`, asserting each dispatches
/// silently (no `SessionEvent` of its own — the substrate never interprets stream-type bytes).
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

/// Reassembles a file from a `FileStream`'s raw `pending_chunks` (arrival order, **not** file
/// order — `on_frame` just appends) by decoding each `{i, data}` [`ChunkFrame`] and opening it
/// under `k_f`, placing plaintext at offset `i * CHUNK_SIZE`. Mirrors what a real receiver engine
/// (task 10.8) does, without depending on it, so this test can assert reassembly correctness on its
/// own regardless of the arrival order the raw frames happen to be in.
fn reassemble(pending: &[Vec<u8>], k_f: &[u8; 32], total_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; total_len];
    for raw in pending {
        let frame = ChunkFrame::decode(raw).expect("valid chunk frame");
        let plaintext = open_chunk(k_f, frame.i, &frame.data).expect("chunk opens under k_f");
        let start = frame.i as usize * CHUNK_SIZE;
        out[start..start + plaintext.len()].copy_from_slice(&plaintext);
    }
    out
}

fn sample_file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn send_file_delivers_a_multi_chunk_file_completely_with_progress_events() {
    let mut alice = Peer::new("sender.a");
    let mut bob = Peer::new("sender.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, _alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    // 3 full CHUNK_SIZE chunks + one short final chunk = 4 chunks total.
    let data = sample_file(3 * CHUNK_SIZE + 1234);
    let (sid, k_f) = open_file_transfer(
        &mut asess,
        &mut alice,
        &mut bsess,
        &mut bob,
        "movie.bin",
        &data,
    )
    .await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    send_file(
        &mut asess,
        &mut alice.chat,
        FileSend {
            sid,
            k_f: &k_f,
            name: "movie.bin".to_string(),
            data: &data,
        },
        &SenderConfig::default(),
        Some(&tx),
    )
    .await
    .expect("send_file must succeed");

    let mut events = Vec::new();
    while let Ok(p) = rx.try_recv() {
        events.push(p);
    }
    assert_eq!(events.len(), 4, "one progress event per chunk");
    for (idx, ev) in events.iter().enumerate() {
        assert_eq!(ev.file_index, 0);
        assert_eq!(ev.file_count, 1);
        assert_eq!(ev.name, "movie.bin");
        assert_eq!(ev.total_bytes, data.len() as u64);
        if idx > 0 {
            assert!(
                ev.bytes_sent > events[idx - 1].bytes_sent,
                "bytes_sent must strictly increase across progress events"
            );
        }
    }
    assert_eq!(events.last().unwrap().bytes_sent, data.len() as u64);

    drain_frames(&mut bsess, &mut bob, 4).await;
    let transfer = bob_file
        .transfer(sid)
        .expect("bob must have accepted and be tracking this transfer");
    assert_eq!(transfer.pending_chunks.len(), 4);

    let reassembled = reassemble(&transfer.pending_chunks, &k_f, data.len());
    assert_eq!(
        reassembled, data,
        "reassembled file must match the source exactly"
    );
}

#[tokio::test]
async fn send_files_sends_a_multi_file_batch_sequentially() {
    let mut alice = Peer::new("batch.a");
    let mut bob = Peer::new("batch.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, _alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    let file_a = sample_file(CHUNK_SIZE + 10); // 2 chunks
    let file_b = sample_file(500); // 1 chunk
    let (sid_a, k_f_a) = open_file_transfer(
        &mut asess, &mut alice, &mut bsess, &mut bob, "a.bin", &file_a,
    )
    .await;
    let (sid_b, k_f_b) = open_file_transfer(
        &mut asess, &mut alice, &mut bsess, &mut bob, "b.bin", &file_b,
    )
    .await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let files = vec![
        FileSend {
            sid: sid_a,
            k_f: &k_f_a,
            name: "a.bin".to_string(),
            data: &file_a,
        },
        FileSend {
            sid: sid_b,
            k_f: &k_f_b,
            name: "b.bin".to_string(),
            data: &file_b,
        },
    ];
    send_files(
        &mut asess,
        &mut alice.chat,
        &files,
        &SenderConfig::default(),
        Some(&tx),
    )
    .await
    .expect("send_files must succeed");

    let mut events = Vec::new();
    while let Ok(p) = rx.try_recv() {
        events.push(p);
    }
    assert_eq!(events.len(), 3, "2 chunks for file 0 + 1 chunk for file 1");
    assert!(
        events
            .windows(2)
            .all(|w| w[0].file_index <= w[1].file_index),
        "file_index must never decrease — sequential batch sending, never interleaved: {events:?}"
    );
    assert!(events.iter().all(|e| e.file_count == 2));
    let file0_events: Vec<_> = events.iter().filter(|e| e.file_index == 0).collect();
    let file1_events: Vec<_> = events.iter().filter(|e| e.file_index == 1).collect();
    assert_eq!(file0_events.len(), 2);
    assert_eq!(file1_events.len(), 1);
    assert_eq!(file0_events.last().unwrap().bytes_sent, file_a.len() as u64);
    assert_eq!(file1_events.last().unwrap().bytes_sent, file_b.len() as u64);

    drain_frames(&mut bsess, &mut bob, 3).await;
    let transfer_a = bob_file.transfer(sid_a).expect("transfer a tracked");
    let transfer_b = bob_file.transfer(sid_b).expect("transfer b tracked");
    assert_eq!(
        reassemble(&transfer_a.pending_chunks, &k_f_a, file_a.len()),
        file_a
    );
    assert_eq!(
        reassemble(&transfer_b.pending_chunks, &k_f_b, file_b.len()),
        file_b
    );
}

#[tokio::test]
async fn send_chunk_frame_does_not_assume_call_order_reflects_file_order() {
    // The channel is reliable + unordered (`FileStream::channel_cfg`): a real transport may deliver
    // frames in a different order than they were sent. `LoopbackTransport`'s in-process fabric is a
    // plain FIFO queue, so it can't itself reorder bytes in flight — but this test can still prove
    // the engine-level property the task cares about: `send_chunk_frame` bakes each frame's true
    // position into its own `i` field rather than relying on the order it was *called* in, so
    // calling it out of numeric order still produces a set of frames that any index-driven receiver
    // reassembles correctly. This is a meaningful proxy for "the engine doesn't assume in-order
    // delivery" because the one place order could leak in is exactly this per-chunk send primitive
    // — if it silently depended on being called `0, 1, 2, …`, scrambling the call order below would
    // corrupt the reassembled file; it doesn't.
    let mut alice = Peer::new("reorder.a");
    let mut bob = Peer::new("reorder.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, _alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    let data = sample_file(2 * CHUNK_SIZE + 777); // 3 chunks: 0, 1, 2 (2 short-final).
    let (sid, k_f) = open_file_transfer(
        &mut asess,
        &mut alice,
        &mut bsess,
        &mut bob,
        "scrambled.bin",
        &data,
    )
    .await;
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    assert_eq!(chunks.len(), 3);

    // Deliberately scrambled call order: 2, 0, 1 — the last chunk sent first.
    for &i in &[2usize, 0, 1] {
        send_chunk_frame(&mut asess, &mut alice.chat, sid, &k_f, i as u64, chunks[i])
            .await
            .expect("send_chunk_frame must succeed regardless of call order");
    }

    drain_frames(&mut bsess, &mut bob, 3).await;
    let transfer = bob_file.transfer(sid).expect("transfer tracked");
    assert_eq!(transfer.pending_chunks.len(), 3);

    // Bob's own arrival order mirrors the scrambled call order (loopback is FIFO) — proving the
    // *frames themselves*, not some out-of-band ordering, are what let reassembly succeed below.
    let first_arrived = ChunkFrame::decode(&transfer.pending_chunks[0]).expect("valid chunk frame");
    assert_eq!(
        first_arrived.i, 2,
        "arrival order must reflect the scrambled call order, not file order"
    );

    let reassembled = reassemble(&transfer.pending_chunks, &k_f, data.len());
    assert_eq!(
        reassembled, data,
        "reassembly by each frame's own `i` must succeed even though frames arrived out of order"
    );
}
