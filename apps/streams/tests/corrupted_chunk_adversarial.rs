//! Corrupted-chunk adversarial test (task 10.16): proves, across the **full** sender→wire→receiver
//! pipeline (real X3DH handshake, real `P2pSession`, real `LoopbackTransport`, real sender-side
//! chunk-sealing, real ratchet-sealed `send_stream_frame`/`pump` hand-off, real `FileStream::on_frame`
//! dispatch), that an injected corrupted chunk is:
//! 1. detected — rejected via [`meridian_streams::ReceiveError::Crypto`], the per-chunk AEAD check
//!    (task 10.5/10.8), not merely "some error";
//! 2. never written to the reassembly buffer at **any** point before a correct resend arrives —
//!    checked against [`meridian_streams::FileReceiver`]'s own live state immediately after the
//!    corrupted frame is processed (and again after further frames land), not inferred after the
//!    fact from the final reassembled file;
//! 3. recovered via task 10.9's real in-stream resume mechanism (`ResumeRequest`/
//!    `send_missing_chunks`), triggering a genuine re-request rather than a second, ad hoc resend;
//! 4. ultimately delivered byte-identical to the source once the good chunk arrives.
//!
//! This is deliberately **not** what `receiver.rs`'s own unit tests already do (feed
//! `FileReceiver::receive_frame` a hand-corrupted byte string directly): this test drives the whole
//! pipeline — [`establish_ratchet`]/[`connect`]/[`open_file_transfer`] mirror `sender_engine.rs`
//! (task 10.7)'s and `resume_protocol.rs` (task 10.9)'s own harnesses — and the corruption is
//! injected on the frame's way onto the wire, not on the receiver's own API surface.
//!
//! ## Injection point, and why it's the correct layer (not a `Transport`-level proxy)
//! `docs/tasks/phase-10/10.16-corrupted-chunk-adversarial-test.md` suggests either (a) a thin
//! wrapping/proxy around the transport that flips a bit in one chunk frame as it passes through, or
//! (b) driving the real sender loop and mutating the specific frame bytes it produces before handing
//! them to the real receiver-side processing. This test uses (b), and deliberately **not** (a):
//!
//! `P2pSession::send_stream_frame` (task 10.4) ratchet-seals its `bytes` argument (task 10.5's
//! chunk-level AEAD ciphertext, already wrapped in a [`ChunkFrame`] and tagged, task 10.9) *before*
//! handing it to `Transport::send`. A `Transport`-level proxy can only ever see and mutate the
//! **outer ratchet ciphertext** — flipping a bit there fails the *ratchet's own* AEAD inside
//! `chat.open_stream_frame` at `pump()`, surfacing as `SessionError::Chat(_)` and never even
//! reaching `FileStream::on_frame`/`FileReceiver`. That would adversarially test the ratchet
//! substrate (already covered elsewhere), not this task's actual target: task 10.8's *chunk-level*
//! `ReceiveError::Crypto`. So instead, [`corrupted_chunk_wire_bytes`] below reproduces
//! [`meridian_streams::send_chunk_frame`]'s own real construction byte-for-byte — real
//! [`meridian_streams::seal_chunk`] (task 10.5's AEAD), real [`ChunkFrame::encode`], real
//! `tag_frame` (task 10.9's wire framing) — and flips one ciphertext byte only *after* all of that
//! real sealing/framing has happened, i.e. exactly the "somewhere between sender and receiver"
//! corruption point the task asks for. The corrupted bytes are then handed to the very same
//! `P2pSession::send_stream_frame` every good chunk in this test uses, so the corrupted frame still
//! travels through a real ratchet-seal, a real `LoopbackTransport` hop, a real ratchet-open at the
//! peer's `pump()`, and real `FileStream::on_frame` buffering — only the one byte that
//! `FileReceiver::receive_frame`'s own AEAD-open step is responsible for catching is wrong.

use std::sync::Arc;

use meridian_core::chat::ChatState;
use meridian_core::session::{answer, dial, MemRelay, P2pSession, SessionError, SessionEvent};
use meridian_core::streams::{register_stream_type, StreamRegistry};
use meridian_core::transport::{LoopbackFabric, LoopbackTransport, Transport};
use meridian_identity::{generate_account, AccountId, MemorySecretStore};
use meridian_signaling::generate_bundle;
use meridian_streams::merkle::{MerkleTree, CHUNK_SIZE};
use meridian_streams::resume::tag_frame;
use meridian_streams::sender::{send_chunk_frame, send_missing_chunks, send_resume_bitmap};
use meridian_streams::{seal_chunk, ChunkFrame, FileManifest, FileMeta, FileReceiver, FileStream};
use meridian_streams::{ReceiveError, SenderConfig, FRAME_TAG_CHUNK};

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

/// Mirrors `sender_engine.rs`/`resume_protocol.rs`'s own identical helper: establish the T03
/// ratchet between Alice (initiator) and Bob (responder).
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

/// Run dial+answer concurrently and return the two established, real P2P sessions.
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

/// Clears the first-contact gate so `mrd.file/1` OPENs aren't rejected outright.
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

/// Drains exactly `n` inbound stream frames on `sess`, asserting each dispatches silently.
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

/// Builds the exact tagged `mrd.file/1` wire bytes the real sender
/// ([`meridian_streams::send_chunk_frame`]) would produce for chunk `i` — real [`seal_chunk`] (task
/// 10.5's per-chunk AEAD), real [`ChunkFrame::encode`], real `tag_frame` (task 10.9's wire framing)
/// — but with one ciphertext byte flipped **after** all of that real sealing/framing, modeling
/// corruption introduced somewhere between the sender's own chunk-sealing step and the wire hand-off.
/// See this file's module doc for why this is the correct injection layer. The returned bytes are
/// handed to the very same `P2pSession::send_stream_frame` every good chunk in this test uses — the
/// only thing this test does differently from a real sender for this one chunk is flip this single
/// bit; ratchet-sealing, transport delivery, ratchet-opening, and `FileStream::on_frame` dispatch on
/// the other side are all the real, unmodified production code path.
fn corrupted_chunk_wire_bytes(k_f: &[u8; 32], i: u64, chunk: &[u8]) -> Vec<u8> {
    let mut sealed = seal_chunk(k_f, i, chunk);
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    let body = ChunkFrame { i, data: sealed }
        .encode()
        .expect("encoding a well-formed chunk frame never fails");
    tag_frame(FRAME_TAG_CHUNK, body)
}

#[tokio::test]
async fn corrupted_chunk_is_rejected_never_written_and_recovered_via_resume() {
    let mut alice = Peer::new("adversarial.a");
    let mut bob = Peer::new("adversarial.b");
    establish_ratchet(&mut alice, &mut bob);

    let fabric = LoopbackFabric::new();
    let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
    let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
    let (reg_a, reg_b, alice_file, bob_file) = file_registries();
    let (mut asess, mut bsess) = connect(ta, tb, &mut alice, &mut bob, reg_a, reg_b).await;
    clear_first_contact(&mut asess, &mut alice, &mut bsess, &mut bob).await;

    // 2 full CHUNK_SIZE chunks + one short final chunk = 3 chunks total, mirroring
    // `receiver.rs`'s own `sample_file` shape (full/full/partial), so a single mid-file target
    // chunk (index 1) is neither the first nor the last frame on the wire.
    let data = sample_file(2 * CHUNK_SIZE + 500);
    let tree = MerkleTree::from_bytes(&data);
    let leaf_count = tree.leaf_count();
    assert_eq!(leaf_count, 3);
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    assert_eq!(chunks.len(), leaf_count);

    let (sid, k_f, manifest) = open_file_transfer(
        &mut asess,
        &mut alice,
        &mut bsess,
        &mut bob,
        "adversarial.bin",
        &data,
    )
    .await;

    // Alice registers a resume watcher *before* sending anything, mirroring real usage
    // (`crate::resume`'s module doc on `FileStream::watch_resume`) and `resume_protocol.rs`'s own
    // harness.
    let mut resume_rx = alice_file.watch_resume(sid);

    const TARGET: u64 = 1;

    // --- Phase 1: a full send attempt, real sender code for every chunk except the injected byte
    // flip on the target. ---
    send_chunk_frame(&mut asess, &mut alice.chat, sid, &k_f, 0, chunks[0])
        .await
        .expect("chunk 0 send must succeed");

    let corrupted = corrupted_chunk_wire_bytes(&k_f, TARGET, chunks[TARGET as usize]);
    asess
        .send_stream_frame(&mut alice.chat, sid, &corrupted)
        .await
        .expect("handing the corrupted frame to the real ratchet-seal/transport path must succeed");

    send_chunk_frame(&mut asess, &mut alice.chat, sid, &k_f, 2, chunks[2])
        .await
        .expect("chunk 2 send must succeed");

    // All three frames cross the real wire: ratchet-seal -> `LoopbackTransport` -> ratchet-open at
    // Bob's `pump()` -> `FileStream::on_frame` buffering.
    drain_frames(&mut bsess, &mut bob, 3).await;
    let transfer = bob_file
        .transfer(sid)
        .expect("bob must have accepted and be tracking this transfer");
    assert_eq!(transfer.pending_chunks.len(), 3);

    let mut receiver = FileReceiver::new(manifest, k_f);

    // Chunk 0: genuinely good, must be accepted.
    {
        let frame = ChunkFrame::decode(&transfer.pending_chunks[&0]).expect("valid chunk frame");
        assert_eq!(frame.i, 0);
        let proof = tree.proof(0).expect("index in range");
        let accepted = receiver
            .receive_frame(&transfer.pending_chunks[&0], &proof)
            .expect("chunk 0 must pass AEAD + merkle verification");
        assert_eq!(accepted, 0);
    }
    assert_eq!(receiver.chunk(0).expect("chunk 0 written"), chunks[0]);

    // --- The adversarial frame itself: detected via task 10.8's chunk-level AEAD open, not merkle,
    // not a generic decode failure. ---
    {
        let frame =
            ChunkFrame::decode(&transfer.pending_chunks[&1]).expect("still a well-formed frame");
        assert_eq!(
            frame.i, TARGET,
            "the corrupted frame still claims the right index — only its ciphertext is wrong"
        );
        let proof = tree.proof(TARGET as usize).expect("index in range");
        let err = receiver
            .receive_frame(&transfer.pending_chunks[&1], &proof)
            .expect_err("a bit-flipped chunk must be rejected, never silently accepted");
        assert!(
            matches!(err, ReceiveError::Crypto { i } if i == TARGET),
            "must fail via the chunk-level AEAD-open path (task 10.8's `ReceiveError::Crypto`), \
             not merkle or a generic error: got {err:?}"
        );
    }

    // Assertion (required): never written, checked *immediately* after the corrupted frame is
    // processed and *before* anything else happens — not inferred from the eventual outcome.
    assert!(
        receiver.chunk(TARGET).is_none(),
        "the corrupted chunk's slot must remain empty immediately after rejection"
    );
    assert!(
        !receiver.received_offsets().contains(&TARGET),
        "the corrupted offset must not be recorded as received"
    );
    assert_eq!(
        receiver
            .received_offsets()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![0],
        "only chunk 0 has been accepted so far — the corrupted chunk contributed nothing"
    );
    assert!(!receiver.is_complete());

    // Chunk 2: also genuinely good, must be accepted independently of chunk 1's fate.
    {
        let frame = ChunkFrame::decode(&transfer.pending_chunks[&2]).expect("valid chunk frame");
        assert_eq!(frame.i, 2);
        let proof = tree.proof(2).expect("index in range");
        let accepted = receiver
            .receive_frame(&transfer.pending_chunks[&2], &proof)
            .expect("chunk 2 must pass AEAD + merkle verification");
        assert_eq!(accepted, 2);
    }

    // Re-assert "never written" now that two *other* chunks have landed around it — the corrupted
    // chunk's slot must still be empty, not just "empty right after the failure".
    assert!(
        receiver.chunk(TARGET).is_none(),
        "the corrupted chunk's slot must still be empty after later chunks are processed"
    );
    assert!(!receiver.received_offsets().contains(&TARGET));
    assert!(
        !receiver.is_complete(),
        "the transfer must not be reported complete while the corrupted chunk is still missing"
    );

    // --- Phase 2: a genuine re-request via task 10.9's real resume mechanism, not a bespoke resend
    // path. ---
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
        vec![TARGET],
        "the bitmap must mark exactly the corrupted (never-verified) chunk missing — nothing else"
    );

    // --- Phase 3: resume resends only the missing (corrupted) chunk, using its real, uncorrupted
    // bytes from the source file. ---
    let cfg = SenderConfig::default();
    let resent_indices =
        send_missing_chunks(&mut asess, &mut alice.chat, sid, &k_f, &data, &resume, &cfg)
            .await
            .expect("send_missing_chunks must succeed");
    assert_eq!(
        resent_indices,
        vec![TARGET],
        "resume must resend exactly the one corrupted/missing chunk, nothing already-verified"
    );

    drain_frames(&mut bsess, &mut bob, resent_indices.len()).await;
    let transfer_after_resume = bob_file.transfer(sid).expect("bob tracks the transfer");
    // (task 11.3) `pending_chunks` is now keyed by chunk index and bounded to one entry per index —
    // the genuine resend for `TARGET` *replaces* the earlier corrupted entry at the same key rather
    // than appending a fourth entry (see `TransferState::pending_chunks`'s own doc: this is exactly
    // the scenario — a resume resend superseding a previously-corrupted delivery — that requires
    // last-arrival-wins rather than first-wins/ignore semantics).
    assert_eq!(transfer_after_resume.pending_chunks.len(), 3);
    let resent_frame_bytes = &transfer_after_resume.pending_chunks[&TARGET];
    let resent_frame = ChunkFrame::decode(resent_frame_bytes).expect("valid chunk frame");
    assert_eq!(resent_frame.i, TARGET);
    let proof = tree.proof(TARGET as usize).expect("index in range");
    let accepted = receiver
        .receive_frame(resent_frame_bytes, &proof)
        .expect("the resent chunk is genuine and must pass both AEAD and merkle verification");
    assert_eq!(accepted, TARGET);

    // --- Final assertions: recovered correctly, and the transfer completes byte-identical. ---
    assert_eq!(
        receiver.chunk(TARGET).expect("target chunk now written"),
        chunks[TARGET as usize],
        "the recovered chunk must be the real, uncorrupted plaintext — never the corrupted bytes"
    );
    assert!(
        receiver.is_complete(),
        "the transfer must be complete once the resent chunk lands"
    );
    assert_eq!(
        receiver.reassemble().unwrap(),
        data,
        "the reassembled file must match the source exactly, byte for byte"
    );
}
