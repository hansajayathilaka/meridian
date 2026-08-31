//! `meridian send <mrd1-id> <path>...` — resumable P2P file transfer (T09), wiring
//! `meridian-streams`'s already-built sender/receiver primitives to a live `P2pSession`.
//!
//! **Orchestration only** (`apps/cli/CLAUDE.md`): every byte of chunking, per-chunk AEAD, and
//! merkle hashing lives in `meridian-streams`; this module only opens/drives a `mrd.file/1` stream
//! over an already-established session, renders progress, and prompts a human for the accept/reject
//! decision `FileStream::on_open` defers to it.
//!
//! ## Role / direction — `TODO: confirm` (design is silent; recorded here rather than invented)
//! Like `session connect`/`chat`, this command is symmetric at the P2P-handshake level: role
//! (dial vs. answer) is decided by key order (the lexicographically-smaller identity key initiates —
//! mirrors `chat.rs`/`session_connect.rs` exactly, so two peers both typing `meridian send <other>
//! <path>` never race). But unlike chat (an open-ended, bidirectional REPL), a `send` invocation
//! names a **directed** batch of files, and the underlying `P2pSession` has no split
//! reader/writer half — a single mutable session cannot both stream a multi-gigabyte upload out via
//! `meridian_streams::send_file`'s own blocking send loop *and* concurrently service inbound
//! `pump()` calls (nothing in that send loop ever calls `pump()` itself). Given that hard substrate
//! constraint, this implementation picks the simplest option that stays honest about it rather than
//! inventing a fix that would touch `meridian-core` (out of this task's scope): **only the
//! initiator's own `<path>...` batch is actually sent; the responder side receives** (via the exact
//! same command, `<path>...` unused on that side beyond its length feeding `--expect`'s default —
//! see below). A future task that gives `P2pSession` a real split, or a persistent
//! background-receiving daemon, would remove this restriction; it is recorded here, not hidden.
//!
//! ## Responder exit condition — `TODO: confirm`
//! There is no wire-level "batch complete" signal (`mrd.file/1` has no such message, and adding one
//! would be a core/wire change, also out of scope here). A real transport's connection close *would*
//! eventually surface as [`meridian_core::session::SessionEvent::Closed`] once the initiator closes
//! its own session, but `LoopbackTransport::close` only tears down the closer's own side of the
//! fabric (`apps/transport/src/loopback.rs`) — it does not, and this module must not assume it does,
//! wake the peer's `recv()`. So the responder instead exits once it has fully received and verified
//! `--expect` files (defaulting to its own `<path>...` count — an admittedly odd stand-in, but one
//! that never leaves the loop with nothing to bound it), falling back to `SessionEvent::Closed` too
//! wherever a real transport does deliver it.
//!
//! ## Receiver-side integrity check — whole-file merkle, not per-chunk
//! `apps/streams/src/receiver.rs`'s own module doc records an upstream `TODO: confirm`: the wire
//! carries no per-chunk merkle proof, so `FileReceiver::receive_frame` (which *requires* one) has no
//! real caller outside its own tests (which hand it a proof computed from the sender's already-known
//! plaintext — impossible for a genuine receiver, who by definition doesn't have the file yet). This
//! module does not invent a proof-delivery mechanism (that would be new wire/protocol design,
//! explicitly out of this task's scope); instead it reassembles every chunk (AEAD-opened via
//! [`meridian_streams::open_chunk`], the real per-chunk integrity check) into an in-memory buffer and
//! verifies the **whole-file** merkle root against the manifest before writing anything to disk — a
//! single bit-flip anywhere still fails this check and the file is never written, matching the
//! "corrupted chunk is detected, never written" property, just checked once at the end rather than
//! per chunk.

#[cfg(any(test, feature = "webrtc"))]
use std::collections::{BTreeSet, HashMap, HashSet};
#[cfg(any(test, feature = "webrtc"))]
use std::io::Write as _;
#[cfg(any(test, feature = "webrtc"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(test, feature = "webrtc"))]
use std::sync::Arc;

#[cfg(any(test, feature = "webrtc"))]
use tokio::sync::mpsc;
#[cfg(any(test, feature = "webrtc"))]
use zeroize::Zeroizing;

#[cfg(any(test, feature = "webrtc"))]
use meridian_core::chat::{ChatError, ChatState};
use meridian_core::identity::{KeyHandle, SecretStore};
#[cfg(any(test, feature = "webrtc"))]
use meridian_core::session::{P2pSession, SessionError, SessionEvent};
#[cfg(any(test, feature = "webrtc"))]
use meridian_core::streams::StreamId;
#[cfg(any(test, feature = "webrtc"))]
use meridian_core::transport::Transport;
#[cfg(any(test, feature = "webrtc"))]
use meridian_streams::{
    open_chunk, send_file, ChunkFrame, FileManifest, FileMeta, FileSend, FileStream, Hash,
    MerkleTree, SendProgress, SenderConfig, CHUNK_SIZE,
};

/// The opening chat message the initiator sends before any `mrd.file/1` OPEN, purely to clear
/// `PolicyCtx::first_contact` on the responder's side (`decide_file_offer` rejects a first-contact
/// OPEN outright, regardless of the file-level accept/reject hook this task actually cares about) —
/// see the module doc's "Role / direction" section. Never shown to a human on either side (this
/// command has no interactive chat surface of its own).
#[cfg(any(test, feature = "webrtc"))]
const HELLO: &str = "meridian send: opening a file-transfer session";

/// Everything [`run`] needs to establish the real, cross-process P2P session and drive a transfer
/// batch. Mirrors `session_connect.rs::ConnectArgs`/`chat.rs::ChatArgs`. Every field besides those
/// `run`'s own `#[cfg(not(feature = "webrtc"))]` fallback touches is only read by
/// [`run_webrtc`] — mirrors `session_connect.rs::ConnectArgs`'s identical `allow(dead_code)`.
#[cfg_attr(not(feature = "webrtc"), allow(dead_code))]
pub struct SendArgs<'a> {
    pub server: String,
    pub store: &'a dyn SecretStore,
    pub handle: &'a KeyHandle,
    pub account_pub: [u8; 32],
    pub peer_ik: [u8; 32],
    pub peer_label: String,
    pub peer_hint: String,
    pub paths: Vec<PathBuf>,
    pub out_dir: PathBuf,
    /// How many inbound files the responder role waits to fully receive before exiting — see the
    /// module doc's "Responder exit condition" section. Defaults to `paths.len()` at the call site
    /// (`main.rs`) when not given explicitly.
    pub expect: usize,
    pub json: bool,
}

pub async fn run(args: SendArgs<'_>) -> Result<(), String> {
    #[cfg(feature = "webrtc")]
    {
        run_webrtc(args).await
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = args;
        Err(
            "meridian-cli was built without the `webrtc` feature; rebuild with `--features \
             webrtc` to use `meridian send`"
                .to_string(),
        )
    }
}

#[cfg(feature = "webrtc")]
async fn run_webrtc(args: SendArgs<'_>) -> Result<(), String> {
    use meridian_core::proto::error_codes;
    use meridian_core::relay;
    use meridian_core::session::{answer_with_config, dial_with_config};
    use meridian_core::signal_relay::RendezvousRelay;
    use meridian_core::signaling::{SignalError, SignalingClient, DEFAULT_OTK_COUNT};
    use meridian_core::streams::{register_stream_type, StreamRegistry};
    use meridian_core::transport::{IcePolicy, IceServer, WebRtcTransport};

    let SendArgs {
        server,
        store,
        handle,
        account_pub,
        peer_ik,
        peer_label,
        peer_hint,
        paths,
        out_dir,
        expect,
        json,
    } = args;

    let resolved_policy = crate::policy::load()?.resolve(&peer_ik);
    let mut chat = ChatState::default();

    let mut client = SignalingClient::connect(&server, store, handle, account_pub, None, 1)
        .await
        .map_err(|e| format!("connecting to {server}: {e}"))?;

    // Real ephemeral TURN credentials (mirrors `session_connect.rs::run_webrtc` exactly — same
    // reasoning for the `direct`-only degrade-on-`turn_unavailable` behavior).
    let ice_servers: Vec<IceServer> = match client.request_turn_credentials().await {
        Ok(grant) => vec![IceServer {
            urls: grant.urls,
            username: Some(grant.username),
            credential: Some(grant.credential),
        }],
        Err(SignalError::Server(e)) if e.code == error_codes::TURN_UNAVAILABLE => {
            if resolved_policy != IcePolicy::Direct {
                return Err(format!(
                    "no TURN relay is configured on {server} (turn_unavailable), but the \
                     configured policy for {peer_label} is {} — refusing to silently connect \
                     without relay, which would expose host/srflx candidates to the peer",
                    meridian_core::relay::policy_str(resolved_policy)
                ));
            }
            Vec::new()
        }
        Err(e) => {
            return Err(format!("requesting TURN credentials from {server}: {e}"));
        }
    };

    let generated = client
        .publish_bundle(store, handle, DEFAULT_OTK_COUNT)
        .await
        .map_err(|e| format!("publishing bundle: {e}"))?;
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
        crate::now_unix(),
    );

    let initiator = account_pub.as_slice() <= peer_ik.as_slice();
    if initiator {
        let peer_bundle = fetch_with_retry(&mut client, peer_ik, &peer_hint, &peer_label).await?;
        chat.start_initiator_session(
            store,
            handle,
            &account_pub,
            &peer_ik,
            &peer_bundle.spk,
            peer_bundle.otks.first().copied(),
        )
        .map_err(|e| format!("establishing session: {e}"))?;
    }

    // The accept/reject prompt (deliverable 3): a real, blocking terminal prompt. `on_open` is a
    // synchronous trait method with no async escape hatch (`apps/streams/src/file.rs`'s own doc on
    // `with_ask_user`), so this closure must decide synchronously.
    let prompt_label = peer_label.clone();
    let file_stream = Arc::new(FileStream::with_ask_user(
        meridian_streams::DEFAULT_AUTO_ACCEPT_IMAGE_MAX_BYTES,
        move |_policy, manifest| prompt_accept(&prompt_label, manifest),
    ));
    let mut registry = StreamRegistry::with_builtins();
    register_stream_type(&mut registry, file_stream.clone());
    let registry = Arc::new(registry);

    let transport = Arc::new(WebRtcTransport::new());
    let cfg = relay::ice_config(resolved_policy, ice_servers, Vec::new());

    let mut session = {
        let mut adapter = RendezvousRelay::new(&mut client, Some(peer_hint.clone()));
        if initiator {
            dial_with_config(
                transport,
                store,
                handle,
                account_pub,
                peer_ik,
                &mut chat,
                &mut adapter,
                registry,
                cfg,
            )
            .await
            .map_err(|e| format!("dial: {e}"))?
        } else {
            answer_with_config(
                transport,
                store,
                handle,
                account_pub,
                peer_ik,
                &mut chat,
                &mut adapter,
                registry,
                cfg,
            )
            .await
            .map_err(|e| format!("answer: {e}"))?
        }
    };
    // T04's "servers out of the data path" property — the rendezvous connection is no longer
    // needed once the P2P session is up (mirrors `session_connect.rs`).
    let _ = client.close().await;

    let files = if initiator {
        read_files(&paths)?
    } else {
        Vec::new()
    };

    let report = run_over_session(
        &mut session,
        store,
        handle,
        &mut chat,
        account_pub,
        peer_ik,
        initiator,
        &files,
        &file_stream,
        &out_dir,
        expect,
        json,
    )
    .await?;
    print_report(&report, json);
    let _ = session.close().await;
    Ok(())
}

/// Mirrors `session_connect.rs::fetch_with_retry` exactly.
#[cfg(feature = "webrtc")]
async fn fetch_with_retry(
    client: &mut meridian_core::signaling::SignalingClient,
    peer_ik: [u8; 32],
    peer_hint: &str,
    peer_label: &str,
) -> Result<meridian_core::proto::PrekeyBundle, String> {
    use meridian_core::signaling::SignalError;
    let mut stale_hint = false;
    for attempt in 0..40u32 {
        match client
            .fetch_bundle(peer_ik, Some(peer_hint.to_string()), false)
            .await
        {
            Ok(bundle) => return Ok(bundle),
            Err(SignalError::Server(e)) if e.code == "not_found" => {
                stale_hint = false;
                if attempt == 0 {
                    eprintln!("waiting for {peer_label} to come online…");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(SignalError::NotFoundAtHint { .. }) => {
                stale_hint = true;
                if attempt == 0 {
                    eprintln!("waiting for {peer_label} to come online at {peer_hint}…");
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => {
                return Err(format!("fetching {peer_label}: {e}"));
            }
        }
    }
    if stale_hint {
        Err(format!(
            "{peer_label} unreachable at hint {peer_hint}: no account found there after \
             retrying — the hint may be stale"
        ))
    } else {
        Err(format!("{peer_label} did not publish a bundle in time"))
    }
}

/// Reads every path's bytes plus a wire-safe display name (basename only — never the full local
/// path, which could leak local directory structure to the peer).
#[cfg(feature = "webrtc")]
fn read_files(paths: &[PathBuf]) -> Result<Vec<(String, Vec<u8>)>, String> {
    paths
        .iter()
        .map(|p| {
            let data = std::fs::read(p).map_err(|e| format!("reading {}: {e}", p.display()))?;
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_string)
                .unwrap_or_else(|| p.display().to_string());
            Ok((name, data))
        })
        .collect()
}

/// A real, blocking terminal accept/reject prompt for a non-auto-accepted incoming file
/// (deliverable 3). Fails closed (declines) on any I/O error reading the answer.
#[cfg(feature = "webrtc")]
fn prompt_accept(peer_label: &str, manifest: &FileManifest) -> bool {
    println!(
        "incoming file from {peer_label}: {} ({} bytes) — accept? y/n",
        manifest.name, manifest.size
    );
    print!("> ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// What a completed [`run_over_session`] call accomplished — used by the real command to print a
/// final summary and by tests to assert on outcomes.
#[derive(Debug, Default)]
#[cfg(any(test, feature = "webrtc"))]
pub(crate) struct SendReport {
    pub sent: Vec<String>,
    pub received: Vec<PathBuf>,
}

#[cfg(feature = "webrtc")]
fn print_report(report: &SendReport, json: bool) {
    if json {
        return; // every event was already emitted as it happened.
    }
    if report.sent.len() > 1 {
        println!(
            "sent {} file(s): {}",
            report.sent.len(),
            report.sent.join(", ")
        );
    }
    for path in &report.received {
        println!("  saved to {}", path.display());
    }
}

/// Drives one side of a `send` batch over an already-established `P2pSession` — the shared core
/// both the real `webrtc` command and this module's own tests call, generic over [`Transport`] so
/// the loopback test below can drive it without any network. See the module doc for the
/// initiator/responder split this dispatches on.
#[cfg(any(test, feature = "webrtc"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_over_session<T: Transport>(
    session: &mut P2pSession<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    chat: &mut ChatState,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    initiator: bool,
    to_send: &[(String, Vec<u8>)],
    file_stream: &FileStream,
    out_dir: &Path,
    expect_inbound: usize,
    json: bool,
) -> Result<SendReport, String> {
    if initiator {
        run_initiator(session, store, handle, chat, our_ik, peer_ik, to_send, json).await
    } else {
        run_responder(
            session,
            store,
            handle,
            chat,
            our_ik,
            peer_ik,
            file_stream,
            out_dir,
            expect_inbound,
            json,
        )
        .await
    }
}

/// Thin wrapper around [`run_initiator_inner`] that guarantees `session.close()` runs on **every**
/// exit path — success, a declined transfer, or any other error — not just the happy path. A
/// declined/failed transfer must not leave the session dangling open: nothing else on this side is
/// ever coming, and (per the module doc's "Responder exit condition" section) the responder side has
/// no other way to learn that.
#[cfg(any(test, feature = "webrtc"))]
#[allow(clippy::too_many_arguments)]
async fn run_initiator<T: Transport>(
    session: &mut P2pSession<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    chat: &mut ChatState,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    to_send: &[(String, Vec<u8>)],
    json: bool,
) -> Result<SendReport, String> {
    let result =
        run_initiator_inner(session, store, handle, chat, our_ik, peer_ik, to_send, json).await;
    let _ = session.close().await;
    result
}

#[cfg(any(test, feature = "webrtc"))]
#[allow(clippy::too_many_arguments)]
async fn run_initiator_inner<T: Transport>(
    session: &mut P2pSession<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    chat: &mut ChatState,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    to_send: &[(String, Vec<u8>)],
    json: bool,
) -> Result<SendReport, String> {
    // Clear the responder's first-contact gate before any `mrd.file/1` OPEN — see the module doc's
    // "Role / direction" section.
    session
        .send_chat(store, handle, chat, HELLO)
        .await
        .map_err(|e| e.to_string())?;

    let info = session.info().await;
    let mut sent = Vec::new();
    for (name, data) in to_send {
        let tree = MerkleTree::from_bytes(data);
        let root = tree.root();
        print_open_lines(
            name,
            to_send.len(),
            &root,
            tree.leaf_count(),
            &info.path.to_string(),
            json,
        );

        let (params, k_f) = FileStream::build_open_params(
            chat,
            store,
            handle,
            &our_ik,
            &peer_ik,
            FileMeta {
                name: name.clone(),
                size: data.len() as u64,
                root,
            },
        )
        .map_err(|e| format!("{name}: {e}"))?;

        let sid = session
            .open_stream(store, handle, chat, meridian_streams::file::NAME, params)
            .await
            .map_err(|e| format!("{name}: opening transfer: {e}"))?;

        // Wait for the responder's Accept/Reject for exactly this sid, silently servicing anything
        // else pump() surfaces along the way (there should be nothing else on this simple path, but
        // stay defensive rather than assume it).
        loop {
            match session.pump(store, handle, chat).await {
                Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
                Ok(_) => {}
                Err(SessionError::StreamRejected {
                    sid: rsid,
                    code,
                    reason,
                }) if rsid == sid => {
                    return Err(format!("{name}: declined ({code}: {reason})"));
                }
                Err(e) => return Err(format!("{name}: {e}")),
            }
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let printer = tokio::spawn(print_progress_loop(rx, json));
        let result = send_file(
            session,
            chat,
            FileSend {
                sid,
                k_f: &k_f,
                name: name.clone(),
                data,
            },
            &SenderConfig::default(),
            Some(&tx),
        )
        .await;
        drop(tx);
        let _ = printer.await;
        result.map_err(|e| format!("{name}: {e}"))?;

        print_sent_done_line(&root, json);
        sent.push(name.clone());
    }

    Ok(SendReport {
        sent,
        received: Vec::new(),
    })
}

#[cfg(any(test, feature = "webrtc"))]
#[allow(clippy::too_many_arguments)]
async fn run_responder<T: Transport>(
    session: &mut P2pSession<T>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
    chat: &mut ChatState,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    file_stream: &FileStream,
    out_dir: &Path,
    expect_inbound: usize,
    json: bool,
) -> Result<SendReport, String> {
    let mut tracked: HashMap<StreamId, (FileManifest, Zeroizing<[u8; 32]>)> = HashMap::new();
    // "Settled" transfers this side will never re-attempt — either finalized successfully (also in
    // `received`) or definitively, unrecoverably failed (also in `failed`). See BLOCKING #1: this
    // must only ever gain an entry on one of those two terminal outcomes, never merely because
    // `finalize_transfer` was *attempted* — inserting unconditionally after any `Err` used to make a
    // recoverable-looking failure (e.g. one triggered by counting duplicate frames as if they were
    // distinct chunks) permanently un-trackable, hanging this whole loop forever.
    let mut finalized: HashSet<StreamId> = HashSet::new();
    let mut received: Vec<PathBuf> = Vec::new();
    // File names whose transfer definitively failed verification (see below) — counted toward
    // `expect_inbound` so this loop still terminates instead of waiting forever for a chunk that
    // provably cannot still be missing, and surfaced as a hard error (nonzero exit) once the loop
    // ends rather than silently reported as if nothing were wrong (should-fix note in BLOCKING #1).
    let mut failed: Vec<String> = Vec::new();

    while received.len() + failed.len() < expect_inbound {
        match session.pump(store, handle, chat).await {
            Ok(Some(SessionEvent::Closed)) => break,
            Ok(Some(SessionEvent::StreamOpened(sid, ty))) if ty == meridian_streams::file::NAME => {
                if let Some(transfer) = file_stream.transfer(sid) {
                    if let Some(manifest) = transfer.manifest {
                        match chat.open_bytes(
                            store,
                            handle,
                            &our_ik,
                            &peer_ik,
                            &manifest.key,
                            false,
                        ) {
                            Ok(k_f_bytes) => match <[u8; 32]>::try_from(k_f_bytes.as_slice()) {
                                Ok(k_f) => {
                                    print_incoming_line(&manifest, json);
                                    tracked.insert(sid, (manifest, Zeroizing::new(k_f)));
                                }
                                Err(_) => eprintln!(
                                    "! {}: unsealed transfer key has the wrong length",
                                    manifest.name
                                ),
                            },
                            Err(e) => {
                                eprintln!(
                                    "! {}: failed to unseal the transfer key: {e}",
                                    manifest.name
                                )
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                // Anything else — most commonly `Ok(None)`, a raw stream frame (a chunk) dispatched
                // silently into `file_stream`'s own buffer — is a cue to check every tracked,
                // not-yet-finalized transfer for completion.
                let sids: Vec<StreamId> = tracked
                    .keys()
                    .copied()
                    .filter(|s| !finalized.contains(s))
                    .collect();
                for sid in sids {
                    let Some((manifest, k_f)) = tracked.get(&sid) else {
                        continue;
                    };
                    let Some(transfer) = file_stream.transfer(sid) else {
                        continue;
                    };
                    // BLOCKING #1: completion is judged by the number of *distinct* chunk indices
                    // actually received, never by `pending_chunks.len()` (a raw arrival-order frame
                    // count). `mrd.file/1` is reliable-unordered, so a duplicate/retransmitted
                    // delivery of a chunk already received is expected and must not be double-counted
                    // — otherwise this could fire (and fail) while a genuinely distinct chunk index
                    // is still missing.
                    //
                    // Verification-review fix: cardinality alone (`distinct.len() >= leaf_count`) is
                    // not sufficient — it says nothing about *which* indices are present. A peer
                    // holding `k_f` (ordinarily the sender, but also anyone who compromises it) can
                    // send an extra, distinct, out-of-range chunk frame (e.g. `i = 999` for a
                    // 3-chunk file) before the real final chunk arrives; `{0, 1, 999}.len() == 3`
                    // would satisfy the old cardinality check while chunk 2 is still genuinely
                    // missing, firing `finalize_transfer` prematurely and permanently settling the
                    // transfer as failed once it (correctly) rejects the out-of-range frame — even
                    // though the real final chunk arrives moments later. Require *membership* of
                    // every required index instead: only every real index `0..leaf_count` having
                    // actually arrived may trigger finalization.
                    let distinct = distinct_chunk_indices(&transfer.pending_chunks);
                    let leaf_count = leaf_count_for_size(manifest.size) as u64;
                    if (0..leaf_count).all(|i| distinct.contains(&i)) {
                        match finalize_transfer(manifest, k_f, &transfer.pending_chunks, out_dir) {
                            Ok(path) => {
                                print_received_line(manifest, json);
                                received.push(path);
                                finalized.insert(sid);
                            }
                            Err(e) => {
                                // Every distinct chunk index this transfer will ever structurally
                                // need has already arrived (checked above) — this module wires no
                                // resume/re-request mechanism (module doc, "Responder exit
                                // condition"), so there is no further legitimate frame that could
                                // still fix this. Treat it as a hard, terminal failure: settle it
                                // (never retried) and count it toward `expect_inbound` so the loop
                                // still terminates rather than hanging on a transfer that can
                                // provably never complete.
                                eprintln!(
                                    "! {}: transfer failed verification and cannot be completed \
                                     ({e}) — not written",
                                    manifest.name
                                );
                                failed.push(manifest.name.clone());
                                finalized.insert(sid);
                            }
                        }
                    }
                }
            }
            Err(SessionError::Chat(ChatError::MessageRequest)) => {
                // The initiator's opening `HELLO` (see `run_initiator`) — this command has no
                // interactive chat surface of its own (only the per-*file* accept/reject prompt,
                // wired through `FileStream`'s own `ask_user` hook), so auto-accept the chat-level
                // request, mirroring `session.rs::run_demo_generic`'s identical precedent. This
                // clears `PolicyCtx::first_contact`, which is the actual gate on the file-level OPEN
                // that follows and that this task's own accept/reject decision lives at.
                if chat.accept_request(&peer_ik).is_none() {
                    return Err("accepting inbound session: no pending request found".to_string());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    if !failed.is_empty() {
        return Err(format!(
            "{} of {} incoming transfer(s) failed verification and were not written: {}",
            failed.len(),
            failed.len() + received.len(),
            failed.join(", ")
        ));
    }

    Ok(SendReport {
        sent: Vec::new(),
        received,
    })
}

/// Distinct chunk indices actually received so far for one transfer, decoded from each raw
/// arrival-order frame's own `i` field — see BLOCKING #1. A frame that fails to decode contributes no
/// index here (it is not silently treated as "received"); if a transfer is later attempted to
/// finalize anyway, [`finalize_transfer`] will surface that same decode failure itself. Mirrors
/// `apps/streams/src/receiver.rs::FileReceiver::received_offsets`'s identical intent for the identical
/// wire shape.
#[cfg(any(test, feature = "webrtc"))]
fn distinct_chunk_indices(pending_chunks: &[Vec<u8>]) -> BTreeSet<u64> {
    pending_chunks
        .iter()
        .filter_map(|raw| ChunkFrame::decode(raw).ok())
        .map(|frame| frame.i)
        .collect()
}

/// Sanity cap on `manifest.size` before eagerly allocating an in-memory whole-file reassembly buffer
/// (should-fix #6). `manifest.size` is sender-controlled and otherwise completely unbounded, so a
/// hostile or buggy peer could claim an absurd (e.g. multi-terabyte) size purely to force a large
/// allocation before a single byte of the transfer is ever verified — a real memory-exhaustion
/// surface. 4 GiB comfortably covers any realistic test/demo file while still rejecting an obviously
/// unreasonable claim.
///
/// `TODO: confirm` / follow-up, not attempted here: the real fix is streaming reassembly straight to
/// disk (verifying incrementally, or writing to a temp file and never holding the whole plaintext in
/// memory at once), removing the need for this cap entirely. See the module doc's "Receiver-side
/// integrity check" section for why an in-memory whole-file buffer was chosen for this task in the
/// first place.
#[cfg(any(test, feature = "webrtc"))]
const MAX_TRANSFER_SIZE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Reassembles a completed transfer's raw, arrival-order `pending_chunks` (each already AEAD-opened
/// here) into the declared file size, verifies the whole-file merkle root, and — only on a match —
/// writes it under `out_dir`. See the module doc's "Receiver-side integrity check" section for why
/// this checks the whole file rather than calling `FileReceiver::receive_frame` per chunk.
#[cfg(any(test, feature = "webrtc"))]
fn finalize_transfer(
    manifest: &FileManifest,
    k_f: &[u8; 32],
    pending_chunks: &[Vec<u8>],
    out_dir: &Path,
) -> Result<PathBuf, String> {
    if manifest.size > MAX_TRANSFER_SIZE_BYTES {
        return Err(format!(
            "declared file size {} bytes exceeds the {} byte sanity cap — refusing to allocate a \
             whole-file reassembly buffer for a possibly-hostile size claim",
            manifest.size, MAX_TRANSFER_SIZE_BYTES
        ));
    }
    let leaf_count = leaf_count_for_size(manifest.size);
    let mut buf = vec![0u8; manifest.size as usize];
    for raw in pending_chunks {
        let frame = ChunkFrame::decode(raw).map_err(|e| format!("malformed chunk frame: {e}"))?;
        // BLOCKING #2: reject an out-of-range chunk index *before* AEAD-opening it or doing any
        // offset arithmetic on it. `k_f` authenticates only (key, index) — not that the index is
        // actually in range for this file — so any peer holding `k_f` (ordinarily the sender, but
        // also anyone who compromises it) can otherwise supply an arbitrary `u64` index that still
        // authenticates. Without this check, `frame.i as usize * CHUNK_SIZE` for a huge `frame.i`
        // (e.g. near `2^48`) overflows: it panics in a debug build (crashing this whole receiver
        // process on one malformed chunk) and silently wraps to an in-bounds-looking offset in
        // release, corrupting the reassembly buffer at the wrong location. Mirrors
        // `apps/streams/src/receiver.rs::FileReceiver::receive_frame`'s own `OutOfRange` check.
        //
        // Verification-review fix: this used to be fatal for the *whole* transfer (`return Err`),
        // but the caller (`run_responder`'s completion check, above) now only ever calls this
        // function once every real index `0..leaf_count` genuinely has at least one valid-looking
        // frame among `pending_chunks` (see the membership fix there) — `pending_chunks` can still
        // legitimately contain *extra* frames mixed in among those required ones: duplicates,
        // retransmits, or a stray/hostile out-of-range index. None of those are load-bearing for
        // this transfer's success, so skip (not fail) an out-of-range frame here and keep
        // reassembling the indices that actually matter. A frame that *is* in-range but fails to
        // authenticate, or an overrun offset, remains a real, reportable failure below.
        if frame.i as usize >= leaf_count {
            continue;
        }
        let plaintext = open_chunk(k_f, frame.i, &frame.data)
            .map_err(|_| format!("chunk {} failed to authenticate", frame.i))?;
        // Defense in depth even though `frame.i` is now bounds-checked above: never let offset
        // arithmetic itself silently wrap.
        let start = (frame.i as usize)
            .checked_mul(CHUNK_SIZE)
            .ok_or_else(|| format!("chunk {} offset overflow", frame.i))?;
        let end = start
            .checked_add(plaintext.len())
            .ok_or_else(|| format!("chunk {} index overflow", frame.i))?;
        if end > buf.len() {
            return Err(format!(
                "chunk {} overruns the file's declared size — not written",
                frame.i
            ));
        }
        buf[start..end].copy_from_slice(&plaintext);
    }

    let root = MerkleTree::from_bytes(&buf).root();
    if root != manifest.root {
        return Err(format!(
            "merkle root mismatch: expected {}, got {} — transfer corrupted, not written",
            format_root_short(&manifest.root),
            format_root_short(&root)
        ));
    }

    let name = sanitize_file_name(&manifest.name);
    let (mut file, path) = create_unique_file(out_dir, &name)
        .map_err(|e| format!("creating output file for {}: {e}", manifest.name))?;
    file.write_all(&buf)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Number of [`CHUNK_SIZE`] leaves a file of `size` bytes was split into — mirrors
/// `meridian_streams::merkle::MerkleTree`'s own zero-byte convention (a single virtual leaf, never
/// zero leaves), since the responder only ever has `manifest.size` to go on, never the file bytes
/// themselves, until every chunk has arrived.
#[cfg(any(test, feature = "webrtc"))]
fn leaf_count_for_size(size: u64) -> usize {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_SIZE as u64) as usize
    }
}

/// Reduces a sender-supplied file name to a safe on-disk basename: strips any directory components
/// (blocking path traversal, e.g. `../../etc/passwd`) and falls back to a generic name for an empty
/// or `.`/`..` result. `apps/streams/src/manifest.rs`'s own doc flags this exact guard as owed by
/// whichever layer first writes a `mrd.file/1` name to disk — this module is that layer.
#[cfg(any(test, feature = "webrtc"))]
fn sanitize_file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or("received-file")
        .to_string()
}

/// Avoids silently clobbering an existing file in `dir` (appending a numeric suffix on any collision)
/// while also closing should-fix #3's TOCTOU/symlink hazard: creates and returns an exclusively-opened
/// file handle rather than a mere path a caller writes to separately.
///
/// `Path::exists()` (the previous implementation) *follows* symlinks and reports `false` for a
/// dangling one — so a directory entry planted ahead of time as a dangling symlink pointing outside
/// `out_dir` would be treated as "free", and a later plain `std::fs::write` would happily follow it,
/// writing outside `out_dir` and defeating this function's entire purpose. There is also a plain
/// check-then-write race even against a real (non-symlink) file created concurrently between the
/// check and the write.
///
/// `OpenOptions::create_new` closes both problems at once: it fails with `AlreadyExists` for *any*
/// existing directory entry at that path — including a dangling symlink — and, being a single syscall
/// rather than a check followed by a separate write, is atomic against a concurrent creator. On that
/// specific error this simply retries the next numeric-suffix candidate.
#[cfg(any(test, feature = "webrtc"))]
fn create_unique_file(dir: &Path, name: &str) -> Result<(std::fs::File, PathBuf), String> {
    for n in 0u32.. {
        let path = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{name}.{n}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    unreachable!("u32 suffix space exhausted")
}

/// `b3:9af2…` — the demo script's own truncated-root shape.
#[cfg(any(test, feature = "webrtc"))]
fn format_root_short(root: &Hash) -> String {
    format!("b3:{}…", hex::encode(&root[..2]))
}

/// `[file] merkle root b3:9af2… | 16384 chunks | direct path` — the demo script's own header line,
/// verbatim for a single-file send; prefixed with a disambiguating "sending N/M" line for a
/// multi-file batch (the demo script only ever shows one file).
#[cfg(any(test, feature = "webrtc"))]
fn print_open_lines(
    name: &str,
    batch_len: usize,
    root: &Hash,
    chunks: usize,
    path: &str,
    json: bool,
) {
    if json {
        println!(
            "{{\"event\":\"file_open\",\"name\":{},\"root\":\"b3:{}\",\"chunks\":{chunks}}}",
            json_string(name),
            hex::encode(root)
        );
        return;
    }
    if batch_len > 1 {
        println!("[file] sending {name}");
    }
    println!(
        "  [file] merkle root {} | {chunks} chunks | {path} path",
        format_root_short(root)
    );
}

#[cfg(any(test, feature = "webrtc"))]
async fn print_progress_loop(mut rx: mpsc::UnboundedReceiver<SendProgress>, json: bool) {
    let mut printed_any = false;
    while let Some(p) = rx.recv().await {
        if json {
            println!(
                "{{\"event\":\"progress\",\"file_index\":{},\"file_count\":{},\"name\":{},\"bytes_sent\":{},\"total_bytes\":{},\"bytes_per_sec\":{}}}",
                p.file_index, p.file_count, json_string(&p.name), p.bytes_sent, p.total_bytes, p.bytes_per_sec
            );
        } else {
            print_progress_bar(&p);
            printed_any = true;
        }
    }
    if printed_any {
        println!();
    }
}

/// Renders one `SendProgress` update as `  38% ▓▓▓▓▓░░░░ 41 MB/s` (the demo script's own shape),
/// overwriting the current terminal line via `\r`.
#[cfg(any(test, feature = "webrtc"))]
fn print_progress_bar(p: &SendProgress) {
    print!(
        "\r  {}",
        render_progress_bar(p.bytes_sent, p.total_bytes, p.bytes_per_sec)
    );
    let _ = std::io::stdout().flush();
}

/// Pure formatting split out of [`print_progress_bar`] so the exact shape is unit-testable without
/// capturing stdout.
#[cfg(any(test, feature = "webrtc"))]
fn render_progress_bar(bytes_sent: u64, total_bytes: u64, bytes_per_sec: f64) -> String {
    let pct: u64 = if total_bytes == 0 {
        100
    } else {
        ((bytes_sent.saturating_mul(100)) / total_bytes).min(100)
    };
    // A 10-wide bar, filled proportionally (rounded to the nearest tenth). The feature spec's own
    // demo script's `▓▓▓▓▓░░░░` for "38%" is a 9-wide, hand-illustrated sketch, not a literal
    // render of a real percentage under any consistent formula (5/9 ≈ 56%, not 38%) — this matches
    // its overall *shape* (`NN% <bar of ▓/░> <rate>`) as closely as practical rather than chasing an
    // inconsistent exact reproduction.
    let filled = ((pct as f64 / 100.0) * 10.0).round() as usize;
    let bar: String = "▓".repeat(filled) + &"░".repeat(10 - filled);
    format!("{pct}% {bar} {}", format_rate(bytes_per_sec))
}

/// `41 MB/s`-shaped throughput, decimal (1000-based) units to match the demo script's own labeling.
#[cfg(any(test, feature = "webrtc"))]
fn format_rate(bytes_per_sec: f64) -> String {
    const KB: f64 = 1000.0;
    const MB: f64 = KB * 1000.0;
    const GB: f64 = MB * 1000.0;
    if bytes_per_sec >= GB {
        format!("{:.0} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.0} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.0} KB/s", bytes_per_sec / KB)
    } else {
        format!("{bytes_per_sec:.0} B/s")
    }
}

/// Reports the *local* send loop's own completion — this side finished streaming every chunk without
/// a transport error, and can only speak to its own locally-computed root (the one it just chunked
/// and sent). It deliberately does **not** claim the receiver's own merkle check passed: `send_file`
/// has no application-level acknowledgment from the peer (`docs/api/wire-protocol.md`'s `mrd.file/1`
/// carries no such message), so this side has no signal telling it whether the receiver's independent
/// verification (`finalize_transfer`) actually succeeded, hung, or failed — see BLOCKING #1/#2's own
/// fixes for how that can go wrong purely on the receiver's side without this sender ever finding out.
/// Wording an honest, locally-scoped claim ("sent") rather than a receiver-side one ("verified …
/// matches") is a should-fix in its own right (should-fix #5) — inventing a real ack is out of scope
/// here.
#[cfg(any(test, feature = "webrtc"))]
fn print_sent_done_line(root: &Hash, json: bool) {
    if json {
        println!(
            "{{\"event\":\"sent\",\"root\":\"b3:{}\"}}",
            hex::encode(root)
        );
    } else {
        println!(
            "sent \u{2714} {} — awaiting the receiver's own verification (no delivery/verification \
             acknowledgment exists on the wire today)",
            format_root_short(root)
        );
    }
}

#[cfg(any(test, feature = "webrtc"))]
fn print_incoming_line(manifest: &FileManifest, json: bool) {
    if json {
        println!(
            "{{\"event\":\"incoming\",\"name\":{},\"size\":{}}}",
            json_string(&manifest.name),
            manifest.size
        );
    } else {
        println!(
            "[file] receiving {} ({} bytes)",
            manifest.name, manifest.size
        );
    }
}

#[cfg(any(test, feature = "webrtc"))]
fn print_received_line(manifest: &FileManifest, json: bool) {
    if json {
        println!(
            "{{\"event\":\"received\",\"name\":{},\"root\":\"b3:{}\"}}",
            json_string(&manifest.name),
            hex::encode(manifest.root)
        );
    } else {
        println!(
            "done \u{2714} verified {} matches",
            format_root_short(&manifest.root)
        );
    }
}

/// Minimal JSON string escaping — mirrors `chat.rs::json_string`.
#[cfg(any(test, feature = "webrtc"))]
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use meridian_core::identity::{generate_account, AccountId, MemorySecretStore};
    use meridian_core::session::{answer, dial, MemRelay};
    use meridian_core::signaling::generate_bundle;
    use meridian_core::streams::{register_stream_type, StreamRegistry};
    use meridian_core::transport::{LoopbackFabric, LoopbackTransport};

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

    /// Mirrors `apps/streams/tests/sender_engine.rs::establish_ratchet`.
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

    /// Establishes a real two-party `P2pSession<LoopbackTransport>` pair with the given `FileStream`
    /// (`ask_user`) hooks registered on each side — the same real dial/answer substrate
    /// `apps/streams/tests/sender_engine.rs` drives, so this test exercises `send.rs`'s own logic
    /// against a genuine session, not a stub.
    async fn connect(
        alice: &mut Peer,
        bob: &mut Peer,
        alice_file: Arc<FileStream>,
        bob_file: Arc<FileStream>,
    ) -> (P2pSession<LoopbackTransport>, P2pSession<LoopbackTransport>) {
        let fabric = LoopbackFabric::new();
        let ta = Arc::new(LoopbackTransport::new(fabric.clone()));
        let tb = Arc::new(LoopbackTransport::new(fabric.clone()));
        let mut reg_a = StreamRegistry::with_builtins();
        register_stream_type(&mut reg_a, alice_file);
        let mut reg_b = StreamRegistry::with_builtins();
        register_stream_type(&mut reg_b, bob_file);

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
                Arc::new(reg_a)
            ),
            answer(
                tb,
                bstore,
                &bhandle,
                bob_ik,
                alice_ik,
                bchat,
                &mut relay_b,
                Arc::new(reg_b)
            ),
        );
        (
            ra.expect("dial established"),
            rb.expect("answer established"),
        )
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn send_and_receive_round_trip_over_loopback_is_byte_identical() {
        let mut alice = Peer::new("send.alice");
        let mut bob = Peer::new("send.bob");
        establish_ratchet(&mut alice, &mut bob);

        let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let (mut asess, mut bsess) =
            connect(&mut alice, &mut bob, alice_file, bob_file.clone()).await;

        let out_dir = tempfile::tempdir().unwrap();
        let data = sample(3 * CHUNK_SIZE + 1234);
        let files = vec![("movie.bin".to_string(), data.clone())];
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

        let (send_result, recv_result) = tokio::join!(
            run_over_session(
                &mut asess,
                &alice.store,
                alice.account.handle(),
                &mut alice.chat,
                alice_ik,
                bob_ik,
                true,
                &files,
                &bob_file, // unused on the initiator path
                out_dir.path(),
                1,
                false,
            ),
            run_over_session(
                &mut bsess,
                &bob.store,
                bob.account.handle(),
                &mut bob.chat,
                bob_ik,
                alice_ik,
                false,
                &[],
                &bob_file,
                out_dir.path(),
                1,
                false,
            ),
        );

        let sent = send_result.expect("send must succeed");
        assert_eq!(sent.sent, vec!["movie.bin".to_string()]);

        let received = recv_result.expect("receive must succeed");
        assert_eq!(received.received.len(), 1);
        let on_disk = std::fs::read(&received.received[0]).expect("written file readable");
        assert_eq!(
            on_disk, data,
            "received file must be byte-identical to the source"
        );
    }

    #[tokio::test]
    async fn a_declined_file_is_never_written_and_the_sender_sees_the_decline() {
        let mut alice = Peer::new("send.decline.alice");
        let mut bob = Peer::new("send.decline.bob");
        establish_ratchet(&mut alice, &mut bob);

        let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        // The accept/reject prompt (deliverable 3): this stands in for a human answering "n".
        let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| false));
        let (mut asess, mut bsess) = connect(&mut alice, &mut bob, alice_file, bob_file).await;

        let out_dir = tempfile::tempdir().unwrap();
        let data = sample(500);
        let files = vec![("secret.pdf".to_string(), data)];
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

        // Bob's side, bounded: service exactly the two frames this scenario produces (the
        // initiator's opening chat message — first contact, auto-accepted, see `run_responder`'s
        // own identical precedent — and the following `mrd.file/1` OPEN, which `bob_file`'s
        // `ask_user` hook declines) and stop. Deliberately not `run_responder` here: its `expect`
        // exit condition has nothing to count towards on a transfer that will never complete (see
        // `send.rs`'s own module doc, "Responder exit condition"), so it would pump forever waiting
        // for a file that is never coming.
        let bob_task = async {
            loop {
                match bsess
                    .pump(&bob.store, bob.account.handle(), &mut bob.chat)
                    .await
                {
                    Err(SessionError::Chat(ChatError::MessageRequest)) => {
                        bob.chat
                            .accept_request(&alice_ik)
                            .expect("accept the opening chat message");
                    }
                    // The Open frame dispatched: bob's own `on_open` already ran inside this same
                    // `pump()` call, declined, and sent `Reject` back — nothing left to service.
                    Ok(_) => break,
                    Err(e) => panic!("unexpected error servicing bob's side: {e}"),
                }
            }
        };

        let (send_result, ()) = tokio::join!(
            run_initiator(
                &mut asess,
                &alice.store,
                alice.account.handle(),
                &mut alice.chat,
                alice_ik,
                bob_ik,
                &files,
                false,
            ),
            bob_task,
        );

        let err = send_result.expect_err("a declined transfer must surface as an error");
        assert!(err.contains("declined"), "unexpected error: {err}");
        assert!(
            std::fs::read_dir(out_dir.path()).unwrap().next().is_none(),
            "a declined file must never be written to disk"
        );
    }

    /// Builds a `mrd.file/1`-shaped chunk frame (tag byte + `ChunkFrame` CBOR) exactly the way the
    /// real sender engine does, so these regression tests can inject specific (including hostile/
    /// duplicate) frames directly via [`P2pSession::send_stream_frame`] without going through
    /// [`meridian_streams::send_file`]'s own send loop.
    fn tagged_chunk_frame(k_f: &[u8; 32], i: u64, plaintext: &[u8]) -> Vec<u8> {
        let sealed = meridian_streams::seal_chunk(k_f, i, plaintext);
        let frame = ChunkFrame { i, data: sealed }.encode().unwrap();
        meridian_streams::resume::tag_frame(meridian_streams::FRAME_TAG_CHUNK, frame)
    }

    /// BLOCKING #1 regression test: a duplicate/retransmitted chunk frame must never inflate the
    /// responder's completion check (previously `pending_chunks.len()`, a raw arrival-order frame
    /// count) past the file's real `leaf_count` while a genuinely distinct chunk index is still
    /// missing. Sends chunk 0 twice before chunk 1, and withholds chunk 2 until after that — with the
    /// pre-fix raw-count check, `pending_chunks.len()` reaches `leaf_count` (3) the moment chunk 1
    /// arrives (0, 0-dup, 1 = 3 raw frames) despite chunk 2 never having arrived, causing a premature,
    /// failing `finalize_transfer` call that (pre-fix) got marked `finalized` unconditionally and then
    /// hung `run_responder` forever (`received.len()` could never reach `expect_inbound`). This test
    /// would hang (and eventually be killed by the test harness) without the fix; with it,
    /// `run_responder` must complete normally once the real chunk 2 arrives.
    #[tokio::test]
    async fn a_duplicate_chunk_frame_does_not_hang_the_responder_and_the_transfer_still_completes()
    {
        let mut alice = Peer::new("send.dup.alice");
        let mut bob = Peer::new("send.dup.bob");
        establish_ratchet(&mut alice, &mut bob);

        let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let (mut asess, mut bsess) =
            connect(&mut alice, &mut bob, alice_file, bob_file.clone()).await;

        let out_dir = tempfile::tempdir().unwrap();
        let data = sample(2 * CHUNK_SIZE + 1234); // exactly 3 chunks: 0, 1 full-size, 2 short
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

        let alice_task = async {
            asess
                .send_chat(&alice.store, alice.account.handle(), &mut alice.chat, HELLO)
                .await
                .expect("hello");

            let tree = MerkleTree::from_bytes(&data);
            let (params, k_f) = FileStream::build_open_params(
                &mut alice.chat,
                &alice.store,
                alice.account.handle(),
                &alice_ik,
                &bob_ik,
                FileMeta {
                    name: "dup.bin".to_string(),
                    size: data.len() as u64,
                    root: tree.root(),
                },
            )
            .expect("build open params");
            let sid = asess
                .open_stream(
                    &alice.store,
                    alice.account.handle(),
                    &mut alice.chat,
                    meridian_streams::file::NAME,
                    params,
                )
                .await
                .expect("open stream");

            loop {
                match asess
                    .pump(&alice.store, alice.account.handle(), &mut alice.chat)
                    .await
                {
                    Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
                    Ok(_) => {}
                    Err(e) => panic!("unexpected error waiting for accept: {e}"),
                }
            }

            let chunk_plaintext = |i: usize| -> &[u8] {
                let start = i * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(data.len());
                &data[start..end]
            };

            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 0, chunk_plaintext(0)),
                )
                .await
                .unwrap();
            // The duplicate: a retransmission of a chunk already sent, entirely plausible over
            // reliable-unordered SCTP delivery/resume — must not count as a second distinct index.
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 0, chunk_plaintext(0)),
                )
                .await
                .unwrap();
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 1, chunk_plaintext(1)),
                )
                .await
                .unwrap();
            // Give the responder a chance to (incorrectly, pre-fix) attempt and fail a premature
            // finalize before chunk 2 — genuinely still missing at this point — ever arrives.
            tokio::task::yield_now().await;
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 2, chunk_plaintext(2)),
                )
                .await
                .unwrap();
        };

        let (_, recv_result) = tokio::join!(
            alice_task,
            run_responder(
                &mut bsess,
                &bob.store,
                bob.account.handle(),
                &mut bob.chat,
                bob_ik,
                alice_ik,
                &bob_file,
                out_dir.path(),
                1,
                false,
            ),
        );

        let report = recv_result
            .expect("the responder must complete, not hang, despite the duplicate frame");
        assert_eq!(report.received.len(), 1);
        let on_disk = std::fs::read(&report.received[0]).unwrap();
        assert_eq!(
            on_disk, data,
            "the duplicate frame must not have corrupted reassembly"
        );
    }

    /// Verification-review regression test: a spurious, distinct, **out-of-range** chunk frame
    /// (e.g. `i = 999` for a 3-chunk file) arriving *before* the real final chunk must not
    /// prematurely satisfy the completion check (cardinality alone — `{0, 1, 999}.len() == 3 ==
    /// leaf_count` — used to be enough) nor, once the completion check correctly waits for real
    /// membership, cause `finalize_transfer` to fail the whole transfer when it later encounters
    /// that same stray frame mixed in among the real ones. Sends chunk 0, chunk 1, then the
    /// spurious out-of-range frame, then finally the real chunk 2 — the transfer must still
    /// complete successfully with a byte-identical file, not settle as a permanent failure.
    #[tokio::test]
    async fn a_spurious_out_of_range_chunk_frame_does_not_fail_an_otherwise_completable_transfer() {
        let mut alice = Peer::new("send.spurious.alice");
        let mut bob = Peer::new("send.spurious.bob");
        establish_ratchet(&mut alice, &mut bob);

        let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let (mut asess, mut bsess) =
            connect(&mut alice, &mut bob, alice_file, bob_file.clone()).await;

        let out_dir = tempfile::tempdir().unwrap();
        let data = sample(2 * CHUNK_SIZE + 1234); // exactly 3 chunks: 0, 1 full-size, 2 short
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());

        let alice_task = async {
            asess
                .send_chat(&alice.store, alice.account.handle(), &mut alice.chat, HELLO)
                .await
                .expect("hello");

            let tree = MerkleTree::from_bytes(&data);
            let (params, k_f) = FileStream::build_open_params(
                &mut alice.chat,
                &alice.store,
                alice.account.handle(),
                &alice_ik,
                &bob_ik,
                FileMeta {
                    name: "spurious.bin".to_string(),
                    size: data.len() as u64,
                    root: tree.root(),
                },
            )
            .expect("build open params");
            let sid = asess
                .open_stream(
                    &alice.store,
                    alice.account.handle(),
                    &mut alice.chat,
                    meridian_streams::file::NAME,
                    params,
                )
                .await
                .expect("open stream");

            loop {
                match asess
                    .pump(&alice.store, alice.account.handle(), &mut alice.chat)
                    .await
                {
                    Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
                    Ok(_) => {}
                    Err(e) => panic!("unexpected error waiting for accept: {e}"),
                }
            }

            let chunk_plaintext = |i: usize| -> &[u8] {
                let start = i * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(data.len());
                &data[start..end]
            };

            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 0, chunk_plaintext(0)),
                )
                .await
                .unwrap();
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 1, chunk_plaintext(1)),
                )
                .await
                .unwrap();
            // The spurious frame: a distinct, out-of-range index (999 is well past this 3-chunk
            // file's `leaf_count`) — still authenticates under `k_f` (which authenticates only
            // (key, index), never that the index is in range), so a compromised or malicious
            // sender can produce it. Sent *before* the real final chunk, exactly the ordering the
            // reviewing agent's reproduction relied on: with the pre-fix cardinality-only
            // completion check, `{0, 1, 999}.len() == 3 == leaf_count` would fire
            // `finalize_transfer` right here, before chunk 2 ever arrives.
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 999, b"garbage-out-of-range-payload"),
                )
                .await
                .unwrap();
            tokio::task::yield_now().await;
            // The real final chunk, arriving moments later — must not be ignored by an
            // already-`finalized` (and, pre-fix, permanently failed) transfer.
            asess
                .send_stream_frame(
                    &mut alice.chat,
                    sid,
                    &tagged_chunk_frame(&k_f, 2, chunk_plaintext(2)),
                )
                .await
                .unwrap();
        };

        let (_, recv_result) = tokio::join!(
            alice_task,
            run_responder(
                &mut bsess,
                &bob.store,
                bob.account.handle(),
                &mut bob.chat,
                bob_ik,
                alice_ik,
                &bob_file,
                out_dir.path(),
                1,
                false,
            ),
        );

        let report = recv_result.expect(
            "a spurious out-of-range frame must not permanently fail an otherwise-completable \
             transfer",
        );
        assert_eq!(report.received.len(), 1);
        let on_disk = std::fs::read(&report.received[0]).unwrap();
        assert_eq!(
            on_disk, data,
            "the spurious frame must not have corrupted reassembly"
        );
    }

    /// BLOCKING #1's other half: once every distinct chunk index this transfer will ever need has
    /// arrived, a transfer that still cannot verify (here: a manifest whose claimed root can never
    /// match the real data — this module wires no resume/re-request mechanism, so nothing will ever
    /// fix it) must settle as a clean, terminal failure rather than being retried forever or hanging
    /// `run_responder`'s loop (the pre-fix bug: `finalized.insert(sid)` ran even on `Err`, but nothing
    /// ever incremented `received.len()`, so `while received.len() < expect_inbound` never exited).
    #[tokio::test]
    async fn a_transfer_that_can_never_verify_settles_as_a_clean_failure_instead_of_hanging() {
        let mut alice = Peer::new("send.badroot.alice");
        let mut bob = Peer::new("send.badroot.bob");
        establish_ratchet(&mut alice, &mut bob);

        let alice_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let bob_file = Arc::new(FileStream::with_ask_user(0, |_, _| true));
        let (mut asess, mut bsess) =
            connect(&mut alice, &mut bob, alice_file, bob_file.clone()).await;

        let out_dir = tempfile::tempdir().unwrap();
        let data = sample(500); // a single chunk
        let (alice_ik, bob_ik) = (alice.ik(), bob.ik());
        let wrong_root: Hash = [0x7F; 32]; // never matches `data`'s real merkle root

        let alice_task = async {
            asess
                .send_chat(&alice.store, alice.account.handle(), &mut alice.chat, HELLO)
                .await
                .expect("hello");

            let (params, k_f) = FileStream::build_open_params(
                &mut alice.chat,
                &alice.store,
                alice.account.handle(),
                &alice_ik,
                &bob_ik,
                FileMeta {
                    name: "corrupt.bin".to_string(),
                    size: data.len() as u64,
                    root: wrong_root,
                },
            )
            .expect("build open params");
            let sid = asess
                .open_stream(
                    &alice.store,
                    alice.account.handle(),
                    &mut alice.chat,
                    meridian_streams::file::NAME,
                    params,
                )
                .await
                .expect("open stream");

            loop {
                match asess
                    .pump(&alice.store, alice.account.handle(), &mut alice.chat)
                    .await
                {
                    Ok(Some(SessionEvent::StreamOpened(got, _))) if got == sid => break,
                    Ok(_) => {}
                    Err(e) => panic!("unexpected error waiting for accept: {e}"),
                }
            }

            asess
                .send_stream_frame(&mut alice.chat, sid, &tagged_chunk_frame(&k_f, 0, &data))
                .await
                .unwrap();
        };

        let (_, recv_result) = tokio::join!(
            alice_task,
            run_responder(
                &mut bsess,
                &bob.store,
                bob.account.handle(),
                &mut bob.chat,
                bob_ik,
                alice_ik,
                &bob_file,
                out_dir.path(),
                1,
                false,
            ),
        );

        let err = recv_result
            .expect_err("a transfer that can never verify must fail cleanly, never hang forever");
        assert!(
            err.contains("failed verification"),
            "unexpected error: {err}"
        );
        assert!(
            std::fs::read_dir(out_dir.path()).unwrap().next().is_none(),
            "an unverified transfer must never be written to disk"
        );
    }

    #[test]
    fn distinct_chunk_indices_collapses_duplicate_frames_to_one_index() {
        let key = [0x11u8; 32];
        let frame_bytes = tagged_chunk_frame(&key, 4, b"payload");
        // Strip the tag byte back off — `distinct_chunk_indices` operates on `pending_chunks`'
        // already-untagged shape (`FileStream::on_frame`'s own contract).
        let (_, body) = frame_bytes.split_first().unwrap();
        let pending = vec![body.to_vec(), body.to_vec(), body.to_vec()];
        let distinct = distinct_chunk_indices(&pending);
        assert_eq!(
            distinct.len(),
            1,
            "three copies of the same index must collapse to one"
        );
        assert!(distinct.contains(&4));
    }

    /// BLOCKING #2 regression test: an out-of-range chunk index must never reach the unchecked
    /// `frame.i as usize * CHUNK_SIZE` offset multiply that used to panic (debug builds) or
    /// silently wrap into an in-bounds-looking offset (release builds). `open_chunk` only
    /// authenticates `(key, index)`, never that the index is actually in range for this file, so
    /// any peer holding `k_f` can otherwise supply an arbitrary `u64` index that still
    /// authenticates.
    ///
    /// Verification-review update: `finalize_transfer` no longer treats an out-of-range frame as
    /// immediately fatal for the whole transfer (see the fix's own doc comment) — it is now
    /// *skipped*, tolerating it as an irrelevant/stray frame mixed in among the real ones. Here the
    /// only frame supplied is the hostile out-of-range one, so leaf 0 (this file's one real,
    /// required chunk) never actually gets reassembled and the whole-file merkle check correctly
    /// fails instead — proving the safety property this test cares about (never panics, never
    /// writes a bogus/corrupted file) survives the behavior change, even though the specific error
    /// text is no longer "out of range" for this exact single-frame scenario.
    #[test]
    fn finalize_transfer_skips_an_out_of_range_chunk_index_without_panicking() {
        let key = [0x9Cu8; 32];
        let data = sample(10); // a single leaf
        let tree = MerkleTree::from_bytes(&data);
        let manifest = FileManifest {
            name: "tiny.bin".to_string(),
            size: data.len() as u64,
            root: tree.root(),
            key: vec![0xAA; 32],
        };
        // Large enough that `i * CHUNK_SIZE` would overflow `usize` on the multiply the pre-fix code
        // performed unconditionally.
        let hostile_i = u64::MAX / 2;
        let frame_bytes = tagged_chunk_frame(&key, hostile_i, b"whatever");
        let (_, body) = frame_bytes.split_first().unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        // Must return `Err` (leaf 0's real data never arrived, so the merkle check must fail), not
        // panic — the surrounding test harness itself is the panic detector.
        let err = finalize_transfer(&manifest, &key, &[body.to_vec()], out_dir.path()).expect_err(
            "skipping the only (out-of-range) frame must leave leaf 0 unfilled, \
                         failing the merkle check rather than silently succeeding",
        );
        assert!(
            err.contains("merkle root mismatch"),
            "unexpected error: {err}"
        );
        assert!(
            std::fs::read_dir(out_dir.path()).unwrap().next().is_none(),
            "nothing must be written when a required chunk's real data never arrived"
        );
    }

    /// Companion to the skip-behavior test above: an out-of-range frame mixed in *alongside* every
    /// real required chunk must be silently ignored, and the transfer must still complete and
    /// verify correctly — the direct unit-level proof of the fix's core claim (only in-range frames
    /// are load-bearing for success/failure).
    #[test]
    fn finalize_transfer_ignores_an_out_of_range_frame_mixed_in_with_real_chunks() {
        let key = [0x22u8; 32];
        let data = sample(10); // a single leaf
        let tree = MerkleTree::from_bytes(&data);
        let manifest = FileManifest {
            name: "tiny.bin".to_string(),
            size: data.len() as u64,
            root: tree.root(),
            key: vec![0xAA; 32],
        };

        let real = tagged_chunk_frame(&key, 0, &data);
        let (_, real_body) = real.split_first().unwrap();
        let stray = tagged_chunk_frame(&key, 999, b"garbage");
        let (_, stray_body) = stray.split_first().unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let path = finalize_transfer(
            &manifest,
            &key,
            &[real_body.to_vec(), stray_body.to_vec()],
            out_dir.path(),
        )
        .expect("the stray out-of-range frame must be ignored, not fail the transfer");
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    /// Should-fix #3 regression test: a pre-planted dangling symlink at the candidate path must not
    /// be treated as "free" (the old `Path::exists()` check follows symlinks and reports `false` for
    /// a dangling one) — `create_unique_file` must detect it via `create_new`'s own atomic check and
    /// fall through to the next numeric-suffix candidate instead of opening/following the symlink.
    #[test]
    #[cfg(unix)]
    fn create_unique_file_does_not_follow_a_planted_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("collide.bin");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &candidate)
            .expect("plant a dangling symlink");
        assert!(
            !candidate.exists(),
            "sanity: a dangling symlink reports as non-existent via `Path::exists()`"
        );

        let (file, path) =
            create_unique_file(dir.path(), "collide.bin").expect("must fall through, not error");
        drop(file);
        assert_ne!(
            path, candidate,
            "must never have opened/followed the planted symlink"
        );
        assert_eq!(path, dir.path().join("collide.bin.1"));
    }

    #[test]
    fn sanitize_file_name_strips_directory_components_and_traversal() {
        assert_eq!(sanitize_file_name("photo.jpg"), "photo.jpg");
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("/etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name(".."), "received-file");
        assert_eq!(sanitize_file_name(""), "received-file");
    }

    #[test]
    fn leaf_count_for_size_matches_the_merkle_zero_chunk_convention() {
        assert_eq!(leaf_count_for_size(0), 1);
        assert_eq!(leaf_count_for_size(1), 1);
        assert_eq!(leaf_count_for_size(CHUNK_SIZE as u64), 1);
        assert_eq!(leaf_count_for_size(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(
            leaf_count_for_size((3 * CHUNK_SIZE + 1234) as u64),
            4,
            "matches the sender_engine.rs test's own fixture size"
        );
    }

    #[test]
    fn progress_bar_matches_the_demo_scripts_shape() {
        // "38% ▓▓▓▓▓░░░░ 41 MB/s" (docs/architecture/features/09-file-transfer.md's own demo
        // script) is a hand-illustrated sketch, not a literal render of 38% under any consistent
        // bar-width/rounding formula (its own bar is 9 wide with 5 filled ⇒ ~56%, not 38%) — see
        // `render_progress_bar`'s own doc comment. This pins the overall *shape* instead: leading
        // percentage (no unit suffix stealing the `%`), a `▓`/`░` bar, then the rate.
        let line = render_progress_bar(38, 100, 41_000_000.0);
        assert_eq!(line, "38% ▓▓▓▓░░░░░░ 41 MB/s");
    }

    #[test]
    fn progress_bar_caps_at_100_percent_and_never_overfills() {
        let line = render_progress_bar(150, 100, 0.0);
        assert!(line.starts_with("100% "));
        assert_eq!(line.matches('▓').count(), 10);
        assert_eq!(line.matches('░').count(), 0);
    }

    #[test]
    fn format_rate_picks_the_right_unit() {
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(999.0), "999 B/s");
        assert_eq!(format_rate(41_000_000.0), "41 MB/s");
        assert_eq!(format_rate(3_400_000_000.0), "3 GB/s");
    }

    #[test]
    fn format_root_short_matches_the_demo_scripts_shape() {
        // "b3:9af2…" — the root's first two bytes, hex-encoded.
        let root: Hash = {
            let mut h = [0u8; 32];
            h[0] = 0x9a;
            h[1] = 0xf2;
            h
        };
        assert_eq!(format_root_short(&root), "b3:9af2…");
    }
}
