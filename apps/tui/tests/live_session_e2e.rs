//! Task 4.38's own deliverable: a durable, **two-process** regression test that drives the real
//! `meridian_tui::worker::dispatch` (the same function `crate::run_worker`'s live event loop calls
//! for every effect a real `meridian tui` session dispatches) end to end for two independent
//! simulated peers — closing the exact coverage gap this task's own file names: `tests/at_rest_audit.rs`
//! (task 4.27) predates `run_worker` being real and hand-calls the underlying store functions
//! directly, so none of this crate's existing test suite (screen snapshot tests, `run_worker_*.rs`'s
//! own single-account dispatches, `tests/inbound_delivery.rs`'s one-real-account-plus-one-hand-rolled-
//! peer setup) ever exercises **two full accounts, each driven through the real worker, actually
//! talking to each other over a real rendezvous server** — the thing the T17 demo itself needs.
//!
//! ## Why two literal OS processes, not two in-process `App`/worker pairs
//! `meridian_core::account::config_dir` (and therefore every sealed-store path this crate's worker
//! touches — `account.json`/`trust.bin`/`sessions.bin`/`contacts.json`) resolves via
//! `std::env::var("MERIDIAN_HOME")`, a **process-global** value (confirmed directly by
//! `apps/core/src/account.rs`'s own `config_dir` — no thread-local or per-task override exists
//! anywhere in this workspace). A live two-peer exchange genuinely needs both accounts' inbound
//! connections open concurrently (the rendezvous server has no store-and-forward yet — T07 — so a
//! message routed while the recipient isn't already connected is simply dropped, never queued): that
//! means one peer's persistent `run_inbound_loop` task and the other peer's outbound `SendMessage`
//! dispatch are genuinely racing in wall-clock time. With a single process and one shared
//! `$MERIDIAN_HOME` env var, there is no way to guarantee which peer's on-disk paths are "active" at
//! the instant a delivery actually lands — a real risk of one peer's inbound handler silently
//! reading/resealing the *other* peer's `sessions.bin`. Two literal, separately-launched OS processes
//! (each with its own env, set once at `Command::spawn` time) removes the hazard structurally instead
//! of relying on provably-fragile scheduling arguments. This mirrors the task's own literal phrasing
//! ("two temp `$MERIDIAN_HOMEs`... driving `App::update` for both 'peers'") read as "two independent
//! peer processes", not "two in-process actors sharing one env".
//!
//! ## Why `worker::dispatch`/`run_inbound_loop` directly, not the full `App`/`update` screen stack
//! `App::update` is a pure, synchronous state machine with no I/O of its own (tui-client.md §4); it is
//! already exercised thoroughly, screen by screen, by `screens_*.rs` and by each `run_worker_*.rs`
//! file's own single-account dispatches. The coverage gap this task exists to close is specifically
//! **`run_worker`'s real dispatch, integrated across effect groups, between two genuinely separate
//! accounts, over a real network** — calling `meridian_tui::worker::dispatch`/`run_inbound_loop`
//! directly (both `pub`, both exactly what `crate::run_worker`'s own event loop calls) hits that gap
//! precisely without re-deriving `App`'s already-covered screen-navigation logic a second time here.
//!
//! ## Account type: OS-keystore (via the sanctioned in-process mock), not file-backed
//! `worker.rs::open_account_store` (the helper `AddContact`/`AcceptRequest`/`MarkVerified`/
//! `SendMessage`/`PersistHistory` all call) fails closed today for a file-backed account — a genuine,
//! already-flagged residual gap (task 4.37's own Status section; re-confirmed live by task 4.38's own
//! Status section) that this task must surface, never paper over. A file-backed account therefore
//! cannot complete this scenario at all right now. Each child process instead installs
//! `meridian_core::identity::install_mock_keystore()` — the same sanctioned, headless-CI-safe pattern
//! `tests/run_worker_contacts.rs`/`tests/run_worker_trust.rs`/`tests/run_worker_chat.rs`/
//! `tests/inbound_delivery.rs` already use — before dispatching `Effect::GenerateAccount { store:
//! StoreChoice::Os, .. }`, so `open_account_store`'s `StoreKind::Os` branch resolves for real, in a
//! genuinely separate OS process per peer (stronger isolation than those single-process files get,
//! since the mock keystore itself is process-global state).
//!
//! ## "Restart persists" is checked same-process, not via a third process — and that's the honest limit
//! `install_mock_keystore()`'s own doc comment is explicit: "it does not persist" — it is an
//! in-memory-only mock, by design (`apps/store/src/os.rs`). A literal third process reusing the same
//! `$MERIDIAN_HOME` could re-read `account.json`/`trust.bin`/etc. off disk, but its own fresh
//! `install_mock_keystore()` call would start with an *empty* keystore, unable to unwrap the secret
//! the first process's mock keystore held only in that now-exited process's memory — a structural
//! limitation of testing the OS-keystore path headlessly at all (the same one
//! `tests/load_session.rs`'s own module doc names: "only the thin `keyring`-backed
//! `OsSecretStore::new`/`init_os_keystore` glue itself is untestable headlessly"). So this test proves
//! restart-persistence the same way `tests/load_session.rs`/`tests/preflight.rs` already do: a fresh
//! `Effect::LoadSession` dispatch, in the same process, once the chat exchange is done, reading back
//! whatever the earlier dispatches actually sealed to disk (no in-memory state reused) — not a literal
//! second process launch. Documented here rather than overclaimed.
//!
//! ## `harness = false`
//! This file is registered in `apps/tui/Cargo.toml` with `harness = false` so it owns a plain `fn
//! main()` instead of libtest's auto-generated one — the standard, idiomatic way for a Rust test
//! binary to re-invoke `std::env::current_exe()` as a real child process (gated here by the
//! `LIVE_E2E_ROLE` env var) without fighting the default test harness's own CLI. Running this binary
//! normally (`cargo test -p meridian-tui --test live_session_e2e`, or under `cargo nextest`) executes
//! the **orchestrator** branch below, whose own process exit code (0 = pass) is what either test
//! runner reports — the two child invocations it spawns are ordinary subprocesses from their
//! perspective, never separately discovered or double-counted.
//!
//! ## Formerly known-failing; the gate is now removed (task 4.39)
//! This test used to reproducibly fail (task 4.38's second finding: no code path in `meridian-tui`
//! republished a prekey bundle with vault-persisted secrets, so `ChatError::UnknownPrekey` blocked all
//! first-contact decryption — see `docs/tasks/phase-4/4.38-t17-acceptance-demo-closure.md` and
//! `tui-client.md` §11). Task 4.39 closed that defect (`worker::republish_bundle`, called once per
//! session right before `run_inbound_loop` is spawned — see that function's own module doc in
//! `apps/tui/src/worker.rs`). Since this test drives `worker::dispatch`/`run_inbound_loop` directly
//! rather than through `crate::run_worker`'s own event loop (see this module doc's own "why
//! `worker::dispatch`/`run_inbound_loop` directly" section above), each peer below calls
//! `worker::republish_bundle` itself, once, immediately before starting its own persistent inbound
//! loop — mirroring exactly what `run_worker`'s wiring now does, not a different sequence invented
//! here. The opt-in `LIVE_E2E_RUN` gate this file used to need (`harness = false` means `#[ignore]`
//! does not apply — see the removed section this replaced) is gone: this test now runs unconditionally
//! under plain `cargo test -p meridian-tui --test live_session_e2e`.
//!
//! ## Simplifications, stated plainly
//! - Petname is the generic `"peer"`, not the demo script's cosmetic `"bob"` — which of the two roles
//!   below acts as the X3DH *initiator* is decided at runtime (`run_send_message`'s own
//!   lexicographic-pubkey-order rule — whoever's pubkey sorts first CAN, and only they, send first; a
//!   fresh keypair's ordering can't be hardcoded in advance), so this test cannot know ahead of time
//!   which role's name to use.
//! - Single local rendezvous, not the `just two-orgs` cross-org variant — the demo script itself
//!   offers the single-server form as the default; the cross-org path is T06's own territory.
//! - No independent safety-number cross-check — `mark_verified`'s own UI-level "same 60-digit number
//!   on both sides" property is already covered by `tests/screens_verify.rs`; this file's own job is
//!   the network/worker integration, not re-proving that computation.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};

use meridian_core::account::AccountDescriptor;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    install_mock_keystore, parse_id, KeyHandle, OsSecretStore, SecretStore,
};
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::{
    AcceptRequestEffect, AcceptRequestRequest, AddContactEffect, AddContactRequest, AppEvent,
    Effect, GenerateAccountRequest, InboundEvent, LoadSessionEffect, LoadSessionOutcome,
    LoadSessionRequest, MarkVerifiedEffect, MarkVerifiedRequest, PersistHistoryEffect,
    PersistHistoryRequest, PublishBundleRequest, RegisterRequest, SendMessageEffect,
    SendMessageRequest, StoreChoice, WorkerEvent,
};
use meridian_tui::statusbar::ConnectionState;
use meridian_tui::store::history::{self, Direction as HistDirection, HistoryEntry, MessageState};
use meridian_tui::worker::{dispatch, republish_bundle, run_inbound_loop, OnboardingSession};

const ROLE_ENV: &str = "LIVE_E2E_ROLE";
const TAG_ENV: &str = "LIVE_E2E_TAG";
const SERVER_ENV: &str = "LIVE_E2E_SERVER";
const SHARED_ENV: &str = "LIVE_E2E_SHARED";

const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
const FILE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const INBOUND_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    match env::var(ROLE_ENV).ok().as_deref() {
        Some("peer") => {
            let rt = tokio::runtime::Runtime::new().expect("build child tokio runtime");
            match rt.block_on(run_peer()) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("[live_session_e2e peer] FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => match run_orchestrator() {
            Ok(()) => {
                println!("[live_session_e2e] both peers completed the full onboarding -> add \
                           contact -> message request -> accept -> mark verified -> chat -> restart \
                           flow successfully, driven end to end through the real worker::dispatch.");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[live_session_e2e] FAILED: {e}");
                std::process::exit(1);
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Orchestrator (the normal `cargo test`/`cargo nextest` entry point)
// ---------------------------------------------------------------------------

fn run_orchestrator() -> Result<(), String> {
    let server = spawn_server();
    let shared = tempfile::tempdir().map_err(|e| format!("shared tempdir: {e}"))?;
    let home_a = tempfile::tempdir().map_err(|e| format!("home a tempdir: {e}"))?;
    let home_b = tempfile::tempdir().map_err(|e| format!("home b tempdir: {e}"))?;

    let exe = env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let child_a = spawn_peer(&exe, "a", home_a.path(), shared.path(), &server)?;
    let child_b = spawn_peer(&exe, "b", home_b.path(), shared.path(), &server)?;

    let out_a = wait_with_timeout(child_a, CHILD_TIMEOUT, "peer a")?;
    let out_b = wait_with_timeout(child_b, CHILD_TIMEOUT, "peer b")?;

    report(&out_a, "a");
    report(&out_b, "b");

    if !out_a.status.success() || !out_b.status.success() {
        return Err(format!(
            "peer a exit={:?} peer b exit={:?} — see stdout/stderr dumped above",
            out_a.status.code(),
            out_b.status.code()
        ));
    }
    Ok(())
}

fn report(out: &std::process::Output, tag: &str) {
    if !out.status.success() {
        eprintln!(
            "--- peer {tag} stdout ---\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        eprintln!(
            "--- peer {tag} stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn spawn_peer(
    exe: &Path,
    tag: &str,
    home: &Path,
    shared: &Path,
    server: &str,
) -> Result<std::process::Child, String> {
    Command::new(exe)
        .env(ROLE_ENV, "peer")
        .env(TAG_ENV, tag)
        .env(SERVER_ENV, server)
        .env(SHARED_ENV, shared)
        .env("MERIDIAN_HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning peer {tag}: {e}"))
}

/// Blocks on `child`'s exit + captured output on a dedicated OS thread, enforcing `timeout` as a pure
/// safety net (every genuine wait inside a peer's own script already carries its own, tighter bound —
/// see the module doc — so this should only ever fire on a genuine hang/deadlock, never in the
/// ordinary success path).
fn wait_with_timeout(
    child: std::process::Child,
    timeout: Duration,
    label: &str,
) -> Result<std::process::Output, String> {
    let (tx, rx) = std_mpsc::channel();
    std::thread::spawn(move || {
        let out = child.wait_with_output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(format!("waiting on {label}: {e}")),
        Err(_) => Err(format!(
            "{label} did not exit within {timeout:?} — likely hung; every internal wait in the \
             peer script has its own tighter timeout, so this is a real defect, not a slow CI box"
        )),
    }
}

/// Starts the real rendezvous server on a background OS thread with its own runtime, bound to an
/// ephemeral port — mirrors `tests/run_worker_account.rs::spawn_server`/`tests/inbound_delivery.rs::
/// spawn_server` exactly, just with a plain `MemoryStore` (no call-counting needed here).
fn spawn_server() -> String {
    let store = std::sync::Arc::new(MemoryStore::new());
    let (tx, rx) = std_mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build rendezvous runtime");
        rt.block_on(async move {
            let config = Config::default();
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral port");
            let addr = listener.local_addr().expect("local_addr");
            tx.send(addr).expect("send addr");
            let _ = serve(state, listener).await;
        });
    });
    let addr = rx.recv().expect("recv rendezvous addr");
    format!("ws://{addr}")
}

// ---------------------------------------------------------------------------
// Peer (child process) — the actual worker::dispatch-driven script
// ---------------------------------------------------------------------------

async fn run_peer() -> Result<(), String> {
    let tag = env::var(TAG_ENV).map_err(|_| format!("{TAG_ENV} not set"))?;
    let other_tag = if tag == "a" { "b" } else { "a" };
    let server = env::var(SERVER_ENV).map_err(|_| format!("{SERVER_ENV} not set"))?;
    let shared = PathBuf::from(env::var(SHARED_ENV).map_err(|_| format!("{SHARED_ENV} not set"))?);

    // See the module doc's "burn the one-time real autodetect attempt first" note — mirrors
    // `tests/run_worker_contacts.rs`'s own `KEYRING_WARMUP` precedent exactly, just process-scoped
    // here instead of `std::sync::Once`-scoped (this whole process only ever calls it once anyway).
    let _ = keyring::Entry::new("meridian-tui-live-e2e-warmup", "warmup");
    install_mock_keystore();

    let mut onboarding = OnboardingSession::default();

    println!("[peer {tag}] generating account…");
    let generated = match dispatch(
        Effect::GenerateAccount(meridian_tui::app::GenerateAccountEffect {
            request: GenerateAccountRequest {
                store: StoreChoice::Os,
                // Both peers hint at the *same* domain the single local rendezvous server actually
                // serves (`Config::default().server.domain == "localhost"`) — a mismatched hint is
                // indistinguishable from a cross-org federation target to `worker::
                // sanitize_routing_hint`/the server's own routing rule (`apps/rendezvous/src/ws.rs`),
                // and this single-server demo variant deliberately isn't exercising federation (that
                // is T06's `just two-orgs` territory — see the module doc's "Simplifications" list).
                hint: "localhost".to_string(),
            },
            outcome: None,
        }),
        &mut onboarding,
    )
    .await
    {
        WorkerEvent::Completed(Effect::GenerateAccount(e)) => e
            .outcome
            .ok_or("GenerateAccount completed with no outcome")?,
        other => return Err(format!("GenerateAccount failed: {other:?}")),
    };
    println!("[peer {tag}] generated {}", generated.id);

    println!("[peer {tag}] registering…");
    match dispatch(
        Effect::Register(RegisterRequest {
            server: server.clone(),
            invite: None,
            store: StoreChoice::Os,
            label: generated.label.clone(),
            account_pub: generated.account_pub,
        }),
        &mut onboarding,
    )
    .await
    {
        WorkerEvent::Completed(Effect::Register(_)) => {}
        other => return Err(format!("Register failed: {other:?}")),
    }

    println!("[peer {tag}] publishing bundle…");
    match dispatch(
        Effect::PublishBundle(meridian_tui::app::PublishBundleEffect {
            request: PublishBundleRequest {
                server: server.clone(),
                store: StoreChoice::Os,
                label: generated.label.clone(),
                account_pub: generated.account_pub,
                otk_count: 5,
            },
            outcome: None,
        }),
        &mut onboarding,
    )
    .await
    {
        WorkerEvent::Completed(Effect::PublishBundle(_)) => {}
        other => return Err(format!("PublishBundle failed: {other:?}")),
    }

    // Hand off our own id so the other peer can find us, then wait for theirs.
    write_atomic(&shared.join(format!("{tag}_id.txt")), &generated.id)?;
    println!("[peer {tag}] wrote identity, waiting for peer {other_tag}'s…");
    let other_id = wait_for_file(
        &shared.join(format!("{other_tag}_id.txt")),
        FILE_WAIT_TIMEOUT,
    )?;
    let other = parse_id(&other_id).map_err(|e| format!("parsing peer id: {e}"))?;
    let other_pub = *other.pubkey();
    let other_hint = other.hint().to_string();

    let descriptor = AccountDescriptor::load().map_err(|e| format!("loading account.json: {e}"))?;
    let service = descriptor
        .service
        .clone()
        .ok_or("OS-keystore account has no service recorded")?;
    let handle = KeyHandle::from_label(&descriptor.label);

    // Only the lexicographically-smaller pubkey can send first — `worker::run_send_message`'s own
    // X3DH-initiator rule (see the module doc). Both peers compute this identically, independently.
    let initiator = generated.account_pub.as_slice() <= other_pub.as_slice();
    println!(
        "[peer {tag}] role: {}",
        if initiator { "initiator" } else { "responder" }
    );

    if initiator {
        run_initiator(
            &tag,
            other_tag,
            &shared,
            &server,
            &other_id,
            generated.account_pub,
            other_pub,
            &other_hint,
            &service,
            &handle,
        )
        .await?;
    } else {
        run_responder(
            &tag,
            &shared,
            &server,
            generated.account_pub,
            &service,
            &handle,
        )
        .await?;
    }

    // "Restart": a fresh Effect::LoadSession, reading back only what actually made it to disk — see
    // the module doc's "restart persists" section for exactly what this can and can't prove headlessly.
    println!("[peer {tag}] simulating restart via a fresh Effect::LoadSession…");
    let mut restart_session = OnboardingSession::default();
    let reloaded = match dispatch(
        Effect::LoadSession(LoadSessionEffect {
            request: LoadSessionRequest,
            outcome: None,
        }),
        &mut restart_session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::LoadSession(e)) => match e.outcome {
            Some(LoadSessionOutcome::Loaded(boxed)) => (*boxed)
                .into_option()
                .ok_or("LoadSession Loaded outcome carried no session")?,
            other => return Err(format!("unexpected LoadSession outcome: {other:?}")),
        },
        other => return Err(format!("restart LoadSession failed: {other:?}")),
    };

    let other_contact = reloaded
        .trust
        .contact(&other_pub)
        .ok_or("reloaded trust.bin has no record of the peer after restart")?;
    if other_contact.state != meridian_core::trust::TrustState::Verified {
        return Err(format!(
            "reloaded trust state for peer is {:?}, expected Verified",
            other_contact.state
        ));
    }
    if !reloaded.chat.has_session(&other_pub) {
        return Err("reloaded sessions.bin has no live session with the peer after restart".into());
    }
    println!("[peer {tag}] restart check OK: trust=Verified, session present.");

    let reload_store = OsSecretStore::new(&service);
    let history = history::load_or_default(&hex::encode(other_pub), &reload_store, &handle)
        .map_err(|e| format!("reloading history: {e}"))?;
    if history.is_empty() {
        return Err("reloaded history.jsonl is empty after restart".into());
    }
    println!(
        "[peer {tag}] restart check OK: {} history entr(y/ies) persisted.",
        history.len()
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_initiator(
    tag: &str,
    other_tag: &str,
    shared: &Path,
    server: &str,
    other_id: &str,
    own_pub: [u8; 32],
    other_pub: [u8; 32],
    other_hint: &str,
    service: &str,
    handle: &KeyHandle,
) -> Result<(), String> {
    let mut session = OnboardingSession::default();

    println!("[peer {tag}] adding peer as a contact…");
    match dispatch(
        Effect::AddContact(AddContactEffect {
            request: AddContactRequest {
                id: other_id.to_string(),
                pubkey: other_pub,
                hint: other_hint.to_string(),
                petname: Some("peer".to_string()),
            },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::AddContact(_)) => {}
        other => return Err(format!("AddContact failed: {other:?}")),
    }

    println!("[peer {tag}] waiting for peer {other_tag} to be listening…");
    wait_for_file(
        &shared.join(format!("{other_tag}_ready.marker")),
        FILE_WAIT_TIMEOUT,
    )?;

    println!("[peer {tag}] sending first message (intro)…");
    let intro_body = "hello from the initiator — this is the intro";
    let sent = match dispatch(
        Effect::SendMessage(SendMessageEffect {
            request: SendMessageRequest {
                peer_pubkey: other_pub,
                peer_hint: other_hint.to_string(),
                body: intro_body.to_string(),
            },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::SendMessage(e)) => {
            e.outcome.ok_or("SendMessage completed with no outcome")?
        }
        other => return Err(format!("SendMessage (intro) failed: {other:?}")),
    };
    if !sent.delivered {
        return Err(
            "intro message reported delivered=false — the responder should already be \
                     connected at this point (readiness handshake above)"
                .into(),
        );
    }
    println!("[peer {tag}] intro delivered.");

    persist(
        other_pub,
        HistDirection::Out,
        &sent.mid,
        sent.ts,
        intro_body,
        MessageState::Delivered,
    )
    .await?;

    // Task 4.39: republish a fresh, vault-persisted bundle before starting the persistent inbound
    // loop — mirrors exactly what `crate::run_worker`'s own `inbound_handoff` wiring now does
    // (`worker::republish_bundle`, once per session, immediately before `run_inbound_loop` is
    // spawned); this file drives `dispatch`/`run_inbound_loop` directly rather than through
    // `run_worker`'s event loop (see the module doc), so it has to make that same call itself.
    // Connects as *this* account (`own_pub`), never `other_pub` — a bundle is only ever republished
    // for the account that owns it.
    println!("[peer {tag}] republishing prekey bundle (vault-persisted)…");
    let os = OsSecretStore::new(service);
    republish_bundle(&os, handle, own_pub, server)
        .await
        .map_err(|e| format!("republishing bundle: {e}"))?;

    println!("[peer {tag}] waiting for the reply…");
    let mut rx = spawn_inbound(own_pub, server, service, handle);
    let reply = wait_for_inbound(&mut rx, INBOUND_TIMEOUT)
        .await
        .ok_or("timed out waiting for the responder's reply")?;
    let (mid, body) = match reply {
        InboundEvent::Message { entry, .. } => (entry.mid.clone(), entry.body.clone()),
        other => return Err(format!("expected an inbound Message reply, got {other:?}")),
    };
    println!("[peer {tag}] received reply: {body:?}");
    persist_entry(
        other_pub,
        HistDirection::In,
        &mid,
        &body,
        MessageState::Received,
    )
    .await?;

    println!("[peer {tag}] marking peer verified…");
    match dispatch(
        Effect::MarkVerified(MarkVerifiedEffect {
            request: MarkVerifiedRequest { pubkey: other_pub },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::MarkVerified(_)) => {}
        other => return Err(format!("MarkVerified failed: {other:?}")),
    }

    Ok(())
}

async fn run_responder(
    tag: &str,
    shared: &Path,
    server: &str,
    own_pub: [u8; 32],
    service: &str,
    handle: &KeyHandle,
) -> Result<(), String> {
    let mut session = OnboardingSession::default();

    // Task 4.39: same republish-before-listening step as `run_initiator` above — see that call
    // site's own comment. The responder is the role that actually needs this in this scenario (it
    // is the one receiving the initiator's first-contact intro), but every real session republishes
    // unconditionally, regardless of role — see `worker::republish_bundle`'s own doc comment.
    println!("[peer {tag}] republishing prekey bundle (vault-persisted)…");
    let os = OsSecretStore::new(service);
    republish_bundle(&os, handle, own_pub, server)
        .await
        .map_err(|e| format!("republishing bundle: {e}"))?;

    println!("[peer {tag}] starting the persistent inbound loop…");
    let mut rx = spawn_inbound(own_pub, server, service, handle);

    if !wait_for_connected(&mut rx, CONNECT_TIMEOUT).await {
        return Err("inbound loop never reported Connected".into());
    }
    write_atomic(&shared.join(format!("{tag}_ready.marker")), "ready")?;
    println!("[peer {tag}] listening; wrote readiness marker.");

    let request = match wait_for_inbound(&mut rx, INBOUND_TIMEOUT).await {
        Some(InboundEvent::MessageRequest(entry)) => entry,
        Some(other) => return Err(format!("expected a MessageRequest first, got {other:?}")),
        None => return Err("timed out waiting for the initiator's message request".into()),
    };
    let sender = request.sender_ik;
    let (mid_hex, intro_body) = match &request.intro {
        ChatContent::Text { id, body } => (hex::encode(id), body.clone()),
        other => return Err(format!("expected a Text intro, got {other:?}")),
    };
    println!(
        "[peer {tag}] received message request from {}; intro={intro_body:?}",
        hex::encode(sender)
    );

    match dispatch(
        Effect::AcceptRequest(AcceptRequestEffect {
            request: AcceptRequestRequest { sender_ik: sender },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::AcceptRequest(_)) => {}
        other => return Err(format!("AcceptRequest failed: {other:?}")),
    }
    persist_entry(
        sender,
        HistDirection::In,
        &mid_hex,
        &intro_body,
        MessageState::Received,
    )
    .await?;

    println!("[peer {tag}] replying…");
    let reply_body = "hello from the responder — this is the reply";
    let sent = match dispatch(
        Effect::SendMessage(SendMessageEffect {
            request: SendMessageRequest {
                peer_pubkey: sender,
                // No advisory hint recorded for a message-request sender — see
                // `AcceptRequestRequest`'s own doc comment ("no hint is available here"). An empty
                // hint routes locally on this single-server demo (`worker::sanitize_routing_hint`).
                peer_hint: String::new(),
                body: reply_body.to_string(),
            },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::SendMessage(e)) => e
            .outcome
            .ok_or("SendMessage (reply) completed with no outcome")?,
        other => return Err(format!("SendMessage (reply) failed: {other:?}")),
    };
    if !sent.delivered {
        return Err(
            "reply reported delivered=false — the initiator should still be connected \
                     waiting for it"
                .into(),
        );
    }
    persist(
        sender,
        HistDirection::Out,
        &sent.mid,
        sent.ts,
        reply_body,
        MessageState::Delivered,
    )
    .await?;

    println!("[peer {tag}] marking peer verified…");
    match dispatch(
        Effect::MarkVerified(MarkVerifiedEffect {
            request: MarkVerifiedRequest { pubkey: sender },
            outcome: None,
        }),
        &mut session,
    )
    .await
    {
        WorkerEvent::Completed(Effect::MarkVerified(_)) => {}
        other => return Err(format!("MarkVerified failed: {other:?}")),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

async fn persist(
    peer_pubkey: [u8; 32],
    dir: HistDirection,
    mid: &str,
    ts: u64,
    body: &str,
    state: MessageState,
) -> Result<(), String> {
    let entry = HistoryEntry {
        v: history::CURRENT_VERSION,
        mid: mid.to_string(),
        dir,
        ts,
        stream: "mrd.chat/1".to_string(),
        body: body.to_string(),
        state,
    };
    let mut onboarding = OnboardingSession::default();
    match dispatch(
        Effect::PersistHistory(PersistHistoryEffect {
            request: PersistHistoryRequest { peer_pubkey, entry },
            outcome: None,
        }),
        &mut onboarding,
    )
    .await
    {
        WorkerEvent::Completed(Effect::PersistHistory(_)) => Ok(()),
        other => Err(format!("PersistHistory failed: {other:?}")),
    }
}

async fn persist_entry(
    peer_pubkey: [u8; 32],
    dir: HistDirection,
    mid: &str,
    body: &str,
    state: MessageState,
) -> Result<(), String> {
    persist(peer_pubkey, dir, mid, now_unix(), body, state).await
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn spawn_inbound(
    account_pub: [u8; 32],
    server: &str,
    service: &str,
    handle: &KeyHandle,
) -> tokio::sync::mpsc::UnboundedReceiver<AppEvent> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let store: Box<dyn SecretStore> = Box::new(OsSecretStore::new(service));
    tokio::spawn(run_inbound_loop(
        store,
        handle.clone(),
        account_pub,
        server.to_string(),
        vec![50, 100, 250],
        tx,
    ));
    rx
}

/// Mirrors `tests/inbound_delivery.rs::recv_inbound` exactly (same skip-`ConnectionStatus` shape).
async fn wait_for_inbound(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    timeout: Duration,
) -> Option<InboundEvent> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::Inbound(event))) => return Some(*event),
            Ok(Some(AppEvent::ConnectionStatus(_))) => continue,
            Ok(Some(_)) | Ok(None) | Err(_) => return None,
        }
    }
}

/// Mirrors `tests/inbound_delivery.rs::recv_connected` exactly.
async fn wait_for_connected(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::ConnectionStatus(ConnectionState::Connected))) => return true,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Writes `contents` to `path` atomically (temp file + rename) so a concurrent reader in the other
/// process never observes a partial write — the file-based handshake this test's two independent
/// processes use instead of any shared in-memory/env state (see the module doc).
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("renaming into {}: {e}", path.display()))
}

/// Polls for `path` to appear (bounded, 100ms interval) — mirrors this crate's own
/// `worker::fetch_with_retry` polling idiom.
fn wait_for_file(path: &Path, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = fs::read_to_string(path) {
            if !contents.is_empty() {
                return Ok(contents);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out after {timeout:?} waiting for {}",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
