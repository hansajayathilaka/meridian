//! Task 5.10 (review finding F10) — reproduces, and then closes, the drain-window gap:
//! `Effect::PersistHistory` is dispatched to the worker task over an unbounded channel it does not
//! itself await, so if `run`'s old shutdown path (`drop(guard); Ok(())`, no intervening `.await`)
//! fired before the worker task ever got scheduled, the process could exit with the effect still
//! sitting unpolled in the channel buffer — never written, never even attempted. Real users hit
//! this by sending a message and quitting (or the process being killed) within moments of it
//! rendering; found live by 4.51's own test-engineer restart-probing pass (`docs/tasks/phase-4/
//! 4.51-file-backed-inbound-blocking-fix.md`), confirmed still present and untested by 5.10's own
//! review pass.
//!
//! `run` itself can't be driven from a test (its own doc comment: real-terminal-only), so this
//! drives the *real* pieces `run`'s shutdown path is built from — `run_worker` and
//! `drain_pending_persist_history` — through `meridian_tui::test_support` (a `test-support`-feature
//! seam, mirroring `terminal::test_support`'s identical shape), wired exactly like `run` wires them:
//! a real `effect_tx`/`effect_rx` pair, a real spawned `run_worker` task, and a real, sealed,
//! `MERIDIAN_HOME`-rooted `history/<peer>.jsonl` underneath it (mirrors `tests/history_load.rs`'s
//! own `EnvGuard`/OS-keystore fixture idiom).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tokio::sync::mpsc;

use meridian_core::account::AccountDescriptor;
use meridian_core::identity::{generate_account, install_mock_keystore, AccountId, OsSecretStore};

use meridian_tui::app::{
    AppEvent, Effect, PersistHistoryEffect, PersistHistoryRequest, WorkerEvent,
};
use meridian_tui::store::history::{self, Direction, HistoryEntry, MessageState};
use meridian_tui::test_support::{
    drain_pending_persist_history, is_persist_history_ack, run_worker,
    PERSIST_HISTORY_DRAIN_TIMEOUT,
};

const SERVICE: &str = "meridian-tui-persist-history-drain-test";
const NOW: u64 = 1_760_000_100;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors `tests/history_load.rs`'s own
// `EnvGuard` exactly (a separate test binary/process from `worker.rs`'s own unit-test `ENV_LOCK`,
// so the two never race each other).
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());
static KEYRING_WARMUP: std::sync::Once = std::sync::Once::new();

struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    prev_home: Option<String>,
}

impl EnvGuard {
    fn set(dir: &Path) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("MERIDIAN_HOME").ok();
        // SAFETY: serialized by ENV_LOCK, the only place in this test binary touching this var.
        unsafe {
            std::env::set_var("MERIDIAN_HOME", dir);
        }
        KEYRING_WARMUP.call_once(|| {
            let _ = keyring::Entry::new("meridian-tui-persist-history-drain-warmup", "warmup");
        });
        install_mock_keystore();
        Self {
            _lock: lock,
            prev_home,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see `EnvGuard::set`.
        unsafe {
            match &self.prev_home {
                Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                None => std::env::remove_var("MERIDIAN_HOME"),
            }
        }
    }
}

/// An OS-keystore-backed account (task 5.10's fixture never needs a passphrase-unlocked file-backed
/// one: `worker::open_account_store`'s `StoreKind::Os` arm needs no `OnboardingSession` state at
/// all, so `run_worker`'s own freshly-`default()`-constructed session is already enough — no
/// `Effect::LoadSession`/`Effect::Unlock` round trip has to be driven first).
fn setup_os_account() -> AccountId {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    account
}

fn sample_entry() -> HistoryEntry {
    HistoryEntry {
        v: history::CURRENT_VERSION,
        mid: "33333333333333333333333333333333".to_string(),
        dir: Direction::Out,
        ts: NOW,
        stream: "mrd.chat/1".to_string(),
        body: "quitting right after this renders".to_string(),
        state: MessageState::Sent,
    }
}

fn persist_history_effect(peer_pubkey: [u8; 32], entry: HistoryEntry) -> Effect {
    Effect::PersistHistory(PersistHistoryEffect {
        request: PersistHistoryRequest { peer_pubkey, entry },
        outcome: None,
    })
}

/// The regression, and the fix, in one deterministic test — no `sleep`, no wall-clock race, exactly
/// mirroring how `#[tokio::test]`'s default single-threaded runtime and `run`'s own event loop
/// actually schedule tasks.
///
/// **Reproduces the gap (Deliverable 2, "before"):** `run_worker` is spawned — exactly like `run`
/// spawns it — and one `Effect::PersistHistory` is sent to it. `tokio::spawn` only *enqueues* the
/// task; it is not polled until this test's own task yields at an `.await`. Since nothing has
/// awaited yet, `run_worker` provably has not run at all — this is exactly the state `run`'s old
/// shutdown path (`drop(guard); Ok(())`, no intervening `.await`) could return the process from:
/// the sealed transcript is asserted to still show no write at all.
///
/// **Closes the gap (Deliverable 1, "after"):** `drain_pending_persist_history` — the function
/// `run`'s shutdown path now awaits before returning — is then called with `pending: 1`. It waits
/// (bounded, well under `PERSIST_HISTORY_DRAIN_TIMEOUT`) for the worker's matching
/// `WorkerEvent::Completed(Effect::PersistHistory(_))` ack; once it returns, the write is asserted
/// to be durably on disk.
#[tokio::test]
async fn a_persist_history_effect_sent_right_before_shutdown_is_not_lost() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let me = setup_os_account();
    let peer_pubkey = [0x77u8; 32];
    let entry = sample_entry();

    // Wired exactly like `run`: a real effect channel, a real spawned `run_worker`, a real
    // worker-event channel back.
    let (effect_tx, effect_rx) = mpsc::unbounded_channel::<Effect>();
    let (worker_tx, mut worker_rx) = mpsc::unbounded_channel::<AppEvent>();
    tokio::spawn(run_worker(effect_rx, worker_tx));

    effect_tx
        .send(persist_history_effect(peer_pubkey, entry.clone()))
        .expect("send Effect::PersistHistory");

    // --- "Before": nothing has awaited yet, so `run_worker` cannot have run — the file must not
    // reflect the write. This is the reproduction: today's `run` returning here (no drain) is
    // exactly what F10 named.
    let peer_hex = hex::encode(peer_pubkey);
    let os = OsSecretStore::new(SERVICE);
    let before = history::load_or_default(&peer_hex, &os, me.handle())
        .expect("load_or_default must not error on a not-yet-written transcript");
    assert!(
        before.is_empty(),
        "sanity/reproduction: before the worker task has ever been polled, the effect must not \
         have reached disk yet — if this fails, the race this test relies on no longer holds"
    );

    // --- "After": the fix. Drain, bounded, exactly as `run`'s shutdown path now does.
    drain_pending_persist_history(&mut worker_rx, 1, PERSIST_HISTORY_DRAIN_TIMEOUT).await;

    let after = history::load_or_default(&peer_hex, &os, me.handle())
        .expect("load_or_default must not error on the now-written transcript");
    assert_eq!(
        after,
        vec![entry],
        "the in-flight PersistHistory write must have completed and landed on disk once the \
         shutdown drain returns, not been silently lost"
    );
}

/// `is_persist_history_ack` — the predicate the drain's counter (and `run`'s own main-loop
/// bookkeeping) relies on — must recognize both a successful and a failed `PersistHistory`
/// completion as "no longer outstanding" (a failed write is still a worker that is done attempting
/// it — see that function's own doc comment), and must not mistake any other `AppEvent`/`Effect`
/// for one.
#[tokio::test]
async fn is_persist_history_ack_matches_completed_and_failed_persist_history_only() {
    let completed = AppEvent::Worker(Box::new(WorkerEvent::Completed(Effect::PersistHistory(
        PersistHistoryEffect {
            request: PersistHistoryRequest {
                peer_pubkey: [0u8; 32],
                entry: sample_entry(),
            },
            outcome: Some(()),
        },
    ))));
    assert!(is_persist_history_ack(&completed));

    let failed = AppEvent::Worker(Box::new(WorkerEvent::Failed(
        Effect::PersistHistory(PersistHistoryEffect {
            request: PersistHistoryRequest {
                peer_pubkey: [0u8; 32],
                entry: sample_entry(),
            },
            outcome: None,
        }),
        "disk full".to_string(),
    )));
    assert!(is_persist_history_ack(&failed));

    assert!(!is_persist_history_ack(&AppEvent::Tick));
}

/// `drain_pending_persist_history` must be **bounded**, not indefinite: if the worker task is stuck
/// behind some other, genuinely-hanging effect (the function's own doc comment names the concrete
/// example — an unbounded `SignalingClient::connect` inside prekey-bundle republish), shutdown must
/// still terminate rather than hang forever. Simulated here by a `worker_rx` that never receives a
/// matching ack at all: the drain is given a short `timeout` (not the real 2s constant, so this test
/// stays fast) and must return once that elapses, not block past it.
#[tokio::test]
async fn drain_pending_persist_history_gives_up_after_timeout_when_worker_never_acks() {
    let (_worker_tx, mut worker_rx) = mpsc::unbounded_channel::<AppEvent>();

    let started = tokio::time::Instant::now();
    let short_timeout = std::time::Duration::from_millis(50);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        drain_pending_persist_history(&mut worker_rx, 1, short_timeout),
    )
    .await
    .expect(
        "drain_pending_persist_history must give up after its own timeout, not hang forever \
         when the worker never acks",
    );
    assert!(
        started.elapsed() >= short_timeout,
        "the drain must not return before its own timeout elapses"
    );
}

/// The drain must wait for **every** outstanding `PersistHistory` ack, not just the first — a real
/// `run` shutdown can have several sends still in flight (e.g. several messages typed in quick
/// succession right before quitting), each incrementing the same `pending_persist_history` counter.
#[tokio::test]
async fn drain_pending_persist_history_waits_for_all_outstanding_acks() {
    let (worker_tx, mut worker_rx) = mpsc::unbounded_channel::<AppEvent>();

    let ack = || {
        AppEvent::Worker(Box::new(WorkerEvent::Completed(Effect::PersistHistory(
            PersistHistoryEffect {
                request: PersistHistoryRequest {
                    peer_pubkey: [0u8; 32],
                    entry: sample_entry(),
                },
                outcome: Some(()),
            },
        ))))
    };

    // Only 2 of 3 outstanding acks arrive up front; the drain must not return early on those alone.
    worker_tx.send(ack()).expect("send ack 1");
    worker_tx.send(ack()).expect("send ack 2");

    let drain = tokio::spawn(async move {
        drain_pending_persist_history(&mut worker_rx, 3, PERSIST_HISTORY_DRAIN_TIMEOUT).await;
    });

    // Give the two already-queued acks a chance to be consumed without the third being available
    // yet, then confirm the drain hasn't finished — it must still be waiting on the third.
    tokio::task::yield_now().await;
    assert!(
        !drain.is_finished(),
        "the drain must still be waiting on the third outstanding ack"
    );

    worker_tx.send(ack()).expect("send ack 3");
    tokio::time::timeout(std::time::Duration::from_secs(5), drain)
        .await
        .expect("drain must complete promptly once the final ack arrives")
        .expect("drain task must not panic");
}
