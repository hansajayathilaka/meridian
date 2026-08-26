//! `meridian_tui::worker::check_spk_rotation` — task 6.2's own test target
//! (`cargo nextest run -p meridian-tui --test spk_rotation`).
//!
//! Task 6.1 gave `PrekeyVault` a pure `rotation_due(now_unix)` predicate; task 6.2 acts on it inside
//! `worker::run_inbound_loop`'s new periodic `tokio::select!` arm (see that function's own doc
//! comment) via [`check_spk_rotation`], which this file covers directly — not the `tokio::time`
//! wiring around it (real time, `tokio::time::interval_at`), but the function the wiring calls,
//! which takes `now_unix` as an explicit argument and so is driven here with a **fake clock**
//! (arbitrary `u64` timestamps, no real waiting) exactly as this task's own file requires:
//!
//! 1. [`never_republishes_while_the_generation_is_under_the_interval`] — the "session under the
//!    interval never triggers an extra publish" half.
//! 2. [`republishes_automatically_once_the_interval_elapses_then_not_again_immediately_after_and_
//!    again_after_a_second_interval`] — a simulated long session (checks spread across two full
//!    `SPK_ROTATION_INTERVAL_SECS` periods, driven purely by fake `now_unix` values) that republishes
//!    with no user action *and* proves the debounce: a republish resets the generation's age clock,
//!    so the very next check must read `NotDue` again rather than firing on every subsequent tick
//!    while conceptually "still due" — the over-triggering defect class this task's own file names.
//! 3. [`a_failed_republish_leaves_the_stale_generation_in_service_fail_open`] — the fail-open design
//!    decision this task's Outcome section records: a due-but-unreachable republish must not corrupt
//!    or clear the existing (stale) vault entry — it stays exactly as it was, still usable, and the
//!    outcome is a plain `RotationFailed`, never a panic.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::account;
use meridian_core::chat::{ChatState as CoreChatState, SPK_ROTATION_INTERVAL_SECS};
use meridian_core::identity::{generate_account, KeyHandle, MemorySecretStore, SecretStore};
use meridian_core::signaling::SignalingClient;
use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::AppEvent;
use meridian_tui::statusbar::ConnectionState;
use meridian_tui::worker::{check_spk_rotation, run_inbound_loop, SpkRotationOutcome};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` guard — mirrors `tests/republish_bundle.rs`'s own `EnvGuard`, minus the
// mock-keystore install (this file only ever uses `MemorySecretStore`, which never touches the OS
// keychain).
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

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

// ---------------------------------------------------------------------------
// In-process rendezvous server — mirrors `tests/republish_bundle.rs::spawn_server` exactly.
// ---------------------------------------------------------------------------

fn spawn_server() -> String {
    let store = std::sync::Arc::new(MemoryStore::new());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Config::default();
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    let addr = rx.recv().unwrap();
    format!("ws://{addr}")
}

/// A fresh account, registered against `server` by the real challenge–response `connect` handshake
/// (`SignalingClient::connect` registers on first contact — mirrors `tests/inbound_delivery.rs::
/// setup_us_account`/`publish_own_bundle`'s identical shape, never a hand-rolled registration).
/// `MemorySecretStore` throughout: this file never touches the OS keychain or a passphrase keyfile —
/// `check_spk_rotation`'s own store handling is generic over `SecretStore` and task 6.1/6.2 add no
/// store-specific behavior, so a bare in-memory store is the simplest faithful fixture.
async fn onboard(server: &str) -> (MemorySecretStore, KeyHandle, [u8; 32]) {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, "self.example").expect("generate_account");
    let handle = account.handle().clone();
    let account_pub = *account.public_key().as_bytes();
    let client = SignalingClient::connect(server, &store, &handle, account_pub, None, 1)
        .await
        .expect("connect registers the account");
    let _ = client.close().await;
    (store, handle, account_pub)
}

/// Writes a real, sealed `sessions.bin` whose vault's `spk_published_at` is `published_at` — the
/// fake-clock equivalent of "this account last republished at this wall-clock second", so
/// `check_spk_rotation`'s very first call in a test can be driven from a known baseline instead of
/// always starting from the unknown-age (`None`) case task 6.1 already covers on its own.
fn seed_vault_published_at(store: &dyn SecretStore, handle: &KeyHandle, published_at: u64) {
    let mut chat = CoreChatState::default();
    chat.vault
        .set_bundle([1u8; 32], [2u8; 32], Vec::new(), published_at);
    let sealed = chat.seal_at_rest(store, handle).expect("seal sessions.bin");
    let path = account::sessions_path().expect("sessions_path");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create sessions.bin parent dir");
    }
    std::fs::write(&path, sealed).expect("write sessions.bin");
}

/// Reads `sessions.bin` back and asserts its vault's `spk_published_at` is exactly `expected` — the
/// falsifiable "did this check actually touch the vault or not" assertion every test below relies
/// on. There is no direct accessor for the raw timestamp (deliberately — `PrekeyVault` only exposes
/// the derived `generation_age_secs`/`rotation_due`, task 6.1's own public surface), so this asserts
/// `generation_age_secs(expected) == Some(0)`: true if and only if the vault's own publish timestamp
/// is exactly `expected` (any other stamped value would read a nonzero age at that same `now_unix`).
fn assert_vault_published_at_is(
    store: &dyn SecretStore,
    handle: &KeyHandle,
    expected: u64,
    context: &str,
) {
    let path = account::sessions_path().expect("sessions_path");
    let sealed = std::fs::read(&path).expect("sessions.bin must exist");
    let chat = CoreChatState::open_at_rest(store, handle, &sealed).expect("open sessions.bin");
    // (test-engineer fix) `generation_age_secs(now) = now.saturating_sub(published_at)`, so
    // checking `generation_age_secs(expected) == Some(0)` only ever proves `published_at >=
    // expected` — it silently *saturates* to `Some(0)` (not `None`, not a mismatch) whenever the
    // vault's real `published_at` has moved *past* `expected`, which is exactly what an erroneous
    // extra/early republish would do. That made every caller of this helper vacuous in the one
    // direction that matters (detecting an unwanted republish), verified directly: with
    // `run_inbound_loop`'s `interval_at` swapped back for a plain `interval` (reintroducing the
    // immediate-first-tick bug this task's Outcome section documents fixing), a real republish
    // fired and `check_spk_rotation` returned `Rotated`, yet this assertion — before this fix —
    // still reported success. Anchored instead against `check_now`, a sentinel timestamp far
    // beyond any value this test suite (fake-clock or real-clock) could ever stamp, so
    // `generation_age_secs(check_now) = check_now - published_at` never saturates and the
    // resulting age pins `published_at` down to an exact value, not just a lower bound.
    let check_now: u64 = u64::MAX / 2;
    assert_eq!(
        chat.vault.generation_age_secs(check_now),
        Some(check_now - expected),
        "{context}: expected spk_published_at == {expected}"
    );
}

// ---------------------------------------------------------------------------
// (1) never republishes while under the interval
// ---------------------------------------------------------------------------

#[tokio::test]
async fn never_republishes_while_the_generation_is_under_the_interval() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (store, handle, account_pub) = onboard(&server).await;

    let published_at: u64 = 1_000_000;
    seed_vault_published_at(&store, &handle, published_at);

    // A handful of simulated checks spread across the whole interval, including right up to (but
    // not at) the threshold — every one must read `NotDue`, and the vault's own publish timestamp
    // must never move (the falsifiable half: not just "no error", but "genuinely never republished").
    for offset in [
        0,
        1,
        SPK_ROTATION_INTERVAL_SECS / 2,
        SPK_ROTATION_INTERVAL_SECS - 1,
    ] {
        let now = published_at + offset;
        let outcome = check_spk_rotation(&store, &handle, account_pub, &server, now).await;
        assert_eq!(
            outcome,
            SpkRotationOutcome::NotDue,
            "offset={offset} must not be due yet"
        );
    }

    assert_vault_published_at_is(
        &store,
        &handle,
        published_at,
        "no check under the interval may have touched spk_published_at",
    );
}

// ---------------------------------------------------------------------------
// (2) republishes automatically once due, and the debounce: not again immediately after, but again
//     after a second full interval — a simulated long session, driven entirely by a fake clock.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn republishes_automatically_once_the_interval_elapses_then_not_again_immediately_after_and_again_after_a_second_interval(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (store, handle, account_pub) = onboard(&server).await;

    let published_at: u64 = 2_000_000;
    seed_vault_published_at(&store, &handle, published_at);

    // Just before the first threshold: not due yet.
    let just_before = published_at + SPK_ROTATION_INTERVAL_SECS - 1;
    assert_eq!(
        check_spk_rotation(&store, &handle, account_pub, &server, just_before).await,
        SpkRotationOutcome::NotDue
    );
    assert_vault_published_at_is(
        &store,
        &handle,
        published_at,
        "the not-due check just before the threshold must not have republished",
    );

    // At the threshold: due, and the republish succeeds with no user action — task 6.2's headline
    // property.
    let first_due = published_at + SPK_ROTATION_INTERVAL_SECS;
    assert_eq!(
        check_spk_rotation(&store, &handle, account_pub, &server, first_due).await,
        SpkRotationOutcome::Rotated
    );
    assert_vault_published_at_is(
        &store,
        &handle,
        first_due,
        "a successful rotation must stamp the new spk_published_at at the check's own now_unix",
    );

    // The debounce / no-over-triggering property: immediately after rotating, the generation's age
    // clock has restarted at zero, so the very next check — even though a naive "was due a moment
    // ago" implementation might fire again — must read NotDue, and must not touch the vault again.
    assert_eq!(
        check_spk_rotation(&store, &handle, account_pub, &server, first_due + 1).await,
        SpkRotationOutcome::NotDue,
        "a republish must not be immediately followed by another one at the very next check"
    );
    assert_vault_published_at_is(
        &store,
        &handle,
        first_due,
        "the immediately-following not-due check must not have moved spk_published_at again",
    );

    // Still not due partway through the second interval.
    let mid_second_interval = first_due + SPK_ROTATION_INTERVAL_SECS - 1;
    assert_eq!(
        check_spk_rotation(&store, &handle, account_pub, &server, mid_second_interval).await,
        SpkRotationOutcome::NotDue
    );

    // A full second interval later: due again, and rotates again — proving this is a real recurring
    // check across a simulated multi-week session, not a one-shot fuse.
    let second_due = first_due + SPK_ROTATION_INTERVAL_SECS;
    assert_eq!(
        check_spk_rotation(&store, &handle, account_pub, &server, second_due).await,
        SpkRotationOutcome::Rotated
    );
    assert_vault_published_at_is(
        &store,
        &handle,
        second_due,
        "the second rotation must stamp the second check's own now_unix",
    );
}

// ---------------------------------------------------------------------------
// (3) fail-open: a failed republish leaves the stale generation in service, never panics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_republish_leaves_the_stale_generation_in_service_fail_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    // `server` here is deliberately never spawned — `onboard` needs a real one to register against,
    // then `check_spk_rotation` is handed a deliberately unreachable address instead (mirrors
    // `tests/republish_bundle.rs::republish_bundle_fails_cleanly_without_panicking_on_an_
    // unreachable_server`'s own `"ws://127.0.0.1:1"` trick) rather than tearing a real server down
    // mid-test.
    let real_server = spawn_server();
    let (store, handle, account_pub) = onboard(&real_server).await;

    let published_at: u64 = 3_000_000;
    seed_vault_published_at(&store, &handle, published_at);
    let due_now = published_at + SPK_ROTATION_INTERVAL_SECS;

    let outcome =
        check_spk_rotation(&store, &handle, account_pub, "ws://127.0.0.1:1", due_now).await;
    match outcome {
        SpkRotationOutcome::RotationFailed(message) => {
            assert!(
                message.contains("connecting to"),
                "expected a connect-stage error message, got {message:?}"
            );
        }
        other => panic!("expected RotationFailed against an unreachable server, got {other:?}"),
    }

    // Fail-open, the falsifiable half: the stale generation is untouched, not cleared or corrupted —
    // still exactly the one seeded above, still usable.
    assert_vault_published_at_is(
        &store,
        &handle,
        published_at,
        "a failed republish must leave the existing (stale) generation exactly as it was",
    );

    // And the predicate still reports "due" afterward — the next check (whenever connectivity
    // allows) will try again, rather than this failure permanently suppressing future attempts.
    let path = account::sessions_path().expect("sessions_path");
    let sealed = std::fs::read(&path).expect("sessions.bin must exist");
    let chat = CoreChatState::open_at_rest(&store, &handle, &sealed).expect("open sessions.bin");
    assert!(
        chat.vault.rotation_due(due_now),
        "a failed rotation attempt must not mark the generation as no-longer-due"
    );
}

// ---------------------------------------------------------------------------
// (4) test-engineer-added regression: `run_inbound_loop`'s own rotation timer must not fire on its
//     very first tick, even when the seeded generation is already overdue.
// ---------------------------------------------------------------------------
//
// Tests (1)-(3) above all drive `check_spk_rotation` directly — deliberately, per this file's own
// module doc, since that is the fake-clock-testable unit. But that also means none of them exercise
// `run_inbound_loop`'s actual `tokio::select!`/timer wiring around it at all. This task's own Outcome
// section (`docs/tasks/phase-6/6.2-spk-rotation-enforcement.md`) claims a real defect was caught and
// fixed here: using `tokio::time::interval_at` with a first deadline one full
// `SPK_ROTATION_CHECK_INTERVAL_SECS` (3600s) out, instead of plain `tokio::time::interval` (whose
// first `tick()` resolves immediately on creation), specifically to avoid a spurious republish at
// every single session start. Without a test driving the real loop, a future edit that swapped
// `interval_at` back for `interval` (e.g. during an unrelated refactor) would silently reintroduce
// that bug and nothing in this crate's test suite would fail — tests (1)-(3) never reach this code
// path, and `apps/tui/tests/inbound_delivery.rs`'s existing fixtures that happen to seed an
// already-old `spk_published_at` (e.g. `publish_own_bundle`'s fixed `1_760_000_000`) don't assert
// anything about rotation behavior at all, so an extra republish racing in the background would not
// fail them either.
//
// This test seeds a generation whose age is already **far** past `SPK_ROTATION_INTERVAL_SECS` as of
// the real wall clock (so if the timer fired at t=0 it would find `rotation_due` true and republish
// almost immediately), spawns the real `run_inbound_loop`, waits for it to actually connect, gives it
// a further generous real-time window to complete a spurious republish round trip if one were
// in-flight, and then asserts the vault's `spk_published_at` is still untouched — nowhere near
// `SPK_ROTATION_CHECK_INTERVAL_SECS` (3600s), so the only way an early republish could land inside
// this window is the immediate-first-tick bug this test targets. Necessarily real time, not a fake
// clock: `run_inbound_loop`'s own tick arm calls production `now_unix()` internally, which this test
// has no way to inject.
#[tokio::test]
async fn rotation_timer_does_not_fire_on_the_very_first_tick_even_when_already_overdue() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let (store, handle, account_pub) = onboard(&server).await;

    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    // Four full intervals overdue — comfortably past `rotation_due`'s own threshold, so there is no
    // ambiguity about whether an immediate-first-tick check would find this generation due.
    let published_at = real_now.saturating_sub(4 * SPK_ROTATION_INTERVAL_SECS);
    seed_vault_published_at(&store, &handle, published_at);

    let store: std::sync::Arc<dyn SecretStore> = std::sync::Arc::new(store);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();
    tokio::spawn(run_inbound_loop(
        store.clone(),
        handle.clone(),
        account_pub,
        server.clone(),
        vec![50, 100],
        tx,
    ));

    // Wait for the loop to actually connect (bounded — never hangs the test on a wiring failure
    // unrelated to this test's own concern).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(AppEvent::ConnectionStatus(ConnectionState::Connected))) => {
                connected = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
    assert!(connected, "run_inbound_loop must connect within 10s");

    // A generous real-time window, well past what a real connect + 101-signature republish round
    // trip against a local in-process server would take if one were incorrectly in flight, but
    // orders of magnitude short of `SPK_ROTATION_CHECK_INTERVAL_SECS` (3600s) — so nothing except an
    // immediate-first-tick bug could explain a republish landing here.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert_vault_published_at_is(
        store.as_ref(),
        &handle,
        published_at,
        "run_inbound_loop's rotation timer must not republish on its very first tick, even though \
         the seeded generation is already far overdue — only the debounced hourly check (task 6.2) \
         may republish, never an immediate one at loop start",
    );
}
