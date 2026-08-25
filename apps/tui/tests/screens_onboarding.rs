//! `meridian_tui::screens::onboarding` — task 4.16's own test target
//! (`cargo nextest run -p meridian-tui --test screens_onboarding`).
//!
//! State-machine coverage (every sub-step's key/worker-event transitions, including the Esc
//! back-navigation rules and the passphrase-never-rendered invariant) plus a screen-snapshot test
//! per sub-step at 80x24 and a narrow 40x24 — 40 chosen as "clearly below the 80-column floor
//! `apps/cli/src/tui.rs::check_environment`'s `MIN_COLS` already enforces before the TUI ever
//! starts" (exactly half of it), while keeping the row count at that same floor's `MIN_ROWS` (24)
//! so only column-width wrapping behavior is exercised in isolation. In production this width can
//! never actually reach `render` (the environment gate refuses anything under 80x24 first), but
//! rendering defensively at a narrower width is still worth proving now, in case that floor ever
//! moves or this screen is ever embedded in a smaller pane.
//!
//! Every test up to the "App-level boot test" section below drives transitions by directly feeding
//! `handle_key`/`handle_worker` the same way `apps/tui/src/app.rs`'s own
//! `tick_resize_and_paste_events_are_no_ops_for_now`-style tests do, simulating what a worker's
//! `WorkerEvent::Completed`/`Failed` would report — a real worker now exists (task 4.30/4.37), and
//! task 5.8's own boot test at the bottom of this file drives the *whole* stepped wizard through it
//! for real: real `crossterm` key events into a real `App`, each sub-step's `Effect` executed by the
//! real `meridian_tui::worker::dispatch` (including a real in-process `meridian-rendezvous` server
//! for the `Register`/`PublishBundle` steps, mirroring `apps/tui/tests/run_worker_account.rs`'s own
//! `spawn_server`), landing on a real `Screen::Main` — mirroring
//! `apps/tui/tests/accept_to_chat.rs`'s own harness discipline. Every state-machine test above only
//! ever proves one sub-step's *own* transition in isolation; nothing before task 5.8 drove the full
//! `ChooseStore -> OrgHint -> Generate -> ShowIdentity -> Register -> PublishBundle -> Success ->
//! Main` chain end to end.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::identity;
use meridian_core::signaling::DEFAULT_OTK_COUNT;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

use meridian_tui::app::{
    App, AppEvent, Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount,
    PublishBundleEffect, PublishBundleRequest, PublishedBundle, RegisterRequest, Screen,
    StoreChoice, WorkerEvent,
};
use meridian_tui::screens::onboarding::{
    handle_key, handle_worker, render, ChooseStore, Failed, Generating, OnboardingState, OrgHint,
    PublishingBundle, Registering, ShowIdentity, ShowIdentityFocus, StoreKindChoice, Success,
};
use meridian_tui::worker::{dispatch, OnboardingSession};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn type_str(mut state: OnboardingState, s: &str) -> OnboardingState {
    for c in s.chars() {
        let _ = handle_key(&mut state, char_key(c));
    }
    state
}

fn account() -> GeneratedAccount {
    GeneratedAccount {
        id: "mrd1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@chat.example".into(),
        label: "deadbeef".into(),
        account_pub: [7u8; 32],
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[test]
fn choose_store_defaults_to_os_and_enter_moves_to_org_hint() {
    let mut state = OnboardingState::new();
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(!finished);
    match state {
        OnboardingState::OrgHint(oh) => assert_eq!(oh.store, StoreChoice::Os),
        other => panic!("expected OrgHint, got {other:?}"),
    }
}

#[test]
fn choose_store_esc_at_first_step_is_a_no_op() {
    let mut state = OnboardingState::new();
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(!finished);
    assert!(matches!(state, OnboardingState::ChooseStore(_)));
}

#[test]
fn choose_store_file_requires_a_passphrase_before_continuing() {
    let mut state = OnboardingState::new();
    handle_key(&mut state, key(KeyCode::Down)); // select File
    handle_key(&mut state, key(KeyCode::Enter)); // enter passphrase phase
                                                 // Enter with an empty passphrase must not advance.
    let (_, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(!finished);
    assert!(matches!(state, OnboardingState::ChooseStore(_)));

    state = type_str(state, "hunter2");
    let (effects, _) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    match state {
        OnboardingState::OrgHint(oh) => assert_eq!(
            oh.store,
            StoreChoice::File {
                passphrase: "hunter2".into()
            }
        ),
        other => panic!("expected OrgHint, got {other:?}"),
    }
}

#[test]
fn choose_store_passphrase_esc_backs_out_to_kind_selection() {
    let mut state = OnboardingState::new();
    handle_key(&mut state, key(KeyCode::Down));
    handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "ab");
    handle_key(&mut state, key(KeyCode::Esc));
    match &state {
        OnboardingState::ChooseStore(cs) => {
            assert!(!cs.entering_passphrase);
            assert_eq!(cs.selected, StoreKindChoice::File);
        }
        other => panic!("expected ChooseStore, got {other:?}"),
    }
}

#[test]
fn org_hint_rejects_an_invalid_hint_without_advancing() {
    let mut state = OnboardingState::ChooseStore(ChooseStore::default());
    handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "Not Valid!");
    let (effects, _) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    match &state {
        OnboardingState::OrgHint(oh) => assert!(oh.error.is_some()),
        other => panic!("expected OrgHint, got {other:?}"),
    }
}

#[test]
fn org_hint_rejects_an_empty_hint_without_advancing() {
    let mut state = OnboardingState::ChooseStore(ChooseStore::default());
    handle_key(&mut state, key(KeyCode::Enter));
    let (effects, _) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    match &state {
        OnboardingState::OrgHint(oh) => assert!(oh.error.is_some()),
        other => panic!("expected OrgHint, got {other:?}"),
    }
}

#[test]
fn org_hint_esc_goes_back_to_choose_store() {
    let mut state = OnboardingState::new();
    handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "chat.example");
    handle_key(&mut state, key(KeyCode::Esc));
    assert!(matches!(state, OnboardingState::ChooseStore(_)));
}

#[test]
fn org_hint_valid_hint_dispatches_generate_account_effect() {
    let mut state = OnboardingState::new();
    handle_key(&mut state, key(KeyCode::Enter));
    state = type_str(state, "chat.example");
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(!finished);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::GenerateAccount(GenerateAccountEffect { request, outcome }) => {
            assert_eq!(request.hint, "chat.example");
            assert_eq!(request.store, StoreChoice::Os);
            assert!(outcome.is_none());
        }
        other => panic!("expected GenerateAccount, got {other:?}"),
    }
    assert!(matches!(state, OnboardingState::Generating(_)));
}

/// Note: `GeneratedAccount` structurally holds no private-key field (only public id/label/
/// `account_pub`) — generation is effect-driven and never actually executed in this pure-UI layer,
/// so there is no private key value in scope for this test to compare against. This only checks
/// the `ShowIdentity` transition and its QR/server fields; it does not (and cannot) assert the
/// absence of a raw key from the render.
#[test]
fn generating_completed_transitions_to_show_identity_with_qr() {
    let mut state = OnboardingState::Generating(Generating {
        request: GenerateAccountRequest {
            store: StoreChoice::Os,
            hint: "chat.example".into(),
        },
    });
    let acc = account();
    let effects = handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
            request: GenerateAccountRequest {
                store: StoreChoice::Os,
                hint: "chat.example".into(),
            },
            outcome: Some(acc.clone()),
        })),
    );
    assert!(effects.is_empty());
    match &state {
        OnboardingState::ShowIdentity(si) => {
            assert_eq!(si.account, acc);
            assert!(si.qr.contains('\n'), "QR should be multi-line block art");
            assert_eq!(si.server, "wss://chat.example");
        }
        other => panic!("expected ShowIdentity, got {other:?}"),
    }
}

#[test]
fn generating_failed_transitions_to_failed_with_retry_and_back() {
    let request = GenerateAccountRequest {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
    };
    let mut state = OnboardingState::Generating(Generating {
        request: request.clone(),
    });
    let effects = handle_worker(
        &mut state,
        WorkerEvent::Failed(
            Effect::GenerateAccount(GenerateAccountEffect {
                request,
                outcome: None,
            }),
            "disk full".into(),
        ),
    );
    assert!(effects.is_empty());
    match &state {
        OnboardingState::Failed(f) => {
            assert_eq!(f.message, "disk full");
            assert!(matches!(*f.retry, OnboardingState::Generating(_)));
            assert!(matches!(*f.back, OnboardingState::OrgHint(_)));
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // Enter retries: dispatches the same effect and returns to Generating.
    let (effects, _) = handle_key(&mut state, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::GenerateAccount(_)));
    assert!(matches!(state, OnboardingState::Generating(_)));
}

#[test]
fn failed_esc_goes_back_to_the_editable_step() {
    let mut state = OnboardingState::Failed(Failed {
        message: "boom".into(),
        retry: Box::new(OnboardingState::Generating(Generating {
            request: GenerateAccountRequest {
                store: StoreChoice::Os,
                hint: "chat.example".into(),
            },
        })),
        back: Box::new(OnboardingState::OrgHint(OrgHint {
            store: StoreChoice::Os,
            hint: "chat.example".into(),
            error: None,
        })),
    });
    handle_key(&mut state, key(KeyCode::Esc));
    assert!(matches!(state, OnboardingState::OrgHint(_)));
}

#[test]
fn show_identity_enter_dispatches_register_effect() {
    let mut state = OnboardingState::ShowIdentity(ShowIdentity {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
        invite: String::new(),
        focus: ShowIdentityFocus::Server,
    });
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(!finished);
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::Register(req) => {
            assert_eq!(req.server, "wss://chat.example");
            assert_eq!(req.invite, None);
            assert_eq!(req.account_pub, account().account_pub);
        }
        other => panic!("expected Register, got {other:?}"),
    }
    assert!(matches!(state, OnboardingState::Registering(_)));
}

#[test]
fn show_identity_tab_switches_focus_and_invite_is_optional() {
    let mut state = OnboardingState::ShowIdentity(ShowIdentity {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
        invite: String::new(),
        focus: ShowIdentityFocus::Server,
    });
    handle_key(&mut state, key(KeyCode::Tab));
    state = type_str(state, "invite-token");
    let (effects, _) = handle_key(&mut state, key(KeyCode::Enter));
    match &effects[0] {
        Effect::Register(req) => assert_eq!(req.invite.as_deref(), Some("invite-token")),
        other => panic!("expected Register, got {other:?}"),
    }
}

#[test]
fn registering_completed_dispatches_publish_bundle_effect() {
    let mut state = OnboardingState::Registering(Registering {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
        invite: None,
    });
    let effects = handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::Register(RegisterRequest {
            server: "wss://chat.example".into(),
            invite: None,
            store: StoreChoice::Os,
            label: account().label,
            account_pub: account().account_pub,
        })),
    );
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::PublishBundle(_)));
    assert!(matches!(state, OnboardingState::PublishingBundle(_)));
}

#[test]
fn publishing_bundle_completed_transitions_to_success() {
    let mut state = OnboardingState::PublishingBundle(PublishingBundle {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
    });
    let effects = handle_worker(
        &mut state,
        WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
            request: PublishBundleRequest {
                server: "wss://chat.example".into(),
                store: StoreChoice::Os,
                label: account().label,
                account_pub: account().account_pub,
                otk_count: DEFAULT_OTK_COUNT,
            },
            outcome: Some(PublishedBundle {
                otk_count: DEFAULT_OTK_COUNT,
            }),
        })),
    );
    assert!(effects.is_empty());
    match &state {
        OnboardingState::Success(s) => {
            assert_eq!(s.id, account().id);
            assert_eq!(s.otk_count, DEFAULT_OTK_COUNT);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn success_enter_signals_finished() {
    let mut state = OnboardingState::Success(Success {
        id: account().id,
        otk_count: DEFAULT_OTK_COUNT,
        store: StoreChoice::Os,
    });
    let (effects, finished) = handle_key(&mut state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(finished);
}

/// `ChooseStore`'s hand-rolled `Debug` impl must redact `passphrase` the same way
/// `StoreChoice`'s does (see `apps/tui/src/app.rs`'s `store_choice_debug_redacts_file_passphrase`)
/// — `ChooseStore` holds its own, separate raw `passphrase: String` field for the whole span the
/// user is typing a file-store passphrase, and it sits inside `OnboardingState`/`Screen`/`App`,
/// all of which derive `Debug`, so any `{:?}` anywhere up that chain (including a stray
/// `panic!("{other:?}")` fallback like the ones in this very test file) must never leak it.
#[test]
fn choose_store_debug_redacts_passphrase() {
    let cs = ChooseStore {
        selected: StoreKindChoice::File,
        entering_passphrase: true,
        passphrase: "correct horse battery staple".into(),
    };
    let debug = format!("{cs:?}");
    assert!(!debug.contains("correct horse battery staple"));
    assert!(debug.contains("redacted"));
}

#[test]
fn irrelevant_worker_event_is_ignored() {
    let mut state = OnboardingState::new();
    let effects = handle_worker(&mut state, WorkerEvent::Completed(Effect::FetchBundle));
    assert!(effects.is_empty());
    assert!(matches!(state, OnboardingState::ChooseStore(_)));
}

// ---------------------------------------------------------------------------
// Screen snapshots — one per onboarding sub-step, at 80x24 and a narrow 40x24.
// ---------------------------------------------------------------------------

/// Renders `state` at `width`x`height` and returns the buffer as plain text (no styling) — the
/// shape every screen-snapshot test below asserts substrings against.
fn render_to_text(state: &OnboardingState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| render(state, frame)).expect("draw");
    format!("{}", terminal.backend())
}

fn assert_renders_at_both_widths(state: &OnboardingState, must_contain: &[&str]) {
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(state, w, h);
        for needle in must_contain {
            assert!(
                text.contains(needle),
                "expected {w}x{h} render to contain {needle:?}, got:\n{text}"
            );
        }
    }
}

#[test]
fn snapshot_choose_store() {
    let state = OnboardingState::new();
    assert_renders_at_both_widths(&state, &["OS keychain", "Passphrase-wrapped keyfile"]);
}

#[test]
fn snapshot_choose_store_entering_passphrase_never_shows_raw_passphrase() {
    let state = OnboardingState::ChooseStore(ChooseStore {
        selected: StoreKindChoice::File,
        entering_passphrase: true,
        passphrase: "hunter2".into(),
    });
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_to_text(&state, w, h);
        assert!(!text.contains("hunter2"));
        assert!(text.contains("passphrase"));
    }
}

#[test]
fn snapshot_org_hint() {
    let state = OnboardingState::OrgHint(OrgHint {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        error: None,
    });
    assert_renders_at_both_widths(&state, &["chat.example", "domain hint"]);
}

#[test]
fn snapshot_generating_in_progress() {
    let state = OnboardingState::Generating(Generating {
        request: GenerateAccountRequest {
            store: StoreChoice::Os,
            hint: "chat.example".into(),
        },
    });
    assert_renders_at_both_widths(&state, &["Generating"]);
}

/// Note: `ShowIdentity` structurally holds no private-key field (only the public
/// `GeneratedAccount.id`/`label`/`account_pub`, plus the `qr` string rendered from `account.id`
/// alone) — there is no raw key value in scope for this test to compare against, so it only
/// asserts the public id and QR block actually render, not a render-time negative-content check.
#[test]
fn snapshot_show_identity_renders_public_id_and_qr() {
    let acc = account();
    let state = OnboardingState::ShowIdentity(ShowIdentity {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: acc.clone(),
        qr: identity::render_terminal(&acc.id).expect("render_terminal"),
        server: "wss://chat.example".into(),
        invite: String::new(),
        focus: ShowIdentityFocus::Server,
    });
    // The id fits on one row at 80 cols, so the exact string must appear contiguously there; at
    // 40 cols it legitimately wraps across two rows (each row in `render_to_text`'s dump is its
    // own quoted line), so a naive contiguous-substring check would fail on wrapping alone rather
    // than on anything wrong — checking the id's own prefix (which always lands on the first row
    // regardless of width) is the width-independent way to assert it renders.
    assert!(render_to_text(&state, 80, 24).contains(&acc.id));
    assert_renders_at_both_widths(&state, &["mrd1:", "server:"]);
}

#[test]
fn snapshot_registering_in_progress() {
    let state = OnboardingState::Registering(Registering {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
        invite: None,
    });
    assert_renders_at_both_widths(&state, &["Connecting", "registering"]);
}

#[test]
fn snapshot_publishing_bundle_in_progress() {
    let state = OnboardingState::PublishingBundle(PublishingBundle {
        store: StoreChoice::Os,
        hint: "chat.example".into(),
        account: account(),
        qr: "qr".into(),
        server: "wss://chat.example".into(),
    });
    // "Publishing" (body text) must survive at both widths; the full "publishing bundle" step
    // label only needs to survive where the title has room for it (80 cols) — at 40 cols the
    // bordered title is legitimately truncated, same as any other overlong block title.
    assert_renders_at_both_widths(&state, &["Publishing"]);
    assert!(render_to_text(&state, 80, 24).contains("publishing bundle"));
}

#[test]
fn snapshot_success_terminal_state() {
    let state = OnboardingState::Success(Success {
        id: account().id,
        otk_count: 42,
        store: StoreChoice::Os,
    });
    assert_renders_at_both_widths(&state, &["Registered", "42"]);
}

#[test]
fn snapshot_failed_terminal_state() {
    let state = OnboardingState::Failed(Failed {
        message: "connection refused".into(),
        retry: Box::new(OnboardingState::Registering(Registering {
            store: StoreChoice::Os,
            hint: "chat.example".into(),
            account: account(),
            qr: "qr".into(),
            server: "wss://chat.example".into(),
            invite: None,
        })),
        back: Box::new(OnboardingState::ShowIdentity(ShowIdentity {
            store: StoreChoice::Os,
            hint: "chat.example".into(),
            account: account(),
            qr: "qr".into(),
            server: "wss://chat.example".into(),
            invite: String::new(),
            focus: ShowIdentityFocus::Server,
        })),
    });
    assert_renders_at_both_widths(&state, &["connection refused", "retry"]);
}

// ---------------------------------------------------------------------------
// App-level boot test (task 5.8) — the full stepped onboarding wizard, driven end to end by real
// `crossterm` key events through a real `App`, each sub-step's `Effect` executed by the real
// `meridian_tui::worker::dispatch`, landing on a real `Screen::Main`. See this file's own module
// doc for why this closes a real coverage gap rather than duplicating the state-machine tests
// above.
// ---------------------------------------------------------------------------

const APP_TEST_PASSPHRASE: &str = "correct horse battery staple";
const APP_TEST_HINT: &str = "chat.example";

/// `$MERIDIAN_HOME` environment guard — mirrors `apps/tui/tests/run_worker_account.rs`'s own (no
/// OS-keystore warmup needed: this test exercises the `StoreChoice::File` branch throughout, the
/// same reason that file's own module doc gives for never exercising `StoreChoice::Os` — a
/// headless CI runner has no real platform credential store).
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

/// A real, in-process `meridian-rendezvous` server on an ephemeral port, backed by a plain
/// `MemoryStore` — mirrors `apps/tui/tests/run_worker_account.rs::spawn_server` exactly (that
/// file's own doc comment explains why a background OS thread with its own runtime, rather than
/// the calling `#[tokio::test]`'s own, is used: the cached `SignalingClient` a real `Register`
/// dispatch produces has to keep working across this test's own later `PublishBundle` dispatch).
fn spawn_server() -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Config::default();
            let state = AppState::new(config, std::sync::Arc::new(MemoryStore::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    let addr = rx.recv().unwrap();
    format!("ws://{addr}")
}

fn render_app_to_text(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    format!("{}", terminal.backend())
}

#[tokio::test]
async fn the_full_stepped_onboarding_wizard_reaches_a_real_screen_main() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let server = spawn_server();
    let mut session = OnboardingSession::default();

    let mut app = App::new();
    assert!(matches!(app.current_screen(), Screen::Onboarding(_)));

    // --- ChooseStore: select the File-backed keystore and type its passphrase ---------------------
    let effects = app.update(AppEvent::Key(key(KeyCode::Down))); // toggle Os -> File
    assert!(effects.is_empty());
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter))); // enter the passphrase phase
    assert!(effects.is_empty());
    for c in APP_TEST_PASSPHRASE.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let rendered = render_app_to_text(&app, 80, 24);
    assert!(
        !rendered.contains(APP_TEST_PASSPHRASE),
        "the typed passphrase must never render in cleartext:\n{rendered}"
    );
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter))); // submit -> OrgHint
    assert!(effects.is_empty());
    assert!(matches!(
        app.current_screen(),
        Screen::Onboarding(state) if matches!(state.as_ref(), OnboardingState::OrgHint(_))
    ));

    // --- OrgHint: type the domain hint, dispatching a real Effect::GenerateAccount ------------------
    for c in APP_TEST_HINT.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::GenerateAccount(_)));
    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(
            event,
            WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
                outcome: Some(_),
                ..
            }))
        ),
        "account generation against a real File-backed keyfile must succeed: {event:?}"
    );
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // --- ShowIdentity: a really rendered id/QR, then re-point the prefilled server at the real
    // in-process rendezvous server this test just started, and submit ------------------------------
    let (real_id, prefill_len) = match app.current_screen() {
        Screen::Onboarding(state) => match state.as_ref() {
            OnboardingState::ShowIdentity(si) => {
                assert!(si.qr.contains('\n'), "QR should be multi-line block art");
                assert_eq!(si.server, format!("wss://{APP_TEST_HINT}"));
                (si.account.id.clone(), si.server.chars().count())
            }
            other => panic!("expected ShowIdentity, got {other:?}"),
        },
        other => panic!("expected Screen::Onboarding, got {other:?}"),
    };
    assert!(real_id.starts_with("mrd1:"));
    assert!(real_id.ends_with(&format!("@{APP_TEST_HINT}")));
    let shown = render_app_to_text(&app, 80, 24);
    // The id is long enough to wrap across two rows at 80 cols (each row in `render_app_to_text`'s
    // dump is its own quoted line), so a naive contiguous-substring check on the full id would fail
    // on wrapping alone — checking its own prefix (which always lands on the first row regardless
    // of width) is the width-independent way to assert it renders, same discipline
    // `snapshot_show_identity_renders_public_id_and_qr` above already uses.
    assert!(
        shown.contains(&real_id[..40]),
        "expected the real minted id to render:\n{shown}"
    );

    for _ in 0..prefill_len {
        app.update(AppEvent::Key(key(KeyCode::Backspace)));
    }
    for c in server.chars() {
        app.update(AppEvent::Key(char_key(c)));
    }
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(effects.len(), 1);
    let effect = effects.into_iter().next().unwrap();
    match &effect {
        Effect::Register(req) => {
            assert_eq!(req.server, server);
            assert_eq!(req.invite, None);
        }
        other => panic!("expected Effect::Register, got {other:?}"),
    }
    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(event, WorkerEvent::Completed(Effect::Register(_))),
        "registration against the real in-process rendezvous server must succeed: {event:?}"
    );

    // --- Registering -> PublishingBundle: App::handle_worker's own Registering arm dispatches the
    // next real effect itself, with no further key event needed --------------------------------
    let effects = app.update(AppEvent::Worker(Box::new(event)));
    assert_eq!(effects.len(), 1);
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::PublishBundle(_)));
    assert!(matches!(
        app.current_screen(),
        Screen::Onboarding(state) if matches!(state.as_ref(), OnboardingState::PublishingBundle(_))
    ));
    let event = dispatch(effect, &mut session).await;
    let otk_count = match &event {
        WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
            outcome: Some(published),
            ..
        })) => published.otk_count,
        other => panic!(
            "expected a completed PublishBundle against the real rendezvous server, got {other:?}"
        ),
    };
    assert!(otk_count > 0);

    // --- PublishingBundle -> Success ----------------------------------------------------------------
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());
    match app.current_screen() {
        Screen::Onboarding(state) => match state.as_ref() {
            OnboardingState::Success(s) => {
                assert_eq!(s.id, real_id);
                assert_eq!(s.otk_count, otk_count);
            }
            other => panic!("expected Success, got {other:?}"),
        },
        other => panic!("expected Screen::Onboarding, got {other:?}"),
    }
    let shown = render_app_to_text(&app, 80, 24);
    assert!(
        shown.to_lowercase().contains("registered"),
        "expected the real Success screen to render:\n{shown}"
    );

    // --- Success -> Enter finishes onboarding: for a File-backed account this reuses the passphrase
    // already typed at ChooseStore to dispatch a real Effect::Unlock (task 4.37's own File-store
    // branch), landing on the Unlock screen's own Unlocking sub-state ------------------------------
    let effects = app.update(AppEvent::Key(key(KeyCode::Enter)));
    assert_eq!(
        effects.len(),
        1,
        "finishing onboarding for a File-backed account must dispatch exactly one Effect::Unlock"
    );
    let effect = effects.into_iter().next().unwrap();
    assert!(matches!(effect, Effect::Unlock(_)));
    assert!(matches!(app.current_screen(), Screen::Unlock(_)));

    let event = dispatch(effect, &mut session).await;
    assert!(
        matches!(event, WorkerEvent::Completed(Effect::Unlock(_))),
        "the real, just-minted keyfile must unlock with the same passphrase typed at ChooseStore: \
         {event:?}"
    );
    let leftover = app.update(AppEvent::Worker(Box::new(event)));
    assert!(leftover.is_empty());

    // --- The real end state: a brand-new Screen::Main, with no contacts yet -------------------------
    match app.current_screen() {
        Screen::Main(main) => assert!(
            main.contacts.entries.is_empty(),
            "a brand-new onboarded account has no contacts yet"
        ),
        other => panic!("expected Screen::Main, got {other:?}"),
    }
}
