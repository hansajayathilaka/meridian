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
//! No real worker exists yet (task 4.16's own scope: this is a pure state machine + rendering
//! task, not the effect-execution runtime) — every test below drives transitions by directly
//! feeding `handle_key`/`handle_worker` the same way `apps/tui/src/app.rs`'s own
//! `tick_resize_and_paste_events_are_no_ops_for_now`-style tests do, simulating what a future
//! worker's `WorkerEvent::Completed`/`Failed` would report.

use meridian_core::identity;
use meridian_core::signaling::DEFAULT_OTK_COUNT;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_tui::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount, PublishBundleEffect,
    PublishBundleRequest, PublishedBundle, RegisterRequest, StoreChoice, WorkerEvent,
};
use meridian_tui::screens::onboarding::{
    handle_key, handle_worker, render, ChooseStore, Failed, Generating, OnboardingState, OrgHint,
    PublishingBundle, Registering, ShowIdentity, ShowIdentityFocus, StoreKindChoice, Success,
};

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
