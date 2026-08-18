//! The Onboarding screen (task 4.16): takes a user with no `account.json` on disk to a registered,
//! published identity — the first thing a new `meridian tui` run shows.
//!
//! The sub-step sequence is binding, from `docs/architecture/diagrams/tui-screen-flow.mermaid`:
//!
//! ```text
//! ChooseStore --> OrgHint --> Generate --> ShowIdentity --> Register --> PublishBundle --> done
//! ```
//!
//! `ChooseStore`/`OrgHint`/`ShowIdentity` collect user input and never touch the network/disk
//! themselves; `Generate`/`Register`/`PublishBundle` exist purely as "an [`Effect`] is in flight" —
//! every input they need was already gathered by an earlier sub-step, so there is nothing left to
//! type while they run. Like [`crate::app`], everything in this module is synchronous and I/O-free:
//! [`handle_key`]/[`handle_worker`] only ever mutate an [`OnboardingState`] and return the
//! [`Effect`]s a (future) worker should execute; [`render`] is a pure view function.
//!
//! **The private key never leaves the `SecretStore` and is never rendered** — this module only
//! ever holds/displays the public `mrd1:` id string, its QR encoding, and (briefly, masked) a
//! file-store passphrase, never private key bytes.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use meridian_core::identity;
use meridian_core::signaling::DEFAULT_OTK_COUNT;

use crate::app::{
    Effect, GenerateAccountEffect, GenerateAccountRequest, GeneratedAccount, PublishBundleEffect,
    PublishBundleRequest, RegisterRequest, StoreChoice, WorkerEvent,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The onboarding sub-step and its own state, one variant per mermaid state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingState {
    ChooseStore(ChooseStore),
    OrgHint(OrgHint),
    Generating(Generating),
    ShowIdentity(ShowIdentity),
    Registering(Registering),
    PublishingBundle(PublishingBundle),
    Success(Success),
    Failed(Failed),
}

impl OnboardingState {
    /// The entry point of the whole flow — always `ChooseStore`.
    pub fn new() -> Self {
        OnboardingState::ChooseStore(ChooseStore::default())
    }
}

impl Default for OnboardingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Sub-step 1: pick where the private key lives. Selecting `File` reveals a second, internal
/// phase (`entering_passphrase`) to collect the passphrase that will wrap it — still the same
/// mermaid state (`ChooseStore --> OrgHint: OS keystore or passphrase keyfile` is one transition,
/// not two), just two rendered phases of it.
#[derive(Clone, PartialEq, Eq)]
pub struct ChooseStore {
    pub selected: StoreKindChoice,
    pub entering_passphrase: bool,
    /// Never rendered in cleartext — masked with `•` (see [`choose_store_lines`]).
    pub passphrase: String,
}

impl std::fmt::Debug for ChooseStore {
    /// Hand-rolled rather than derived: `passphrase` holds the raw text of a live file-store
    /// passphrase for the whole span `entering_passphrase` is `true` (see
    /// `ChooseStore::from_store`'s Esc-back-navigation reconstruction), so it must never appear in
    /// a `{:?}` dump — mirrors `StoreChoice`'s hand-rolled `Debug` in `crate::app`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChooseStore")
            .field("selected", &self.selected)
            .field("entering_passphrase", &self.entering_passphrase)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

impl Default for ChooseStore {
    fn default() -> Self {
        Self {
            selected: StoreKindChoice::Os,
            entering_passphrase: false,
            passphrase: String::new(),
        }
    }
}

impl ChooseStore {
    /// Reconstructs the `ChooseStore` a later sub-step's `store: StoreChoice` came from, for
    /// backing out via Esc without losing what the user already typed.
    fn from_store(store: &StoreChoice) -> Self {
        match store {
            StoreChoice::Os => ChooseStore::default(),
            StoreChoice::File { passphrase } => ChooseStore {
                selected: StoreKindChoice::File,
                entering_passphrase: true,
                passphrase: passphrase.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKindChoice {
    Os,
    File,
}

/// Sub-step 2: the `@domain` hint (advisory routing only — `meridian_core::identity::validate_hint`
/// is the same validator `meridian id new` uses, so onboarding never reimplements the rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgHint {
    pub store: StoreChoice,
    pub hint: String,
    pub error: Option<String>,
}

/// Sub-step 3 (in-flight only): `Effect::GenerateAccount` is out; nothing left to type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generating {
    pub request: GenerateAccountRequest,
}

/// Sub-step 4: the freshly minted id + QR are shown (copy/save is the user's job, not this
/// screen's — there is nothing left for it to *do* with them beyond display); below that, the
/// rendezvous server (prefilled from the hint) and an optional invite token are collected before
/// moving on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowIdentity {
    pub store: StoreChoice,
    pub hint: String,
    pub account: GeneratedAccount,
    /// Rendered once via `meridian_core::identity::render_terminal` (pure — no I/O) when entering
    /// this state, not recomputed every frame.
    pub qr: String,
    pub server: String,
    pub invite: String,
    pub focus: ShowIdentityFocus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowIdentityFocus {
    Server,
    Invite,
}

/// Sub-step 5 (in-flight only): `Effect::Register` is out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registering {
    pub store: StoreChoice,
    pub hint: String,
    pub account: GeneratedAccount,
    pub qr: String,
    pub server: String,
    pub invite: Option<String>,
}

/// Sub-step 6 (in-flight only): `Effect::PublishBundle` is out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishingBundle {
    pub store: StoreChoice,
    pub hint: String,
    pub account: GeneratedAccount,
    pub qr: String,
    pub server: String,
}

/// Terminal state: onboarding is done. `Enter` (see [`handle_key`]'s `Success` arm for the exact
/// key set) signals "finished" back up to `App`, which (task 4.37) builds and dispatches whichever
/// effect the freshly onboarded account's own store needs to reach a real `Screen::Main` —
/// `Effect::LoadSession` for [`StoreChoice::Os`] (nothing sealed on disk yet to read — see
/// `crate::session::LiveSession::empty`'s own doc comment), `Effect::Unlock` for
/// [`StoreChoice::File`] (the single-round-trip unwrap `Screen::Unlock` itself uses, reusing the
/// passphrase already typed at `ChooseStore` rather than re-prompting for it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Success {
    pub id: String,
    pub otk_count: usize,
    /// Carried forward from [`PublishingBundle::store`] (task 4.37) — the one piece of onboarding's
    /// own state `App::handle_key`'s finished-arm needs but this struct didn't retain before: which
    /// effect to dispatch on completion, and (for `StoreChoice::File`) the still-live passphrase to
    /// dispatch it with, without re-prompting the user a second time.
    pub store: StoreChoice,
}

/// Terminal state: the in-flight effect for `retry` failed. `Esc` returns to `back` (the last
/// editable sub-step, so the user can fix whatever caused it — a bad passphrase, an unreachable
/// server, …); `Enter`/`r` re-dispatches the identical effect [`effect_for`] derives from `retry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub message: String,
    pub retry: Box<OnboardingState>,
    pub back: Box<OnboardingState>,
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

/// Whether `modifiers` marks `key` as a plain typed character (not a Ctrl/Alt shortcut this
/// screen doesn't otherwise handle) — used to keep e.g. an accidental `Ctrl+X` from being inserted
/// literally into a text field.
fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the [`Effect`]s (if any) this key produced, and whether
/// onboarding just finished (the caller, `App::handle_key`, is responsible for swapping the screen
/// on `true` — this module has no reach into the screen stack itself).
pub fn handle_key(state: &mut OnboardingState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state {
        OnboardingState::ChooseStore(cs) => {
            if let Some(next) = handle_choose_store(cs, key) {
                *state = next;
            }
            (Vec::new(), false)
        }
        OnboardingState::OrgHint(oh) => {
            let (next, effects) = handle_org_hint(oh, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, false)
        }
        // In-flight: no input to give while an Effect is out. There is also no cancel mechanism in
        // this synchronous model yet — Esc/other keys are simply ignored until the worker reports
        // back (see `handle_worker`), rather than pretending to cancel something the (nonexistent)
        // worker was never told to stop.
        OnboardingState::Generating(_)
        | OnboardingState::Registering(_)
        | OnboardingState::PublishingBundle(_) => (Vec::new(), false),
        OnboardingState::ShowIdentity(si) => {
            let (next, effects) = handle_show_identity(si, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, false)
        }
        OnboardingState::Failed(f) => {
            let (next, effects) = handle_failed(f, key);
            if let Some(next) = next {
                *state = next;
            }
            (effects, false)
        }
        OnboardingState::Success(_) => {
            let finished = matches!(key.code, KeyCode::Enter | KeyCode::Char(' '));
            (Vec::new(), finished)
        }
    }
}

fn handle_choose_store(cs: &mut ChooseStore, key: KeyEvent) -> Option<OnboardingState> {
    if cs.entering_passphrase {
        match key.code {
            // Back out to kind-selection, not out of onboarding — see the module-level Esc note in
            // `crate::app::App::handle_key`.
            KeyCode::Esc => cs.entering_passphrase = false,
            KeyCode::Backspace => {
                cs.passphrase.pop();
            }
            KeyCode::Enter if !cs.passphrase.is_empty() => {
                return Some(OnboardingState::OrgHint(OrgHint {
                    store: StoreChoice::File {
                        passphrase: cs.passphrase.clone(),
                    },
                    hint: String::new(),
                    error: None,
                }));
            }
            KeyCode::Char(c) if is_plain_char(key.modifiers) => cs.passphrase.push(c),
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                cs.selected = match cs.selected {
                    StoreKindChoice::Os => StoreKindChoice::File,
                    StoreKindChoice::File => StoreKindChoice::Os,
                };
            }
            KeyCode::Enter => match cs.selected {
                StoreKindChoice::Os => {
                    return Some(OnboardingState::OrgHint(OrgHint {
                        store: StoreChoice::Os,
                        hint: String::new(),
                        error: None,
                    }));
                }
                StoreKindChoice::File => cs.entering_passphrase = true,
            },
            // ChooseStore is the very first onboarding sub-step — there is nothing beneath it to
            // go back to, so Esc here is a deliberate no-op (see the module doc + the Esc note in
            // `crate::app::App::handle_key`).
            KeyCode::Esc => {}
            _ => {}
        }
    }
    None
}

fn handle_org_hint(oh: &mut OrgHint, key: KeyEvent) -> (Option<OnboardingState>, Vec<Effect>) {
    match key.code {
        KeyCode::Esc => {
            return (
                Some(OnboardingState::ChooseStore(ChooseStore::from_store(
                    &oh.store,
                ))),
                Vec::new(),
            );
        }
        KeyCode::Backspace => {
            oh.hint.pop();
            oh.error = None;
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => {
            oh.hint.push(c);
            oh.error = None;
        }
        KeyCode::Enter => match identity::validate_hint(&oh.hint) {
            Ok(()) => {
                let request = GenerateAccountRequest {
                    store: oh.store.clone(),
                    hint: oh.hint.clone(),
                };
                let effect = Effect::GenerateAccount(GenerateAccountEffect {
                    request: request.clone(),
                    outcome: None,
                });
                return (
                    Some(OnboardingState::Generating(Generating { request })),
                    vec![effect],
                );
            }
            Err(e) => oh.error = Some(e.to_string()),
        },
        _ => {}
    }
    (None, Vec::new())
}

fn handle_show_identity(
    si: &mut ShowIdentity,
    key: KeyEvent,
) -> (Option<OnboardingState>, Vec<Effect>) {
    match key.code {
        KeyCode::Esc => {
            return (
                Some(OnboardingState::OrgHint(OrgHint {
                    store: si.store.clone(),
                    hint: si.hint.clone(),
                    error: None,
                })),
                Vec::new(),
            );
        }
        KeyCode::Tab => {
            si.focus = match si.focus {
                ShowIdentityFocus::Server => ShowIdentityFocus::Invite,
                ShowIdentityFocus::Invite => ShowIdentityFocus::Server,
            };
        }
        KeyCode::Backspace => match si.focus {
            ShowIdentityFocus::Server => {
                si.server.pop();
            }
            ShowIdentityFocus::Invite => {
                si.invite.pop();
            }
        },
        KeyCode::Char(c) if is_plain_char(key.modifiers) => match si.focus {
            ShowIdentityFocus::Server => si.server.push(c),
            ShowIdentityFocus::Invite => si.invite.push(c),
        },
        KeyCode::Enter if !si.server.trim().is_empty() => {
            let invite = if si.invite.trim().is_empty() {
                None
            } else {
                Some(si.invite.clone())
            };
            let request = RegisterRequest {
                server: si.server.clone(),
                invite,
                store: si.store.clone(),
                label: si.account.label.clone(),
                account_pub: si.account.account_pub,
            };
            let next = OnboardingState::Registering(Registering {
                store: si.store.clone(),
                hint: si.hint.clone(),
                account: si.account.clone(),
                qr: si.qr.clone(),
                server: si.server.clone(),
                invite: request.invite.clone(),
            });
            let effect = Effect::Register(request);
            return (Some(next), vec![effect]);
        }
        _ => {}
    }
    (None, Vec::new())
}

fn handle_failed(f: &mut Failed, key: KeyEvent) -> (Option<OnboardingState>, Vec<Effect>) {
    match key.code {
        KeyCode::Esc => (Some((*f.back).clone()), Vec::new()),
        KeyCode::Enter | KeyCode::Char('r') => {
            let retry_state = (*f.retry).clone();
            let effects = effect_for(&retry_state).into_iter().collect();
            (Some(retry_state), effects)
        }
        _ => (None, Vec::new()),
    }
}

/// The [`Effect`] a given in-flight [`OnboardingState`] would dispatch — used to re-derive the
/// retry effect from [`Failed::retry`] without storing the effect and the state redundantly.
fn effect_for(state: &OnboardingState) -> Option<Effect> {
    match state {
        OnboardingState::Generating(g) => Some(Effect::GenerateAccount(GenerateAccountEffect {
            request: g.request.clone(),
            outcome: None,
        })),
        OnboardingState::Registering(r) => Some(Effect::Register(RegisterRequest {
            server: r.server.clone(),
            invite: r.invite.clone(),
            store: r.store.clone(),
            label: r.account.label.clone(),
            account_pub: r.account.account_pub,
        })),
        OnboardingState::PublishingBundle(p) => Some(Effect::PublishBundle(PublishBundleEffect {
            request: PublishBundleRequest {
                server: p.server.clone(),
                store: p.store.clone(),
                label: p.account.label.clone(),
                account_pub: p.account.account_pub,
                otk_count: DEFAULT_OTK_COUNT,
            },
            outcome: None,
        })),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`] — the (future) worker reporting an [`Effect`] this screen dispatched
/// finished or failed. A worker event that doesn't match the current in-flight step (e.g. a stale
/// reply after the user already retried) is silently ignored, never a panic.
pub fn handle_worker(state: &mut OnboardingState, event: WorkerEvent) -> Vec<Effect> {
    match state {
        OnboardingState::Generating(g) => match event {
            WorkerEvent::Completed(Effect::GenerateAccount(GenerateAccountEffect {
                outcome: Some(account),
                ..
            })) => {
                let qr = identity::render_terminal(&account.id)
                    .unwrap_or_else(|e| format!("<qr render failed: {e}>"));
                let server = format!("wss://{}", g.request.hint);
                *state = OnboardingState::ShowIdentity(ShowIdentity {
                    store: g.request.store.clone(),
                    hint: g.request.hint.clone(),
                    account,
                    qr,
                    server,
                    invite: String::new(),
                    focus: ShowIdentityFocus::Server,
                });
                Vec::new()
            }
            WorkerEvent::Failed(Effect::GenerateAccount(_), message) => {
                let back = OnboardingState::OrgHint(OrgHint {
                    store: g.request.store.clone(),
                    hint: g.request.hint.clone(),
                    error: None,
                });
                let retry = OnboardingState::Generating(g.clone());
                *state = OnboardingState::Failed(Failed {
                    message,
                    retry: Box::new(retry),
                    back: Box::new(back),
                });
                Vec::new()
            }
            _ => Vec::new(),
        },
        OnboardingState::Registering(r) => match event {
            WorkerEvent::Completed(Effect::Register(_)) => {
                let request = PublishBundleRequest {
                    server: r.server.clone(),
                    store: r.store.clone(),
                    label: r.account.label.clone(),
                    account_pub: r.account.account_pub,
                    otk_count: DEFAULT_OTK_COUNT,
                };
                let effect = Effect::PublishBundle(PublishBundleEffect {
                    request,
                    outcome: None,
                });
                *state = OnboardingState::PublishingBundle(PublishingBundle {
                    store: r.store.clone(),
                    hint: r.hint.clone(),
                    account: r.account.clone(),
                    qr: r.qr.clone(),
                    server: r.server.clone(),
                });
                vec![effect]
            }
            WorkerEvent::Failed(Effect::Register(_), message) => {
                let back = OnboardingState::ShowIdentity(ShowIdentity {
                    store: r.store.clone(),
                    hint: r.hint.clone(),
                    account: r.account.clone(),
                    qr: r.qr.clone(),
                    server: r.server.clone(),
                    invite: r.invite.clone().unwrap_or_default(),
                    focus: ShowIdentityFocus::Server,
                });
                let retry = OnboardingState::Registering(r.clone());
                *state = OnboardingState::Failed(Failed {
                    message,
                    retry: Box::new(retry),
                    back: Box::new(back),
                });
                Vec::new()
            }
            _ => Vec::new(),
        },
        OnboardingState::PublishingBundle(p) => match event {
            WorkerEvent::Completed(Effect::PublishBundle(PublishBundleEffect {
                outcome: Some(published),
                ..
            })) => {
                *state = OnboardingState::Success(Success {
                    id: p.account.id.clone(),
                    otk_count: published.otk_count,
                    store: p.store.clone(),
                });
                Vec::new()
            }
            WorkerEvent::Failed(Effect::PublishBundle(_), message) => {
                // `invite` is deliberately dropped here, not threaded through from wherever the
                // user originally typed it: `PublishingBundle` carries no `invite` field because
                // by this point `Effect::Register`'s execution already redeemed it successfully
                // (this is *publish* failing, after register succeeded). Re-populating it would
                // risk the user resubmitting it on retry and attempting a double-redeem of a
                // normally single-use token — see `RegisterRequest`'s doc comment in `app.rs`.
                let back = OnboardingState::ShowIdentity(ShowIdentity {
                    store: p.store.clone(),
                    hint: p.hint.clone(),
                    account: p.account.clone(),
                    qr: p.qr.clone(),
                    server: p.server.clone(),
                    invite: String::new(),
                    focus: ShowIdentityFocus::Server,
                });
                let retry = OnboardingState::PublishingBundle(p.clone());
                *state = OnboardingState::Failed(Failed {
                    message,
                    retry: Box::new(retry),
                    back: Box::new(back),
                });
                Vec::new()
            }
            _ => Vec::new(),
        },
        // Not currently waiting on a worker: ignore.
        OnboardingState::ChooseStore(_)
        | OnboardingState::OrgHint(_)
        | OnboardingState::ShowIdentity(_)
        | OnboardingState::Failed(_)
        | OnboardingState::Success(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — see the module doc.
pub fn render(state: &OnboardingState, frame: &mut Frame<'_>) {
    let area = frame.area();
    let title = format!("Meridian — Onboarding · {}", step_label(state));
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    render_body(state, frame, rows[0]);
    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn render_body(state: &OnboardingState, frame: &mut Frame<'_>, area: Rect) {
    match state {
        // ShowIdentity gets a dedicated layout so the QR block is never line-wrapped (it's
        // block-art; `Wrap` would corrupt it) while everything else in this screen still wraps
        // safely at a narrow width.
        OnboardingState::ShowIdentity(si) => render_show_identity(si, frame, area),
        _ => {
            let lines = body_lines(state);
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
        }
    }
}

fn render_show_identity(si: &ShowIdentity, frame: &mut Frame<'_>, area: Rect) {
    // The id (`mrd1:…@hint`) is a plain, wrappable string — unlike the QR block below it, it must
    // stay fully visible even at a narrow width, so it gets as many rows as it needs rather than a
    // fixed one (a 40-col pane needs 2 rows for a ~66-char id; 80 cols fits it in 1).
    let usable_width = area.width.max(1);
    let id_len = si.account.id.chars().count() as u16;
    let id_height = id_len.div_ceil(usable_width).max(1);

    let qr_lines: Vec<Line<'static>> = si.qr.lines().map(|l| Line::from(l.to_string())).collect();
    let qr_height = (qr_lines.len() as u16).min(area.height.saturating_sub(id_height + 3));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(id_height), // id
            Constraint::Length(qr_height),
            Constraint::Length(1), // blank
            Constraint::Length(1), // server field
            Constraint::Length(1), // invite field
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(Line::from(si.account.id.clone())).wrap(Wrap { trim: false }),
        rows[0],
    );
    frame.render_widget(Paragraph::new(qr_lines), rows[1]);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("server: "),
            Span::styled(
                si.server.clone(),
                focus_style(si.focus == ShowIdentityFocus::Server),
            ),
        ])),
        rows[3],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("invite (optional): "),
            Span::styled(
                si.invite.clone(),
                focus_style(si.focus == ShowIdentityFocus::Invite),
            ),
        ])),
        rows[4],
    );
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
    }
}

fn step_label(state: &OnboardingState) -> &'static str {
    match state {
        OnboardingState::ChooseStore(_) => "choose secret store",
        OnboardingState::OrgHint(_) => "home-domain hint",
        OnboardingState::Generating(_) => "generating identity",
        OnboardingState::ShowIdentity(_) => "your identity",
        OnboardingState::Registering(_) => "registering",
        OnboardingState::PublishingBundle(_) => "publishing bundle",
        OnboardingState::Success(_) => "done",
        OnboardingState::Failed(_) => "failed",
    }
}

fn footer_hint(state: &OnboardingState) -> &'static str {
    match state {
        OnboardingState::ChooseStore(cs) if cs.entering_passphrase => {
            "type passphrase · Enter continue · Esc back"
        }
        OnboardingState::ChooseStore(_) => "↑/↓/Tab choose · Enter continue",
        OnboardingState::OrgHint(_) => "type · Enter continue · Esc back",
        OnboardingState::Generating(_) => "please wait…",
        OnboardingState::ShowIdentity(_) => "Tab switch field · type · Enter register · Esc back",
        OnboardingState::Registering(_) => "please wait…",
        OnboardingState::PublishingBundle(_) => "please wait…",
        OnboardingState::Success(_) => "Enter continue",
        OnboardingState::Failed(_) => "Enter retry · Esc back",
    }
}

fn body_lines(state: &OnboardingState) -> Vec<Line<'static>> {
    match state {
        OnboardingState::ChooseStore(cs) => choose_store_lines(cs),
        OnboardingState::OrgHint(oh) => org_hint_lines(oh),
        OnboardingState::Generating(g) => vec![
            Line::from(format!("Generating your identity for @{}…", g.request.hint)),
            Line::from(""),
            Line::from("Minting an Ed25519 keypair and writing it to your chosen secret store."),
        ],
        OnboardingState::Registering(_) => vec![
            Line::from("Connecting to the rendezvous server…"),
            Line::from(""),
            Line::from("Registering your account (redeeming your invite token, if you gave one)."),
        ],
        OnboardingState::PublishingBundle(_) => vec![
            Line::from("Publishing your prekey bundle…"),
            Line::from(""),
            Line::from("Your contacts need this to start a session with you."),
        ],
        OnboardingState::Success(s) => vec![
            Line::from(Span::styled(
                "Registered!",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(s.id.clone()),
            Line::from(format!("Published {} one-time prekeys.", s.otk_count)),
            Line::from(""),
            Line::from("Press Enter to continue."),
        ],
        OnboardingState::Failed(f) => vec![
            Line::from(Span::styled(
                "Something went wrong.",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(f.message.clone()),
            Line::from(""),
            Line::from("Press Enter to retry, or Esc to go back and change your answer."),
        ],
        OnboardingState::ShowIdentity(_) => {
            unreachable!("ShowIdentity is rendered by render_show_identity, not body_lines")
        }
    }
}

fn choose_store_lines(cs: &ChooseStore) -> Vec<Line<'static>> {
    if cs.entering_passphrase {
        let masked: String = "•".repeat(cs.passphrase.chars().count());
        vec![
            Line::from("Passphrase-wrapped keyfile"),
            Line::from(""),
            Line::from(format!("passphrase: {masked}")),
            Line::from(""),
            Line::from(if cs.passphrase.is_empty() {
                "(passphrase required)"
            } else {
                "Press Enter to continue."
            }),
        ]
    } else {
        let os_marker = if cs.selected == StoreKindChoice::Os {
            "> "
        } else {
            "  "
        };
        let file_marker = if cs.selected == StoreKindChoice::File {
            "> "
        } else {
            "  "
        };
        vec![
            Line::from("Where should your private key live?"),
            Line::from(""),
            Line::from(format!("{os_marker}OS keychain")),
            Line::from(format!("{file_marker}Passphrase-wrapped keyfile")),
        ]
    }
}

fn org_hint_lines(oh: &OrgHint) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("What's your home-domain hint? (advisory routing only, e.g. chat.example)"),
        Line::from(""),
        Line::from(format!("@{}", oh.hint)),
    ];
    if let Some(err) = &oh.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    lines
}
