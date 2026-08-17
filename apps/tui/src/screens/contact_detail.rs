//! Contact detail (task 4.19): trust state, key history, per-contact relay-policy override,
//! petname, block/delete. Always pushed on top of [`crate::screens::contacts`]'s
//! [`crate::app::Screen::Contacts`] (see [`crate::app::Screen::ContactDetail`]'s doc), never a root
//! screen of its own. Like every other screen in this crate, [`handle_key`]/[`handle_worker`] only
//! ever mutate a [`ContactDetailState`] and return the [`Effect`]s a (future) worker should execute;
//! [`render`] is a pure view function.
//!
//! **This screen edits a local *copy*.** [`ContactDetailState::entry`] starts as a clone of the
//! [`crate::screens::contacts::ContactEntry`] the user opened; every successful edit
//! (petname/block/policy) updates that copy in place, and — on `Esc` back to the list, or
//! immediately after a successful delete — `crate::app::App::apply_contact_update` reconciles it
//! into `Screen::Contacts`' own `entries`, the single source of truth the list renders from (see
//! that screen's module doc for the `ContactRecord`-vs-`TrustStore` design note this entry type
//! itself resolves).
//!
//! **No new core-crate deletion primitive.** See [`crate::app::DeleteContactRequest`]'s doc comment
//! for why "delete" here only ever removes the local `contacts.json` display entry, never anything
//! from `meridian_core::trust::TrustStore` — a documented judgment call, not something the design
//! docs specify explicitly.
//!
//! **Petname discipline.** [`EditPetname::input`] is the only source [`handle_edit_petname_key`]
//! ever reads a petname value from before dispatching [`Effect::SetPetname`] — never derived from
//! `entry.id`/`entry.hint`/`entry.pubkey` — mirroring `apps/cli/src/contact.rs::cmd_rename`'s
//! identical discipline and `crate::screens::contacts`' own "Petname discipline" section.
//!
//! **Fingerprint alongside petname (tui-client.md §6 rule 2).** [`detail_lines`] always renders the
//! truncated pubkey (`crate::screens::contacts::short_pubkey`) directly beneath the id/petname —
//! this screen is exactly the "wherever a spoofed display name could mislead" case the rule names,
//! since the petname shown here can be edited freely by the user viewing it.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{
    DeleteContactEffect, DeleteContactRequest, Effect, SetPetnameEffect, SetPetnameRequest,
    SetPolicyOverrideEffect, SetPolicyOverrideRequest, SetUserBlockedEffect, SetUserBlockedRequest,
    WorkerEvent,
};
use crate::screens::contacts::{short_pubkey, trust_glyph_and_label, ContactEntry};
use crate::store::contacts::PolicyOverride;
use crate::theme::{color_or_none, RenderCtx};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ContactDetailState {
    pub entry: ContactEntry,
    /// Set `true` the moment [`Effect::DeleteContact`] completes — `crate::app::App` reads this off
    /// the popped screen to know to *remove* rather than upsert in
    /// `crate::screens::contacts::apply_update`.
    pub deleted: bool,
    pub mode: DetailMode,
}

impl ContactDetailState {
    pub fn new(entry: ContactEntry) -> Self {
        Self {
            entry,
            deleted: false,
            mode: DetailMode::View,
        }
    }
}

/// The screen's own sub-mode. `Saving*` variants carry the pending value being written, so
/// [`handle_worker`] can apply it to [`ContactDetailState::entry`] on success without the effect's
/// `outcome` needing to carry it back (every write effect here has an `Option<()>` outcome — see
/// `crate::app`'s doc comments on why).
#[derive(Debug, Clone)]
pub enum DetailMode {
    View,
    EditPetname(EditPetname),
    ConfirmBlock,
    ConfirmDelete,
    SavingPetname(Option<String>),
    SavingBlock(bool),
    SavingPolicy(Option<PolicyOverride>),
    SavingDelete,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct EditPetname {
    pub input: String,
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn is_plain_char(modifiers: KeyModifiers) -> bool {
    !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Handles one key event. Returns the effects (if any) and whether `App` should pop this screen
/// (only `true` for `Esc` at the outermost `View` mode — every nested sub-mode's `Esc` instead
/// cancels back to `View` without leaving the screen, see the module doc).
pub fn handle_key(state: &mut ContactDetailState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match state.mode.clone() {
        DetailMode::View => handle_view_key(state, key),
        DetailMode::EditPetname(edit) => handle_edit_petname_key(state, edit, key),
        DetailMode::ConfirmBlock => handle_confirm_block_key(state, key),
        DetailMode::ConfirmDelete => handle_confirm_delete_key(state, key),
        // In-flight: no input to give while an effect is out — mirrors onboarding's
        // Generating/Registering arms.
        DetailMode::SavingPetname(_)
        | DetailMode::SavingBlock(_)
        | DetailMode::SavingPolicy(_)
        | DetailMode::SavingDelete => (Vec::new(), false),
        DetailMode::Error(_) => handle_error_key(state, key),
    }
}

fn handle_view_key(state: &mut ContactDetailState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => return (Vec::new(), true),
        KeyCode::Char('p') if is_plain_char(key.modifiers) => {
            state.mode = DetailMode::EditPetname(EditPetname {
                input: state.entry.petname.clone().unwrap_or_default(),
            });
        }
        KeyCode::Char('b') if is_plain_char(key.modifiers) => {
            state.mode = DetailMode::ConfirmBlock;
        }
        KeyCode::Char('d') if is_plain_char(key.modifiers) => {
            state.mode = DetailMode::ConfirmDelete;
        }
        KeyCode::Char('o') if is_plain_char(key.modifiers) => {
            let next_policy = cycle_policy(state.entry.policy_override);
            let effect = Effect::SetPolicyOverride(SetPolicyOverrideEffect {
                request: SetPolicyOverrideRequest {
                    pubkey: state.entry.pubkey,
                    policy_override: next_policy,
                },
                outcome: None,
            });
            state.mode = DetailMode::SavingPolicy(next_policy);
            return (vec![effect], false);
        }
        _ => {}
    }
    (Vec::new(), false)
}

fn cycle_policy(current: Option<PolicyOverride>) -> Option<PolicyOverride> {
    match current {
        None => Some(PolicyOverride::Direct),
        Some(PolicyOverride::Direct) => Some(PolicyOverride::PreferRelay),
        Some(PolicyOverride::PreferRelay) => Some(PolicyOverride::RelayOnly),
        Some(PolicyOverride::RelayOnly) => None,
    }
}

fn handle_edit_petname_key(
    state: &mut ContactDetailState,
    mut edit: EditPetname,
    key: KeyEvent,
) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Esc => {
            state.mode = DetailMode::View;
            return (Vec::new(), false);
        }
        KeyCode::Backspace => {
            edit.input.pop();
        }
        KeyCode::Char(c) if is_plain_char(key.modifiers) => edit.input.push(c),
        KeyCode::Enter => {
            // The ONLY source of this petname value — see the module doc.
            let petname = if edit.input.trim().is_empty() {
                None
            } else {
                Some(edit.input.trim().to_string())
            };
            let effect = Effect::SetPetname(SetPetnameEffect {
                request: SetPetnameRequest {
                    pubkey: state.entry.pubkey,
                    petname: petname.clone(),
                },
                outcome: None,
            });
            state.mode = DetailMode::SavingPetname(petname);
            return (vec![effect], false);
        }
        _ => {}
    }
    state.mode = DetailMode::EditPetname(edit);
    (Vec::new(), false)
}

fn handle_confirm_block_key(state: &mut ContactDetailState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let new_blocked = !state.entry.user_blocked;
            let effect = Effect::SetUserBlocked(SetUserBlockedEffect {
                request: SetUserBlockedRequest {
                    pubkey: state.entry.pubkey,
                    blocked: new_blocked,
                },
                outcome: None,
            });
            state.mode = DetailMode::SavingBlock(new_blocked);
            (vec![effect], false)
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.mode = DetailMode::View;
            (Vec::new(), false)
        }
        _ => (Vec::new(), false),
    }
}

fn handle_confirm_delete_key(state: &mut ContactDetailState, key: KeyEvent) -> (Vec<Effect>, bool) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let effect = Effect::DeleteContact(DeleteContactEffect {
                request: DeleteContactRequest {
                    pubkey: state.entry.pubkey,
                },
                outcome: None,
            });
            state.mode = DetailMode::SavingDelete;
            (vec![effect], false)
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.mode = DetailMode::View;
            (Vec::new(), false)
        }
        _ => (Vec::new(), false),
    }
}

fn handle_error_key(state: &mut ContactDetailState, key: KeyEvent) -> (Vec<Effect>, bool) {
    if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
        state.mode = DetailMode::View;
    }
    (Vec::new(), false)
}

// ---------------------------------------------------------------------------
// Worker events
// ---------------------------------------------------------------------------

/// Handles a [`WorkerEvent`]. Returns the effects (if any — there are none on any path here) and
/// whether `App` should pop this screen (`true` only once [`Effect::DeleteContact`] completes
/// successfully — every other completion just updates `entry`/`mode` in place and stays open). An
/// event that doesn't match what's currently saving is silently ignored, never a panic — mirrors
/// `crate::screens::onboarding::handle_worker`.
pub fn handle_worker(state: &mut ContactDetailState, event: WorkerEvent) -> (Vec<Effect>, bool) {
    match state.mode.clone() {
        DetailMode::SavingPetname(petname) => match event {
            WorkerEvent::Completed(Effect::SetPetname(_)) => {
                state.entry.petname = petname;
                state.mode = DetailMode::View;
            }
            WorkerEvent::Failed(Effect::SetPetname(_), message) => {
                state.mode = DetailMode::Error(message);
            }
            _ => {}
        },
        DetailMode::SavingBlock(blocked) => match event {
            WorkerEvent::Completed(Effect::SetUserBlocked(_)) => {
                state.entry.user_blocked = blocked;
                state.mode = DetailMode::View;
            }
            WorkerEvent::Failed(Effect::SetUserBlocked(_), message) => {
                state.mode = DetailMode::Error(message);
            }
            _ => {}
        },
        DetailMode::SavingPolicy(policy) => match event {
            WorkerEvent::Completed(Effect::SetPolicyOverride(_)) => {
                state.entry.policy_override = policy;
                state.mode = DetailMode::View;
            }
            WorkerEvent::Failed(Effect::SetPolicyOverride(_), message) => {
                state.mode = DetailMode::Error(message);
            }
            _ => {}
        },
        DetailMode::SavingDelete => match event {
            WorkerEvent::Completed(Effect::DeleteContact(_)) => {
                state.deleted = true;
                return (Vec::new(), true);
            }
            WorkerEvent::Failed(Effect::DeleteContact(_), message) => {
                state.mode = DetailMode::Error(message);
            }
            _ => {}
        },
        DetailMode::View
        | DetailMode::EditPetname(_)
        | DetailMode::ConfirmBlock
        | DetailMode::ConfirmDelete
        | DetailMode::Error(_) => {}
    }
    (Vec::new(), false)
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Pure view function — degradation-unaware default (unicode on, color on) for any call site without
/// a [`RenderCtx`] handy. See [`render_with_ctx`] and `crate::theme`'s own module doc.
pub fn render(state: &ContactDetailState, frame: &mut Frame<'_>) {
    render_with_ctx(state, frame, &RenderCtx::default());
}

/// Pure view function — see the module doc and `crate::theme`'s own "retrofit scope" section.
pub fn render_with_ctx(state: &ContactDetailState, frame: &mut Frame<'_>, ctx: &RenderCtx) {
    let area = frame.area();
    let title = format!("Meridian — Contact · {}", state.entry.display_label());
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines = body_lines(state, ctx);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), rows[0]);

    let footer = Paragraph::new(Line::from(Span::styled(
        footer_hint(state),
        Style::default().add_modifier(Modifier::DIM),
    )));
    frame.render_widget(footer, rows[1]);
}

fn red_style(ctx: &RenderCtx) -> Style {
    let mut style = Style::default();
    if let Some(color) = color_or_none(Color::Red, ctx) {
        style = style.fg(color);
    }
    style
}

fn body_lines(state: &ContactDetailState, ctx: &RenderCtx) -> Vec<Line<'static>> {
    let mut lines = detail_lines(&state.entry, ctx);
    match &state.mode {
        DetailMode::View | DetailMode::SavingPolicy(_) => {}
        DetailMode::EditPetname(edit) => {
            lines.push(Line::from(""));
            lines.push(Line::from(format!("new petname: {}", edit.input)));
        }
        DetailMode::ConfirmBlock => {
            let verb = if state.entry.user_blocked {
                "unblock"
            } else {
                "block"
            };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("{verb} this contact? (y/n)"),
                red_style(ctx),
            )));
        }
        DetailMode::ConfirmDelete => {
            lines.push(Line::from(""));
            // Review fix (task 4.19, Finding 2): disclose what actually survives a "delete" — see
            // `crate::app::DeleteContactRequest`'s doc comment for why this only ever removes the
            // local `contacts.json` display row, never the underlying `TrustStore` record (trust
            // state, pinned-key history, any block/key-change incident), which resurfaces exactly
            // as it was if this pubkey is ever added again.
            lines.push(Line::from(Span::styled(
                "remove from your local contact list only — trust and key history are kept and \
                 will reappear if added again. Continue? (y/n)",
                red_style(ctx),
            )));
        }
        DetailMode::SavingPetname(_) | DetailMode::SavingBlock(_) | DetailMode::SavingDelete => {
            lines.push(Line::from(""));
            lines.push(Line::from("please wait…"));
        }
        DetailMode::Error(message) => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(message.clone(), red_style(ctx))));
            lines.push(Line::from("Press Enter or Esc to continue."));
        }
    }
    lines
}

/// The always-shown facts about this contact — trust-critical fields first, with the fingerprint
/// directly beneath the petname/id (see the module doc's "Fingerprint alongside petname" section).
fn detail_lines(entry: &ContactEntry, ctx: &RenderCtx) -> Vec<Line<'static>> {
    let (glyph, label) = trust_glyph_and_label(entry.trust, ctx);
    let petname_line = match &entry.petname {
        Some(p) => format!("petname: {p}"),
        None => "petname: (none)".to_string(),
    };
    let mut lines = vec![
        Line::from(entry.id.clone()),
        Line::from(format!("fingerprint: {}", short_pubkey(&entry.pubkey))),
        Line::from(petname_line),
        Line::from(format!("trust: {glyph} {label}")),
    ];
    if entry.user_blocked {
        lines.push(Line::from(Span::styled("locally blocked", red_style(ctx))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("key history:"));
    if entry.pinned_key_history.is_empty() {
        lines.push(Line::from("  (none recorded)"));
    }
    for pk in &entry.pinned_key_history {
        lines.push(Line::from(format!(
            "  {} — first seen {}, last seen {}",
            short_pubkey(&pk.pubkey),
            pk.first_seen_unix,
            pk.last_seen_unix
        )));
    }
    lines.push(Line::from(""));
    let policy_text = match entry.policy_override {
        None => "inherit",
        Some(PolicyOverride::Direct) => "direct",
        Some(PolicyOverride::PreferRelay) => "prefer-relay",
        Some(PolicyOverride::RelayOnly) => "relay-only",
    };
    lines.push(Line::from(format!("relay policy: {policy_text}")));
    lines
}

fn footer_hint(state: &ContactDetailState) -> String {
    match &state.mode {
        DetailMode::View => {
            "p petname · b block · d delete · o cycle relay policy · Esc back".to_string()
        }
        DetailMode::EditPetname(_) => "type petname · Enter save · Esc cancel".to_string(),
        DetailMode::ConfirmBlock | DetailMode::ConfirmDelete => {
            "y confirm · n/Esc cancel".to_string()
        }
        DetailMode::SavingPetname(_)
        | DetailMode::SavingBlock(_)
        | DetailMode::SavingPolicy(_)
        | DetailMode::SavingDelete => "please wait…".to_string(),
        DetailMode::Error(_) => "Enter/Esc continue".to_string(),
    }
}
