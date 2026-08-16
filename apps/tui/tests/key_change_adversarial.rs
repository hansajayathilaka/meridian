//! Task 4.23 — the dedicated adversarial integration test proving that flipping a **verified**
//! contact's key blocks the composer with **no send path anywhere in the UI**
//! (`cargo nextest run -p meridian-tui --test key_change_adversarial`).
//!
//! **Scope, precisely (see the task file's own "Scope boundary").** This does *not* re-test
//! `meridian_core::trust::TrustStore::observe_key_change`/`can_send` themselves — `apps/core/tests`
//! (task 4.4) already owns and proves that state-transition logic at the core-module level. This
//! file assumes the gate computation is correct and asks a UI-only question: once that
//! already-correct gate reads `Blocked`, does *anything* reachable through this crate's own input
//! surface — every keycode this crate matches on, crossed with every practical modifier
//! combination, from every reachable start-mode, fed through both `crate::screens::chat::handle_key`
//! directly and the real `App::update` entry point a keypress actually flows through — ever produce
//! `Effect::SendMessage`, or leave the composer able to accept text that could later produce one?
//!
//! Four layers, matching the task's own four-part deliverable:
//! 1. [`blocked_state`] — the scripted key-change: a **verified** contact's key changes, simulated by
//!    calling `TrustStore::observe_key_change` directly on an owned store exactly as a real client
//!    would apply an inbound key-change event, never by hand-constructing a `Blocked` `Contact`.
//! 2. [`blocked_composer_never_sends_from_any_start_mode_and_never_admits_text_while_normal`] — the
//!    exhaustive keyboard sweep through `chat::handle_key` itself (the closest precedent is
//!    `screens_verify.rs`'s own `blocked_gate_no_key_sequence_clears_blocked_except_via_confirmed_verify`;
//!    this file matches that style rather than inventing a new one).
//! 3. [`blocked_composer_reachable_only_via_screen_chat_no_app_level_key_ever_sends`] and
//!    [`paste_event_is_not_wired_to_any_screen_and_cannot_smuggle_composer_text`] — the same sweep one
//!    layer up, through the real `App::update` a keypress/paste actually flows through, so a *global*
//!    hotkey (`Ctrl+Q`/`Ctrl+R`, `app.rs`'s only two) or an unwired event type can't route around
//!    `Screen::Chat`'s own gate check.
//! 4. [`palette_command_violations`] plus its two tests — the palette-command surface (`crate::surface`),
//!    checked generically (not just "today's registry is empty") so the same check keeps working once
//!    a future task actually wires `PaletteRegistry::find_binding` into `App::handle_key` (`surface.rs`'s
//!    own "orphaned wiring" doc note names task 4.25 as that future owner).
//!
//! Plus [`blocked_composer_visibly_shows_the_blocked_state_throughout_the_sweep`] for the "the user
//! can see why" half of the deliverable (mirrors `screens_chat.rs`'s own
//! `security_blocked_banner_is_always_shown_live_not_only_after_a_failed_attempt`).
//!
//! **Known scope gap, documented rather than silently left uncovered:** none of the sweeps above ever
//! reach `dispatch_gated_send`'s `SendGate::Blocked(_) => Vec::new()` arm via the *retry* path
//! (`r` on a `Failed` entry) — [`blocked_state`]'s fixture always starts with `entries: Vec::new()`, so
//! `retry_last_failed` short-circuits (nothing to retry) before `dispatch_gated_send` is ever reached,
//! for every sweep in this file. That exact scenario — seed a `Failed` entry, flip the gate to
//! `Blocked`, press `r` — is already covered by task 4.20's own `screens_chat.rs`'s
//! `retry_re_checks_the_gate_and_refuses_if_now_blocked`, not duplicated here; a future reader should
//! not assume this file's sweeps are complete for that specific code path.
//!
//! No real worker exists yet — every test below drives transitions by directly feeding
//! `handle_key`/`App::update`, exactly like every other integration test in this crate does.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use meridian_core::trust::{SendGate, TrustState, TrustStore};

use meridian_tui::app::{App, AppEvent, Effect, Screen, SendMessageEffect, SendMessageRequest};
use meridian_tui::screens::chat::{self, ChatFocus, ChatState, ComposerMode};
use meridian_tui::surface::{KeyBinding, PaletteAction, PaletteCommand, PaletteRegistry};

// ---------------------------------------------------------------------------
// Fixture: "a key-change event arriving over the wire" for a Verified contact
// ---------------------------------------------------------------------------

/// Simulates exactly what the task file's own recipe describes: a contact that starts
/// [`TrustState::Verified`] (an out-of-band safety-number compare already happened — task 4.4/4.22 own
/// proving `mark_verified` itself is correct; that machinery is exercised here only as setup, never as
/// the thing under test), then a key-change event arrives over the wire and is applied via
/// [`TrustStore::observe_key_change`] with the contact's *current* pubkey as `previous_pubkey` and a
/// fresh pubkey as `new_pubkey` — never by hand-constructing a `Contact` already in
/// [`TrustState::Blocked`], which would test something this store never actually does.
///
/// Per `observe_key_change`'s own doc, a `Verified` contact transitions straight to
/// [`TrustState::Blocked`] (the hard-stop flavor, not `PinnedKeyChanged`'s warn-and-continue). Returns
/// the resulting [`ChatState`], opened against the *new*, post-change pubkey (mirrors a real client
/// already being mid-conversation when the key-change arrives), and that pubkey for callers that want
/// to inspect `state.trust` directly.
fn blocked_state() -> (ChatState, [u8; 32]) {
    let previous = [0x30u8; 32];
    let current = [0x31u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(previous, "adversary.example", 1_000);
    trust.mark_verified(&previous).expect("known contact");
    let resulting = trust
        .observe_key_change(&previous, current, "adversary.example", 2_000)
        .expect("known contact, distinct new key");
    assert_eq!(
        resulting,
        TrustState::Blocked,
        "fixture setup sanity: a Verified contact's key change must hard-block, not warn"
    );
    let state = ChatState::new(current, "adversary.example".into(), trust, Vec::new(), 0);
    assert!(
        matches!(state.gate(), SendGate::Blocked(_)),
        "fixture setup sanity: can_send must read Blocked before the sweep even starts"
    );
    (state, current)
}

// ---------------------------------------------------------------------------
// Exhaustive keycode x modifier enumeration — extends screens_verify.rs's all_keycodes/all_modifiers
// (same practical set this crate already treats as "the input surface"), per the task's own
// instruction to match that file's exhaustive-enumeration style rather than inventing a new one.
//
// crossterm 0.29's `KeyCode` is not `#[non_exhaustive]`; every zero-argument variant is included below
// (26 lowercase + 26 uppercase + 10 digits + 33 punctuation/space `Char`s, 23 named keys — the original
// 16 plus the 7 terminal-enhancement-only keys `CapsLock`/`ScrollLock`/`NumLock`/`PrintScreen`/`Pause`/
// `Menu`/`KeypadBegin` — 12 `F(n)` keys = 130 simple codes), plus one representative case each of the
// two data-carrying variants whose *inner* enums this sweep does not attempt to exhaust:
// - `KeyCode::Media(MediaKeyCode)` — 13 inner variants, all requiring a hardware media key and the
//   `DISAMBIGUATE_ESCAPE_CODES` keyboard-enhancement flag; genuinely unreachable from a plain terminal
//   in practice, and `chat.rs`'s own `handle_composer_key`/`handle_transcript_key` never match on
//   `KeyCode::Media` at all (both fall through their catch-all `_ => {}` arm), so every inner variant
//   is provably equivalent from this screen's point of view. One representative case
//   (`MediaKeyCode::Play`) is swept as a sentinel for "an unmatched data-carrying KeyCode is still a
//   no-op while Blocked", not because the other twelve could plausibly behave differently.
// - `KeyCode::Modifier(ModifierKeyCode)` — same reasoning, same catch-all outcome; one representative
//   case (`ModifierKeyCode::LeftControl`) is swept for the same sentinel purpose.
// Total: 130 simple codes + 2 representative data-carrying codes = 132 (see the exact-count assertion
// in the primary sweep test, which is derived from `all_keycodes().len()` rather than hand-typed, so
// this comment and that assertion can never silently drift apart).
fn all_keycodes() -> Vec<KeyCode> {
    let mut codes = Vec::new();
    for c in 'a'..='z' {
        codes.push(KeyCode::Char(c));
    }
    for c in 'A'..='Z' {
        codes.push(KeyCode::Char(c));
    }
    for c in '0'..='9' {
        codes.push(KeyCode::Char(c));
    }
    for c in [
        '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}',
        ';', ':', '\'', '"', ',', '.', '<', '>', '/', '?', '\\', '|', '`', '~', ' ',
    ] {
        codes.push(KeyCode::Char(c));
    }
    codes.extend([
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Backspace,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Delete,
        KeyCode::Insert,
        KeyCode::Null,
        // Enhancement-only keys (only readable with `DISAMBIGUATE_ESCAPE_CODES` pushed) — included so
        // the sweep does not silently exclude a real `KeyCode` variant just because this crate never
        // pushes that flag today.
        KeyCode::CapsLock,
        KeyCode::ScrollLock,
        KeyCode::NumLock,
        KeyCode::PrintScreen,
        KeyCode::Pause,
        KeyCode::Menu,
        KeyCode::KeypadBegin,
    ]);
    for n in 1..=12 {
        codes.push(KeyCode::F(n));
    }
    // Representative cases of the two data-carrying variants — see the module-level comment above
    // this function for why a single case each is sufficient rather than exhausting their inner enums.
    codes.push(KeyCode::Media(crossterm::event::MediaKeyCode::Play));
    codes.push(KeyCode::Modifier(
        crossterm::event::ModifierKeyCode::LeftControl,
    ));
    codes
}

/// `KeyModifiers` bit-flag coverage. crossterm 0.29 defines six flag bits (`SHIFT`, `CONTROL`, `ALT`,
/// `SUPER`, `HYPER`, `META`), i.e. 64 possible combinations; sweeping the full powerset would add
/// negligible additional coverage (`chat.rs` only ever calls `.contains(CONTROL)`/`.contains(ALT)`
/// individually or `.intersects(CONTROL | ALT)` — see `is_plain_char` and `handle_composer_key` — never
/// branching on `SUPER`/`HYPER`/`META` or on any specific two-bit combination) at a real multiplicative
/// cost to this file's runtime, so this set covers every individual bit (proving each is individually
/// inert while Blocked) plus two representative multi-bit combinations (`CONTROL | ALT`, `CONTROL |
/// SHIFT`) as a sentinel that combined flags aren't special-cased either — judged the practical ceiling
/// of "the input surface", not the full 64-combination powerset.
fn all_modifiers() -> Vec<KeyModifiers> {
    vec![
        KeyModifiers::NONE,
        KeyModifiers::CONTROL,
        KeyModifiers::ALT,
        KeyModifiers::SHIFT,
        KeyModifiers::SUPER,
        KeyModifiers::HYPER,
        KeyModifiers::META,
        KeyModifiers::CONTROL | KeyModifiers::ALT,
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
    ]
}

/// Every effect in `effects` must not be `Effect::SendMessage` — the one property this whole file
/// exists to pin, checked the same way at every layer (`chat::handle_key` directly, `App::update`).
fn assert_no_send_leaked(effects: &[Effect], context: &str) {
    for effect in effects {
        assert!(
            !matches!(effect, Effect::SendMessage(_)),
            "leaked Effect::SendMessage while the gate reads Blocked ({context}): {effect:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Layer 1: chat::handle_key itself — the sole choke point per chat.rs's own module doc
// ---------------------------------------------------------------------------

/// Which starting sub-mode a fresh `Blocked` [`ChatState`] is placed in before the sweep's one key is
/// fired. `Normal` is the only mode legitimately reachable while the gate is `Blocked` — chat.rs's own
/// `dispatch_gated_send` never constructs `ComposerMode::AwaitingAck` from its `SendGate::Blocked` arm
/// (see that function's doc). The three `AwaitingAck*` variants are swept anyway, as defense in depth:
/// if a future bug ever let `AwaitingAck` coexist with a `Blocked` gate (e.g. a stale mode surviving a
/// key-change that arrived mid-warn-prompt), `TrustStore::acknowledge_key_change`'s own "never clears
/// Blocked" contract (task 4.4) must still hold when exercised from this screen's own key handling, not
/// just at the core-module level — mirrors chat.rs's own module doc: "never blindly trust the
/// acknowledgment, re-check the real gate".
#[derive(Clone, Copy, Debug)]
enum StartMode {
    Normal,
    AwaitingAckAnsweredY,
    AwaitingAckAnsweredYes,
    AwaitingAckAnsweredOther,
}

/// All [`StartMode`] variants, guarded at compile time: the trailing `match` has no wildcard arm, so
/// adding a fifth `StartMode` variant fails to compile right here until a new arm (and a new entry in
/// the `modes` array immediately above it) is added — a plain array literal alone couldn't force that.
fn all_start_modes() -> Vec<StartMode> {
    let modes = [
        StartMode::Normal,
        StartMode::AwaitingAckAnsweredY,
        StartMode::AwaitingAckAnsweredYes,
        StartMode::AwaitingAckAnsweredOther,
    ];
    for mode in &modes {
        match mode {
            StartMode::Normal
            | StartMode::AwaitingAckAnsweredY
            | StartMode::AwaitingAckAnsweredYes
            | StartMode::AwaitingAckAnsweredOther => {}
        }
    }
    modes.to_vec()
}

/// All [`ChatFocus`] variants, guarded the same way as [`all_start_modes`]: a third `ChatFocus`
/// variant added to `chat.rs` fails to compile here until this function is updated to match.
fn all_chat_focuses() -> Vec<ChatFocus> {
    let focuses = [ChatFocus::Composer, ChatFocus::Transcript];
    for focus in &focuses {
        match focus {
            ChatFocus::Composer | ChatFocus::Transcript => {}
        }
    }
    focuses.to_vec()
}

/// The `(StartMode, ChatFocus)` pairs actually worth sweeping — not the full cross product.
/// `chat::handle_key` (see its doc, and [`StartMode`]'s own doc above) checks `state.mode` for
/// `ComposerMode::AwaitingAck` and dispatches to `handle_awaiting_ack_key` *before* ever consulting
/// `state.focus`; verified directly by reading `handle_key`'s body, not assumed. So for the three
/// `AwaitingAck*` start modes, `ChatFocus::Composer` and `ChatFocus::Transcript` hit the exact same
/// code path with the exact same outcome — crossing them with focus would duplicate work, not add
/// coverage. Only [`StartMode::Normal`] — the one mode `handle_key` actually branches on `state.focus`
/// for — is crossed with both focus values; each `AwaitingAck*` mode is swept once, at a fixed
/// (arbitrary) focus.
fn sweep_combos() -> Vec<(StartMode, ChatFocus)> {
    let mut combos = Vec::new();
    for focus in all_chat_focuses() {
        combos.push((StartMode::Normal, focus));
    }
    for mode in all_start_modes() {
        if !matches!(mode, StartMode::Normal) {
            combos.push((mode, ChatFocus::Composer));
        }
    }
    combos
}

const SENTINEL_COMPOSER_TEXT: &str = "SENTINEL: already-typed text before this key";

fn apply_start_mode(state: &mut ChatState, mode: StartMode) {
    match mode {
        StartMode::Normal => {
            state.composer = SENTINEL_COMPOSER_TEXT.to_string();
        }
        StartMode::AwaitingAckAnsweredY => {
            state.mode = ComposerMode::AwaitingAck {
                reason: "a defense-in-depth synthetic reason".to_string(),
                held: "attacker-controlled held body".to_string(),
            };
            state.composer = "y".to_string();
        }
        StartMode::AwaitingAckAnsweredYes => {
            state.mode = ComposerMode::AwaitingAck {
                reason: "a defense-in-depth synthetic reason".to_string(),
                held: "attacker-controlled held body".to_string(),
            };
            state.composer = "yes".to_string();
        }
        StartMode::AwaitingAckAnsweredOther => {
            state.mode = ComposerMode::AwaitingAck {
                reason: "a defense-in-depth synthetic reason".to_string(),
                held: "attacker-controlled held body".to_string(),
            };
            state.composer = "n".to_string();
        }
    }
}

/// This task's central deliverable: **exhaustively**, not by sampling — every [`all_keycodes`] entry
/// crossed with every [`all_modifiers`] entry, from every [`sweep_combos`] `(StartMode, ChatFocus)`
/// pair — fed one at a time through `chat::handle_key` against a fresh `Blocked` [`ChatState`] (rebuilt
/// every iteration, exactly like `screens_verify.rs`'s own sweep, so one iteration's mutation can never
/// leak into the next). Asserts, for every single combination:
/// - no `Effect::SendMessage` is ever returned (true for every `StartMode`, including the three
///   `AwaitingAck*` ones — see this test's name's "never sends from any start mode" half);
/// - `state.entries`/`state.sending` never register a send as having happened;
/// - `state.gate()` still reads `Blocked` afterwards (the underlying `TrustStore` was never mutated
///   into anything that would relax the gate — the one core-level exception this sweep exercises,
///   `acknowledge_key_change`, is proven above to fail closed for a `Blocked` contact);
/// - **for [`StartMode::Normal`] specifically**, the composer text is byte-identical to what it was
///   before the key — proving typing itself is refused outright (tui-client.md §6 rule 1: "the
///   composer is disabled"), not merely that `Enter` alone is refused. This is *not* asserted for the
///   `AwaitingAck*` start modes (see this test's name's "never admits text while normal" half) — those
///   legitimately admit `y`/`n`/`yes` keystrokes into the acknowledgment prompt, which is correct UX
///   for a `Warn`-flavored key change, not a bypass of anything this file is pinning.
///
/// The exact case count is asserted below rather than a loose floor, derived from
/// `sweep_combos().len() * all_keycodes().len() * all_modifiers().len()` — not hand-typed — so this
/// doc comment, that assertion, and the actual enumeration helpers can never silently drift apart the
/// way a hand-typed "~89 keycodes" estimate once did.
#[test]
fn blocked_composer_never_sends_from_any_start_mode_and_never_admits_text_while_normal() {
    let mut checked = 0usize;
    for (start_mode, focus) in sweep_combos() {
        for code in all_keycodes() {
            for modifiers in all_modifiers() {
                let (mut state, peer) = blocked_state();
                state.focus = focus;
                apply_start_mode(&mut state, start_mode);

                let (effects, _exit) = chat::handle_key(&mut state, KeyEvent::new(code, modifiers));
                checked += 1;

                let context = format!(
                    "focus={focus:?} start_mode={start_mode:?} code={code:?} mods={modifiers:?}"
                );
                assert_no_send_leaked(&effects, &context);
                assert!(
                    state.entries.is_empty(),
                    "no send ever completed, so entries must stay empty ({context})"
                );
                assert!(
                    state.sending.is_none(),
                    "no send was ever dispatched, so `sending` must stay None ({context})"
                );
                assert!(
                    matches!(state.trust.can_send(&peer), SendGate::Blocked(_)),
                    "the gate must remain Blocked afterwards ({context})"
                );

                if matches!(start_mode, StartMode::Normal) {
                    assert_eq!(
                        state.composer, SENTINEL_COMPOSER_TEXT,
                        "typing must be refused outright while blocked, not just Enter ({context})"
                    );
                }
            }
        }
    }
    // Exact-count guard (Finding 1/4 of the review pass on this file): if a future edit adds a keycode,
    // modifier, or start-mode/focus combination, this fails immediately with a concrete mismatch rather
    // than silently passing with a stale "big enough" number — forcing that future edit's author to
    // re-derive (not hand-guess) the new total. See `all_keycodes`'s own doc comment for how the 132
    // figure is built up, and `sweep_combos`'s own doc comment for why the multiplier is 5 (2 `Normal`
    // x-focus combos + 3 `AwaitingAck*` combos), not 8 (2 focuses x 4 start modes).
    let expected = sweep_combos().len() * all_keycodes().len() * all_modifiers().len();
    assert_eq!(
        checked, expected,
        "exhaustive sweep must check exactly sweep_combos() x all_keycodes() x all_modifiers() cases"
    );
}

// ---------------------------------------------------------------------------
// Layer 2: the visible half of the deliverable — the banner, live, throughout
// ---------------------------------------------------------------------------

fn render_chat_to_text(state: &ChatState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| chat::render(state, frame))
        .expect("draw");
    format!("{}", terminal.backend())
}

/// Mirrors `screens_chat.rs`'s own `security_blocked_banner_is_always_shown_live_not_only_after_a_failed_attempt`:
/// the hard-stop banner is present on a plain render with no keys pressed at all, and stays present
/// after a batch of the adversarial sweep's own attempts — never only shown reactively after a
/// specifically-failed `Enter`. This is the "the user can see why" half of the deliverable, not just
/// "no effect dispatched".
#[test]
fn blocked_composer_visibly_shows_the_blocked_state_throughout_the_sweep() {
    let (state, _peer) = blocked_state();
    for (w, h) in [(80u16, 24u16), (40u16, 24u16)] {
        let text = render_chat_to_text(&state, w, h);
        assert!(text.contains("SENDS BLOCKED"), "at {w}x{h}:\n{text}");
        assert!(
            text.contains("safety number"),
            "the canonical trust.rs wording must appear verbatim, at {w}x{h}:\n{text}"
        );
    }

    // Now run a representative slice of the adversarial sweep against one live state and confirm the
    // banner is still exactly as present afterwards — recomputed fresh every render (chat.rs's own
    // module doc), never a stale snapshot from the last failed Enter.
    let (mut state, _peer) = blocked_state();
    for code in all_keycodes() {
        for modifiers in all_modifiers() {
            chat::handle_key(&mut state, KeyEvent::new(code, modifiers));
        }
    }
    let text = render_chat_to_text(&state, 80, 24);
    assert!(
        text.contains("SENDS BLOCKED"),
        "banner must still be live after a full sweep of attempts:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// Layer 3: App::update — the actual entry point a keypress flows through, proving no *global*
// hotkey (Ctrl+Q/Ctrl+R, app.rs's only two) or unwired event type routes around Screen::Chat's gate.
// ---------------------------------------------------------------------------

/// Same sweep one layer up: every key goes through the real `App::update`, with `Screen::Chat`
/// (already `Blocked`, via [`blocked_state`]) on top of a fresh `App`'s stack — never through
/// `chat::handle_key` directly. `app.rs`'s `handle_key` checks exactly two unconditional global
/// hotkeys (`Ctrl+Q` quit, `Ctrl+R` open Requests) *before* dispatching to whichever screen is
/// current, so both are included in the swept keyspace here (`'q'`/`'r'` are already members of
/// [`all_keycodes`], `CONTROL` of [`all_modifiers`]) rather than special-cased — this test proves
/// neither one is secretly a `SendMessage` bypass, not just that they exist.
#[test]
fn blocked_composer_reachable_only_via_screen_chat_no_app_level_key_ever_sends() {
    let mut checked = 0usize;
    for focus in all_chat_focuses() {
        for code in all_keycodes() {
            for modifiers in all_modifiers() {
                let (mut state, _peer) = blocked_state();
                state.focus = focus;
                let mut app = App::new();
                app.push_screen(Screen::Chat(Box::new(state)));

                let effects = app.update(AppEvent::Key(KeyEvent::new(code, modifiers)));
                checked += 1;

                assert_no_send_leaked(
                    &effects,
                    &format!("App::update focus={focus:?} code={code:?} mods={modifiers:?}"),
                );
            }
        }
    }
    // Exact-count guard, same rationale as the primary sweep above: this is a pure focus x keycode x
    // modifier sweep (no `StartMode` here — `App::new()` always starts a fresh `Screen::Chat` in
    // `ComposerMode::Normal`), so the expected total is the plain product of all three enumerations.
    let expected = all_chat_focuses().len() * all_keycodes().len() * all_modifiers().len();
    assert_eq!(
        checked, expected,
        "expected exactly all_chat_focuses() x all_keycodes() x all_modifiers() App-level cases"
    );
}

/// Names the two global hotkeys explicitly rather than leaving them implicit inside the big sweep
/// above: `Ctrl+Q` really does still quit (proving it fires at all, not that it's silently swallowed)
/// and `Ctrl+R` really does still open Requests — both while `Screen::Chat` is `Blocked` on top — and
/// neither ever emits `Effect::SendMessage` while doing so.
#[test]
fn named_global_hotkeys_never_send_from_a_blocked_chat_screen() {
    let (state, _peer) = blocked_state();
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(state)));
    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('q'),
        KeyModifiers::CONTROL,
    )));
    assert!(effects.is_empty());
    assert!(app.should_quit(), "Ctrl+Q must still actually quit");

    let (state, _peer) = blocked_state();
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(state)));
    let effects = app.update(AppEvent::Key(KeyEvent::new(
        KeyCode::Char('r'),
        KeyModifiers::CONTROL,
    )));
    assert!(effects.is_empty());
    assert!(
        matches!(app.current_screen(), Screen::Requests(_)),
        "Ctrl+R must still open Requests"
    );
}

/// `AppEvent::Paste` — the task's own "hidden action" phrasing — is, per `app.rs`'s own `update`
/// match arm, not wired to any screen at all today (`AppEvent::Tick | AppEvent::Resize(_, _) |
/// AppEvent::Paste(_) => Vec::new()`, checked *before* any screen ever sees it). Pins that fact so a
/// future task that *does* wire bracketed paste into the composer inherits a regression test that
/// immediately demands the same Blocked-gate discipline `handle_composer_key` already enforces for
/// ordinary typing, rather than silently gaining a bypass.
#[test]
fn paste_event_is_not_wired_to_any_screen_and_cannot_smuggle_composer_text() {
    let (state, _peer) = blocked_state();
    let mut app = App::new();
    app.push_screen(Screen::Chat(Box::new(state)));

    let effects = app.update(AppEvent::Paste("attacker-controlled paste payload".into()));
    assert!(effects.is_empty());
    match app.current_screen() {
        Screen::Chat(state) => assert!(
            state.composer.is_empty(),
            "paste must not reach the composer while this event type remains unwired"
        ),
        other => panic!("expected Screen::Chat, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Layer 4: the palette-command surface (crate::surface) — checked generically, not just "today's
// registry happens to be empty"
// ---------------------------------------------------------------------------

/// Every registered [`PaletteCommand`] whose action would resolve to `Effect::SendMessage` if
/// triggered — the generic check this file's palette-surface tests are built around, reusable by a
/// future task's own test suite once `PaletteRegistry::find_binding` actually gets wired into
/// `App::handle_key` (`surface.rs`'s own "orphaned wiring" doc note names task 4.25 as that owner).
/// Returns the offending commands' ids so a failing assertion names exactly which registration is the
/// problem.
fn palette_command_violations(registry: &PaletteRegistry) -> Vec<&'static str> {
    registry
        .iter()
        .filter(|command| {
            matches!(
                &command.action,
                PaletteAction::Effect(effect) if matches!(**effect, Effect::SendMessage(_))
            )
        })
        .map(|command| command.id)
        .collect()
}

/// Today's actual production surface: no non-test source in this crate ever calls
/// `register_palette_command`/`PaletteRegistry::register` (confirmed by reading `surface.rs`'s own
/// module doc — "T17's own chat renderer is 4.20's job, not this one's" — plus a repo-wide grep over
/// `apps/tui/src`; the only call sites outside `#[cfg(test)]` modules are the trait/type definitions
/// themselves). `App` itself has no `SurfaceRegistry`/`PaletteRegistry` field at all yet (confirmed by
/// reading `app.rs` in full: `Screen`'s only feature-registered variant is `Extension`, reached by
/// direct `Screen::Extension(Box::new(pane))` construction, never by a palette lookup) — so no key
/// event can reach a palette-triggered effect of any kind today, let alone a `SendMessage` one. This
/// is exactly why layer 3's `App::update` sweep above is already exhaustive proof by itself: it drives
/// the one real entry point a keypress flows through, and that entry point has no palette-dispatch
/// arm to route around `Screen::Chat`'s gate through in the first place. An empty registry trivially
/// satisfies [`palette_command_violations`]; the point of this test is documenting *why* it's empty as
/// a checked assertion (a future stray `register_palette_command` call anywhere reachable from `App`
/// would need its own test coverage the moment it starts resolving to `SendMessage`, not a change to
/// this test file).
#[test]
fn no_currently_registered_palette_command_can_resolve_to_send_message() {
    let empty_registry = PaletteRegistry::new();
    assert!(
        palette_command_violations(&empty_registry).is_empty(),
        "no palette command exists in this crate's production registrations today"
    );
}

/// Negative control: proves [`palette_command_violations`] is a real, load-bearing check rather than
/// one that would vacuously pass no matter what — the property the task's own "design the test to be
/// robust to future palette commands being added" instruction is asking for. A hypothetical future
/// command bound to a keybinding and wired to dispatch `Effect::SendMessage` directly (bypassing
/// `chat::dispatch_gated_send`'s gate check entirely, exactly the shape a careless task-4.25
/// integration could take) is caught by name.
#[test]
fn the_palette_command_checker_actually_catches_a_send_capable_command() {
    let mut registry = PaletteRegistry::new();
    registry.register(PaletteCommand {
        id: "hypothetical.chat.quick_send",
        name: "Quick send (hypothetical)",
        description: "a synthetic, never-actually-registered command standing in for a future \
                       ungated send path",
        keybinding: Some(KeyBinding::new(KeyCode::Char('s'), KeyModifiers::CONTROL)),
        action: PaletteAction::Effect(Box::new(Effect::SendMessage(SendMessageEffect {
            request: SendMessageRequest {
                peer_pubkey: [0x31u8; 32],
                peer_hint: "adversary.example".into(),
                body: "attacker-controlled body, dispatched with no gate check".into(),
            },
            outcome: None,
        }))),
    });

    assert_eq!(
        palette_command_violations(&registry),
        vec!["hypothetical.chat.quick_send"],
        "the checker must catch a send-capable palette command by id"
    );
}
