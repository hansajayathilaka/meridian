//! Terminal-constraint degradation (task 4.26) — `cargo nextest run -p meridian-tui --test
//! degradation`.
//!
//! Covers this task's own two named deliverables:
//! 1. Degradation wired through the render layer for the four screens `crate::theme`'s own module doc
//!    names as the retrofit target (`contacts`/`contact_detail`/`verify`/`chat`): `NO_COLOR`
//!    (`RenderCtx::color`) and `ui.unicode = false` (`RenderCtx::unicode`) both actually change what
//!    gets rendered, and the narrow-width contacts-collapse mechanism
//!    (`meridian_tui::theme::contacts_pane_layout`) is exercised against `contacts::render_with_ctx`'s
//!    own row formatting.
//! 2. Snapshot tests at narrow width and under a color-disabled `RenderCtx` (the equivalent of
//!    `NO_COLOR=1` — see the module-level note below on why these tests drive [`RenderCtx`] directly
//!    rather than setting the real process-wide `NO_COLOR` env var), plus a test proving this crate
//!    never renders to the primary screen buffer.
//!
//! Also covers this task's carry-forward fix from 4.22's review: at an extreme post-launch resize
//! shorter than the Verify screen's security banner needs, the banner is scrollable rather than
//! silently clipped — see `verify_screen_extreme_short_terminal_can_scroll_to_the_full_canonical_reason`.
//!
//! **Why these tests construct [`RenderCtx`] directly instead of setting `NO_COLOR` as a real env
//! var.** `std::env::set_var` mutates process-global state that every test binary's threads share
//! (Rust tests run in parallel by default); a test that sets `NO_COLOR` and unsets it again would race
//! every other concurrently-running test in this binary that doesn't expect the env to change under
//! it. `RenderCtx::resolve`'s own unit tests (`crate::theme`) already pin that `NO_COLOR`/`ui.theme`
//! map onto `RenderCtx::color` correctly in isolation; these tests instead exercise the render-layer
//! consumption of an already-resolved `RenderCtx`, which is the actual retrofit this task's
//! deliverable is about and doesn't require touching the environment at all.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;

use meridian_core::trust::{PinnedKey, SendGate, TrustState, TrustStore};

use meridian_tui::screens::chat::{self, ChatState};
use meridian_tui::screens::contact_detail::{self, ContactDetailState};
use meridian_tui::screens::contacts::{self, ContactEntry, ContactsState};
use meridian_tui::screens::verify::{self, VerifyState};
use meridian_tui::store::history::{
    Direction as MsgDirection, HistoryEntry, MessageState, CURRENT_VERSION,
};
use meridian_tui::theme::{contacts_pane_layout, ContactsPaneLayout, RenderCtx};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const COLOR_ON: RenderCtx = RenderCtx {
    color: true,
    unicode: true,
};
const COLOR_OFF: RenderCtx = RenderCtx {
    color: false,
    unicode: true,
};
const ASCII: RenderCtx = RenderCtx {
    color: true,
    unicode: false,
};
const UNICODE: RenderCtx = RenderCtx {
    color: true,
    unicode: true,
};

fn contact_entry(
    tag: u8,
    petname: Option<&str>,
    trust: TrustState,
    user_blocked: bool,
) -> ContactEntry {
    let pubkey = [tag; 32];
    ContactEntry {
        pubkey,
        id: format!("mrd1:contact-{tag:02x}@example.test"),
        hint: "example.test".into(),
        petname: petname.map(|p| p.to_string()),
        trust,
        user_blocked,
        pinned_key_history: vec![PinnedKey {
            pubkey,
            first_seen_unix: 1_000,
            last_seen_unix: 2_000,
        }],
        policy_override: None,
        added_at: 1_000,
        last_activity_at: 2_000,
        unread: 0,
    }
}

fn any_cell_has_fg(buffer: &ratatui::buffer::Buffer, color: Color) -> bool {
    buffer.content.iter().any(|c| c.fg == color)
}

fn contacts_buffer(
    state: &ContactsState,
    w: u16,
    h: u16,
    ctx: &RenderCtx,
) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| contacts::render_with_ctx(state, frame, ctx))
        .expect("draw");
    terminal.backend().buffer().clone()
}

fn contact_detail_buffer(
    state: &ContactDetailState,
    w: u16,
    h: u16,
    ctx: &RenderCtx,
) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| contact_detail::render_with_ctx(state, frame, ctx))
        .expect("draw");
    terminal.backend().buffer().clone()
}

fn chat_buffer(state: &ChatState, w: u16, h: u16, ctx: &RenderCtx) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| chat::render_with_ctx(state, frame, ctx))
        .expect("draw");
    terminal.backend().buffer().clone()
}

fn verify_buffer(state: &VerifyState, w: u16, h: u16, ctx: &RenderCtx) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal
        .draw(|frame| verify::render_with_ctx(state, frame, ctx))
        .expect("draw");
    terminal.backend().buffer().clone()
}

/// Reassembles the **inner** (border-stripped) rows into one continuous, space-joined string — same
/// technique `tests/screens_verify.rs::render_verify_to_text` uses, so a `Paragraph`'s word-wrap can
/// never silently break a substring check across a row boundary, and so ratatui's own border-drawing
/// glyphs (unrelated to this crate's own [`RenderCtx`]-driven glyphs) never leak into a substring
/// check.
fn flatten(buffer: &ratatui::buffer::Buffer) -> String {
    let area = buffer.area;
    let mut rows = Vec::new();
    for y in area.y.saturating_add(1)..area.y.saturating_add(area.height).saturating_sub(1) {
        let mut row = String::new();
        for x in area.x.saturating_add(1)..area.x.saturating_add(area.width).saturating_sub(1) {
            if let Some(cell) = buffer.cell((x, y)) {
                row.push_str(cell.symbol());
            }
        }
        rows.push(row.trim_end().to_string());
    }
    rows.join(" ")
}

fn history_entry(mid: &str, dir: MsgDirection, state: MessageState) -> HistoryEntry {
    HistoryEntry {
        v: CURRENT_VERSION,
        mid: mid.to_string(),
        dir,
        ts: 1_000,
        stream: "mrd.chat/1".to_string(),
        body: "hello".to_string(),
        state,
    }
}

fn blocked_fixture() -> ([u8; 32], TrustStore) {
    let peer_a = [2u8; 32];
    let peer_b = [3u8; 32];
    let mut trust = TrustStore::default();
    trust.observe(peer_a, "peer.example", 1_000);
    trust.mark_verified(&peer_a).expect("known contact");
    trust
        .observe_key_change(&peer_a, peer_b, "peer.example", 2_000)
        .expect("known contact, distinct new key");
    (peer_b, trust)
}

/// Same shape as [`blocked_fixture`], but the hint is a long, **space-free** token instead of the
/// short, fixed `"peer.example"` every other fixture in this crate uses — mirrors a hostile
/// wire-observed `Contact::hint` (bounded to 253 bytes, but never required to contain a space —
/// `apps/core/src/trust.rs::MAX_HINT_LEN`) presented at exactly the moment the peer's key changes:
/// the precise adversarial-interception scenario the Blocked banner exists to surface. Security-review
/// regression: `verify::wrapped_row_count`'s long-word handling once counted any single word longer
/// than the render width as exactly one row, undercounting the space `render_body` reserves for the
/// un-softenable Blocked banner text and silently clipping its tail (see
/// `verify_screen_extreme_short_terminal_with_a_hostile_long_hint_can_scroll_to_the_full_canonical_reason`
/// and
/// `verify_screen_ordinary_terminal_with_a_hostile_long_hint_never_garbles_or_silently_drops_the_banner`
/// below).
fn blocked_fixture_with_hostile_hint() -> ([u8; 32], TrustStore) {
    let peer_a = [22u8; 32];
    let peer_b = [23u8; 32];
    let hostile_hint = "x".repeat(120);
    let mut trust = TrustStore::default();
    trust.observe(peer_a, &hostile_hint, 1_000);
    trust.mark_verified(&peer_a).expect("known contact");
    trust
        .observe_key_change(&peer_a, peer_b, &hostile_hint, 2_000)
        .expect("known contact, distinct new key");
    (peer_b, trust)
}

/// Same shape as [`blocked_fixture_with_hostile_hint`], but the hostile hint is a long, space-free
/// run of a **double-width** character (a CJK ideograph, 3 UTF-8 bytes / 2 terminal cells each)
/// instead of ASCII `"x"` (1 byte / 1 cell each). Security-review regression, residual to the
/// long-word row-count fix above: `verify::wrapped_row_count`'s word-width measurement once counted
/// `word.chars().count()` (Unicode scalar values) rather than actual terminal display-cell width, so
/// any double-width character undercounted its own render footprint by up to 2x — silently clipping
/// the tail of the un-softenable Blocked banner even though the row-count math itself (`ceil(word_width
/// / width)`) was already correct, because the `word_width` it was fed was wrong. 84 repeats × 3
/// bytes = 252 bytes, matching `Contact::hint`'s 253-byte bound (`apps/core/src/trust.rs::MAX_HINT_LEN`)
/// and the reviewer's own reproduction.
fn blocked_fixture_with_wide_hostile_hint() -> ([u8; 32], TrustStore) {
    let peer_a = [24u8; 32];
    let peer_b = [25u8; 32];
    let hostile_hint = "\u{4e2d}".repeat(84);
    let mut trust = TrustStore::default();
    trust.observe(peer_a, &hostile_hint, 1_000);
    trust.mark_verified(&peer_a).expect("known contact");
    trust
        .observe_key_change(&peer_a, peer_b, &hostile_hint, 2_000)
        .expect("known contact, distinct new key");
    (peer_b, trust)
}

// ---------------------------------------------------------------------------
// NO_COLOR (deliverable 1 + 2: color-disabled snapshot)
// ---------------------------------------------------------------------------

#[test]
fn contacts_blocked_row_drops_explicit_color_but_keeps_glyph_and_label_when_no_color() {
    // Two entries: the first (index 0) is selected by default and rendered with the reversed
    // selection style, not `trust_style` — the blocked one under test must be the *second*, unselected
    // row so its own trust color is actually what's being asserted on, not the selection highlight.
    let state = ContactsState::new(vec![
        contact_entry(1, Some("alice"), TrustState::Pinned, false),
        contact_entry(9, Some("mallory"), TrustState::Blocked, false),
    ]);
    let on = contacts_buffer(&state, 80, 24, &COLOR_ON);
    let off = contacts_buffer(&state, 80, 24, &COLOR_OFF);
    assert!(
        any_cell_has_fg(&on, Color::Red),
        "color-on render should style the blocked row in red"
    );
    assert!(
        !any_cell_has_fg(&off, Color::Red),
        "NO_COLOR-equivalent render must never emit an explicit red foreground"
    );
    // The status must still be legible from text alone — glyph + label survive regardless of color.
    let off_text = flatten(&off);
    assert!(off_text.contains("blocked"));
}

#[test]
fn contact_detail_locally_blocked_line_drops_color_but_keeps_the_text_when_no_color() {
    let state =
        ContactDetailState::new(contact_entry(9, Some("mallory"), TrustState::Pinned, true));
    let on = contact_detail_buffer(&state, 80, 24, &COLOR_ON);
    let off = contact_detail_buffer(&state, 80, 24, &COLOR_OFF);
    assert!(any_cell_has_fg(&on, Color::Red));
    assert!(!any_cell_has_fg(&off, Color::Red));
    assert!(flatten(&off).contains("locally blocked"));
}

#[test]
fn verify_blocked_banner_drops_color_but_keeps_the_canonical_wording_when_no_color() {
    let (peer, trust) = blocked_fixture();
    let state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);
    let on = verify_buffer(&state, 100, 30, &COLOR_ON);
    let off = verify_buffer(&state, 100, 30, &COLOR_OFF);
    assert!(any_cell_has_fg(&on, Color::Red));
    assert!(!any_cell_has_fg(&off, Color::Red));
    let off_text = flatten(&off);
    assert!(off_text.contains("SENDS BLOCKED"));
}

#[test]
fn chat_failed_delivery_row_drops_color_but_keeps_the_distinct_glyph_when_no_color() {
    let mut trust = TrustStore::default();
    let peer = [7u8; 32];
    trust.observe(peer, "peer.example", 1_000);
    let entries = vec![history_entry("m1", MsgDirection::Out, MessageState::Failed)];
    let state = ChatState::new(peer, "peer.example".into(), trust, entries, 0);
    let on = chat_buffer(&state, 80, 24, &COLOR_ON);
    let off = chat_buffer(&state, 80, 24, &COLOR_OFF);
    assert!(
        any_cell_has_fg(&on, Color::Red),
        "a failed outbound send should be styled red when color is on"
    );
    assert!(
        !any_cell_has_fg(&off, Color::Red),
        "NO_COLOR-equivalent render must never emit an explicit red foreground for a failed send"
    );
    // The delivery marker itself (a distinct glyph, not a recolored checkmark) still distinguishes
    // failure from success regardless of color — status conveyed by glyph, never color alone.
    assert!(flatten(&off).contains('✗'));
}

// ---------------------------------------------------------------------------
// ui.unicode = false — ASCII glyph fallback (deliverable 1 + 2: narrow/ASCII snapshot)
// ---------------------------------------------------------------------------

#[test]
fn contacts_trust_glyphs_have_ascii_fallback_and_never_mix_unicode_in() {
    let state = ContactsState::new(vec![
        contact_entry(1, Some("alice"), TrustState::Pinned, false),
        contact_entry(2, Some("bob"), TrustState::PinnedKeyChanged, false),
        contact_entry(3, Some("carol"), TrustState::Blocked, false),
    ]);
    let unicode_text = flatten(&contacts_buffer(&state, 80, 24, &UNICODE));
    let ascii_text = flatten(&contacts_buffer(&state, 80, 24, &ASCII));

    assert!(unicode_text.contains('●'));
    assert!(unicode_text.contains('▲'));
    assert!(unicode_text.contains('✕'));

    assert!(!ascii_text.contains('●'));
    assert!(!ascii_text.contains('▲'));
    assert!(!ascii_text.contains('✕'));
    // Labels are what actually carry the meaning once the glyph degrades — still present.
    assert!(ascii_text.contains("pinned"));
    assert!(ascii_text.contains("key changed"));
    assert!(ascii_text.contains("blocked"));
}

#[test]
fn contact_detail_trust_glyph_has_ascii_fallback() {
    let state = ContactDetailState::new(contact_entry(
        5,
        Some("carol"),
        TrustState::PinnedKeyChanged,
        false,
    ));
    let unicode_text = flatten(&contact_detail_buffer(&state, 80, 24, &UNICODE));
    let ascii_text = flatten(&contact_detail_buffer(&state, 80, 24, &ASCII));
    assert!(unicode_text.contains('▲'));
    assert!(!ascii_text.contains('▲'));
    assert!(ascii_text.contains("key changed"));
}

#[test]
fn chat_delivery_markers_have_ascii_fallback_for_every_terminal_state() {
    let mut trust = TrustStore::default();
    let peer = [7u8; 32];
    trust.observe(peer, "peer.example", 1_000);
    let entries = vec![
        history_entry("sent", MsgDirection::Out, MessageState::Sent),
        history_entry("delivered", MsgDirection::Out, MessageState::Delivered),
        history_entry("failed", MsgDirection::Out, MessageState::Failed),
    ];
    let state = ChatState::new(peer, "peer.example".into(), trust, entries, 0);

    let unicode_text = flatten(&chat_buffer(&state, 80, 24, &UNICODE));
    let ascii_text = flatten(&chat_buffer(&state, 80, 24, &ASCII));

    assert!(unicode_text.contains('✓'));
    assert!(unicode_text.contains('✗'));
    assert!(!ascii_text.contains('✓'));
    assert!(!ascii_text.contains('✗'));
    // The ASCII fallback still distinguishes every state from every other by symbol, not just color.
    assert!(ascii_text.contains(" v"));
    assert!(ascii_text.contains("vv"));
    assert!(ascii_text.contains(" x"));
}

#[test]
fn chat_unread_divider_has_an_ascii_fallback() {
    let mut trust = TrustStore::default();
    let peer = [7u8; 32];
    trust.observe(peer, "peer.example", 1_000);
    let entries = vec![
        history_entry("a", MsgDirection::In, MessageState::Received),
        history_entry("b", MsgDirection::In, MessageState::Received),
    ];
    let state = ChatState::new(peer, "peer.example".into(), trust, entries, 1);

    let unicode_text = flatten(&chat_buffer(&state, 80, 24, &UNICODE));
    let ascii_text = flatten(&chat_buffer(&state, 80, 24, &ASCII));
    assert!(unicode_text.contains("── unread ──"));
    assert!(!ascii_text.contains('─'));
    assert!(ascii_text.contains("-- unread --"));
}

// ---------------------------------------------------------------------------
// Narrow-width contacts collapse mechanism (deliverable 4)
// ---------------------------------------------------------------------------

#[test]
fn contacts_pane_layout_is_side_by_side_at_80_and_overlay_below_it() {
    assert!(matches!(
        contacts_pane_layout(79),
        ContactsPaneLayout::Overlay
    ));
    assert!(matches!(
        contacts_pane_layout(80),
        ContactsPaneLayout::SideBySide
    ));
}

/// Applies [`contacts_pane_layout`] against `contacts::render_with_ctx`'s own row formatting: a
/// side-by-side (>=80 columns) row uses the fixed-width padded columns established since task 4.19; a
/// below-80-columns row uses the denser, unpadded format — both always keep glyph + label +
/// fingerprint, never dropping the security-relevant fingerprint at a narrow width (tui-client.md §6
/// rule 2).
#[test]
fn contacts_row_formatting_actually_changes_below_the_80_column_threshold() {
    let state = ContactsState::new(vec![contact_entry(
        4,
        Some("dave-the-overlay-test-name"),
        TrustState::Pinned,
        false,
    )]);
    let wide = flatten(&contacts_buffer(&state, 100, 24, &UNICODE));
    let narrow = flatten(&contacts_buffer(&state, 40, 24, &UNICODE));

    // Side-by-side (>=80 cols): fixed-width padded columns, no " - " connector between name/label.
    assert!(!wide.contains("dave-the-overlay-test-name - pinned"));
    // Overlay (<80 cols): the denser, unpadded connector format.
    assert!(narrow.contains("dave-the-overlay-test-name - pinned"));

    // Both keep the petname, trust label, and fingerprint — nothing dropped at the narrow width.
    for text in [&wide, &narrow] {
        assert!(text.contains("dave-the-overlay-test-name"));
        assert!(text.contains("pinned"));
        assert!(text.contains(&contacts::short_pubkey(&[4u8; 32])));
    }
}

// ---------------------------------------------------------------------------
// Verify screen: extreme post-launch resize (4.22 review carry-forward)
// ---------------------------------------------------------------------------

#[test]
fn verify_screen_extreme_short_terminal_gives_the_banner_the_entire_area() {
    let (peer, trust) = blocked_fixture();
    let state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);
    // Shorter than the banner's own wrapped height at this width — the number/QR pane must give way
    // entirely rather than squeezing the banner (see `verify::render_body`'s own doc comment).
    // "compare out-of-band" is unique to `render_number_and_qr`'s own instructional text — unlike
    // "safety number", it never appears inside the banner's own reason string, which itself begins
    // "The safety number for ... has changed" and would otherwise produce a false positive here.
    let text = flatten(&verify_buffer(&state, 40, 5, &UNICODE));
    assert!(
        !text.contains("compare out-of-band"),
        "the number/QR pane must not render at all once the banner alone needs the whole area; \
         got: {text:?}"
    );
}

#[test]
fn verify_screen_extreme_short_terminal_can_scroll_to_the_full_canonical_reason() {
    let (peer, trust) = blocked_fixture();
    let reason = match trust.can_send(&peer) {
        SendGate::Blocked(reason) => reason,
        other => panic!("expected Blocked, got {other:?}"),
    };
    let mut state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);

    let width = 40;
    let height = 8;
    let words: Vec<&str> = reason.split_whitespace().collect();
    assert!(
        words.len() > 8,
        "fixture's own reason string must be long enough to actually overflow at width 40 for this \
         test to mean anything"
    );
    let prefix = words[..3].join(" ");
    let suffix = words[words.len() - 3..].join(" ");

    let initial = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(
        initial.contains(&prefix),
        "the banner's head must be visible before any scrolling; got: {initial:?}"
    );
    assert!(
        !initial.contains(&suffix),
        "the tail must NOT already be visible at scroll 0 — otherwise this test isn't exercising \
         the overflow case at all; got: {initial:?}"
    );

    // Scroll down repeatedly (PageDown), mirroring a user paging through the banner — far more than
    // enough steps to reach the clamped maximum scroll for this fixture/width.
    for _ in 0..30 {
        verify::handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
    }
    let scrolled = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(
        scrolled.contains(&suffix),
        "the tail of the canonical reason must be reachable by scrolling, never silently and \
         permanently clipped; got: {scrolled:?}"
    );

    // Scrolling further must not panic or scroll past the end (already-clamped at render time).
    for _ in 0..10 {
        verify::handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
    }
    let clamped = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(clamped.contains(&suffix));

    // Scrolling back up returns to the head. The stored `banner_scroll` counter isn't itself
    // clamped to the render-time maximum (only re-clamped at render — see `apply_banner_scroll`'s own
    // doc comment), so after 40 PageDowns above (delta 10 each) this needs comfortably more than 40
    // PageUps to actually unwind back to (or below) zero, not just the `30` used to scroll down.
    for _ in 0..60 {
        verify::handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        );
    }
    let back = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(back.contains(&prefix));
}

/// Security-review regression (reviewer-reproduced failure mode #1): with the pre-fix
/// `wrapped_row_count`, a single space-free word longer than the render width counted as exactly one
/// row instead of `ceil(word_len / width)`, so `wrapped_height` undercounted the banner's real
/// height. At an extreme resize, that undercount made `max_scroll` (computed from the undercounted
/// height) too small — `PageDown` reached its ceiling well before the canonical text's real tail ever
/// scrolled into view. Same shape as
/// `verify_screen_extreme_short_terminal_can_scroll_to_the_full_canonical_reason` above, but against
/// [`blocked_fixture_with_hostile_hint`]'s long, space-free hint instead of the short fixed
/// `"peer.example"` label every other fixture uses — the defect only reproduces once the interpolated
/// `label` itself is a single word wider than the render width.
#[test]
fn verify_screen_extreme_short_terminal_with_a_hostile_long_hint_can_scroll_to_the_full_canonical_reason(
) {
    let (peer, trust) = blocked_fixture_with_hostile_hint();
    let reason = match trust.can_send(&peer) {
        SendGate::Blocked(reason) => reason,
        other => panic!("expected Blocked, got {other:?}"),
    };
    let mut state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);

    let width = 40;
    let height = 8;
    // The reason's tail — "there is no way to send without doing one of those." — is fixed,
    // ordinary-word text (not part of the hostile label itself), so it wraps normally and is a
    // reliable marker for "the canonical text's real end became visible".
    let words: Vec<&str> = reason.split_whitespace().collect();
    let suffix = words[words.len() - 6..].join(" ");
    assert!(
        reason.contains(&suffix),
        "sanity: suffix must actually be a substring of the real reason"
    );

    let initial = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(
        !initial.contains(&suffix),
        "the tail must NOT already be visible at scroll 0 — otherwise this test isn't exercising \
         the overflow case at all; got: {initial:?}"
    );

    for _ in 0..60 {
        verify::handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
    }
    let scrolled = flatten(&verify_buffer(&state, width, height, &UNICODE));
    assert!(
        scrolled.contains(&suffix),
        "the tail of the canonical reason must be reachable by scrolling even when the interpolated \
         label is itself one long, space-free word wider than the render width — never silently and \
         permanently clipped; got: {scrolled:?}"
    );
}

/// Security-review regression (reviewer-reproduced failure mode #2 — the more severe one: this isn't
/// even an extreme resize). With the pre-fix `wrapped_row_count`, the undercount was large enough
/// that even at an entirely ordinary terminal size, `render_body` never entered the
/// overflow/scroll branch at all: it sized the banner's `Constraint::Length` region too small via the
/// undercounted `wrapped_height`, `Paragraph`'s own real (correct) word-wrap then rendered past that
/// region's bottom edge and got silently clipped by `ratatui` — the canonical tail was not present
/// anywhere on screen, and no scroll hint was even offered (since `render_body` believed nothing
/// overflowed). This test asserts the full canonical reason is reachable one way or the other:
/// present immediately if `render_body` (correctly, post-fix) sized the banner region to actually fit
/// it, or reachable by scrolling if it (correctly) decided the banner needed the whole area instead.
/// Either is an acceptable *design* outcome; what must never happen again is the tail being
/// unreachable by both.
#[test]
fn verify_screen_ordinary_terminal_with_a_hostile_long_hint_never_garbles_or_silently_drops_the_banner(
) {
    let (peer, trust) = blocked_fixture_with_hostile_hint();
    let reason = match trust.can_send(&peer) {
        SendGate::Blocked(reason) => reason,
        other => panic!("expected Blocked, got {other:?}"),
    };
    let mut state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);

    for (width, height) in [(40u16, 30u16), (80u16, 24u16)] {
        let words: Vec<&str> = reason.split_whitespace().collect();
        let suffix = words[words.len() - 6..].join(" ");

        let initial = flatten(&verify_buffer(&state, width, height, &UNICODE));
        if initial.contains(&suffix) {
            // The non-overflow branch fit everything correctly — the full text is already there.
            continue;
        }

        // Otherwise this must be the overflow/scroll branch, and the tail must be reachable by
        // scrolling, exactly like the extreme-resize case — not silently and permanently absent.
        state.banner_scroll = 0;
        for _ in 0..60 {
            verify::handle_key(
                &mut state,
                KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            );
        }
        let scrolled = flatten(&verify_buffer(&state, width, height, &UNICODE));
        assert!(
            scrolled.contains(&suffix),
            "at an ordinary {width}x{height} terminal, the full canonical reason must be reachable \
             (either directly or by scrolling) even with a hostile long, space-free hint — never \
             silently absent from the render entirely; got: {scrolled:?}"
        );
        state.banner_scroll = 0;
    }
}

/// Security-review regression (residual finding on the fix above): even after `wrapped_row_count`'s
/// row-count math was corrected to `ceil(word_width / width)`, `word_width` itself was measured as a
/// `char` count rather than actual terminal display-cell width — so a hostile hint made of
/// double-width characters (see [`blocked_fixture_with_wide_hostile_hint`]) still undercounted the
/// banner's real render height by up to 2x, reproducing the exact same "silently absent, no scroll
/// hint offered" failure mode `verify_screen_ordinary_terminal_with_a_hostile_long_hint_never_garbles_or_silently_drops_the_banner`
/// closes for ASCII — just via a different character class. Same shape as that test, but with the
/// wide-character fixture, and pinned to a single ordinary (non-extreme) 40x30 terminal, matching the
/// reviewer's own reproduction exactly.
#[test]
fn verify_screen_ordinary_terminal_with_a_wide_hostile_hint_never_garbles_or_silently_drops_the_banner(
) {
    let (peer, trust) = blocked_fixture_with_wide_hostile_hint();
    let reason = match trust.can_send(&peer) {
        SendGate::Blocked(reason) => reason,
        other => panic!("expected Blocked, got {other:?}"),
    };
    let mut state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);

    let (width, height) = (40u16, 30u16);
    let words: Vec<&str> = reason.split_whitespace().collect();
    let suffix = words[words.len() - 6..].join(" ");

    let initial = flatten(&verify_buffer(&state, width, height, &UNICODE));
    if !initial.contains(&suffix) {
        // Not already fully visible — the overflow/scroll branch must have engaged, and the tail
        // must be reachable by scrolling, exactly like the ASCII-hint regression tests above.
        for _ in 0..60 {
            verify::handle_key(
                &mut state,
                KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            );
        }
        let scrolled = flatten(&verify_buffer(&state, width, height, &UNICODE));
        assert!(
            scrolled.contains(&suffix),
            "at an ordinary {width}x{height} terminal, the full canonical reason must be reachable \
             (either directly or by scrolling) even with a hostile long, space-free, double-width \
             hint — never silently and permanently clipped; got: {scrolled:?}"
        );
        state.banner_scroll = 0;
    }
}

#[test]
fn verify_screen_footer_mentions_scrolling_only_while_the_banner_is_actually_overflowing() {
    let (peer, trust) = blocked_fixture();
    let state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);

    let tall = flatten(&verify_buffer(&state, 100, 30, &UNICODE));
    assert!(!tall.to_lowercase().contains("scroll banner"));

    // Wide enough that the (long) footer hint itself isn't clipped by the render width, short enough
    // that the banner still overflows the available height.
    let short = flatten(&verify_buffer(&state, 100, 6, &UNICODE));
    assert!(short.to_lowercase().contains("scroll banner"));
}

#[test]
fn verify_screen_scroll_keys_never_reach_confirm_mode_from_the_default_view() {
    // Scrolling is only intercepted from View/Error — Confirm's own exhaustive "no dismiss without
    // verify" sweep (tests/screens_verify.rs) already pins that y/Y is the only key that ever calls
    // `TrustStore::mark_verified`; this just confirms scroll keys don't even change `state.mode`
    // while in View, so they can never accidentally short-circuit entering Confirm either.
    let (peer, trust) = blocked_fixture();
    let mut state = VerifyState::new([1u8; 32], peer, "peer.example".into(), trust);
    let (effects, exit) =
        verify::handle_key(&mut state, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert!(effects.is_empty());
    assert!(!exit);
    assert!(matches!(state.mode, verify::VerifyMode::View));
}

// ---------------------------------------------------------------------------
// Alternate-screen-always
// ---------------------------------------------------------------------------

/// Recursively collects every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// **Alternate-screen-always, checked across a representative sweep of this crate's actual render
/// call sites** — not just `crate::terminal::TerminalGuard`'s own restore-on-drop behavior (already
/// covered by `tests/terminal_guard.rs`). This is a distinct property: that *rendering itself* never
/// targets the primary screen buffer. Every file under `src/` except `terminal.rs` (the one place
/// alternate-screen control legitimately lives) and `lib.rs` (whose `run()` legitimately constructs
/// the real backend — checked separately by
/// `run_enters_the_alternate_screen_before_constructing_the_render_backend` below, since forbidding
/// `io::stdout` there entirely would also forbid the backend construction the invariant is *about*)
/// must never reference the raw crossterm alternate-screen/stdout primitives directly — every screen
/// in this crate only ever builds a `ratatui::Frame`, never touches the terminal itself.
#[test]
fn no_render_related_source_file_other_than_terminal_rs_touches_the_primary_buffer_directly() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(
        files.len() > 10,
        "sanity: expected a representative sweep of this crate's actual source files, found only \
         {}",
        files.len()
    );

    let forbidden = [
        "EnterAlternateScreen",
        "LeaveAlternateScreen",
        "crossterm::execute",
        "io::stdout",
        "io::stderr",
    ];
    let mut violations = Vec::new();
    for path in &files {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == "terminal.rs" || file_name == "lib.rs" {
            continue;
        }
        let contents = std::fs::read_to_string(path).expect("read source file");
        for token in forbidden {
            if contents.contains(token) {
                violations.push(format!("{}: contains {token:?}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "found direct primary-buffer/terminal access outside terminal.rs: {violations:#?}"
    );
}

/// A static-ordering check on `lib.rs::run` itself: the alternate screen must be entered
/// (`TerminalGuard::install`) strictly before the render backend (and therefore any
/// `Terminal::draw`/render call) is ever constructed. Complements the sweep above, which only proves
/// *no other file* touches the primary buffer — this proves `run()`'s own, legitimate
/// `CrosstermBackend::new(io::stdout())` call happens only after the switch to the alternate screen.
#[test]
fn run_enters_the_alternate_screen_before_constructing_the_render_backend() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib_rs = std::fs::read_to_string(manifest_dir.join("src/lib.rs")).expect("read src/lib.rs");
    let guard_pos = lib_rs
        .find("TerminalGuard::install")
        .expect("run() must call TerminalGuard::install");
    let backend_pos = lib_rs
        .find("CrosstermBackend::new")
        .expect("run() must construct a CrosstermBackend");
    assert!(
        guard_pos < backend_pos,
        "the alternate screen must be entered before the render backend is ever constructed — \
         found TerminalGuard::install at byte {guard_pos}, CrosstermBackend::new at byte {backend_pos}"
    );
}

// A dynamic `RecordingOps`-backed check ("render every screen while the guard reports the alternate
// screen active") was deliberately **not** added here, even though it would read naturally alongside
// the two static checks above. `crate::terminal`'s own module doc flags exactly why:
// `TerminalGuard::install` installs a **process-global** panic hook, and this test binary runs many
// `#[test]`s concurrently by default — any unrelated assertion failure (a panic) anywhere else in this
// same binary while such a test's guard is alive would trip *this* test's hook instead of the failing
// test's own, spuriously toggling this test's `RecordingOps` and reporting a false "left the alternate
// screen" here. `tests/terminal_guard.rs` already owns the one legitimate dynamic exercise of this
// mechanism (a single `#[test]` per binary, immune to this race by construction); duplicating it here
// would only add a flaky, non-deterministic test for no additional real coverage — the two static
// checks above already prove both halves of "alternate-screen-always" (no screen touches the primary
// buffer directly; `run()` enters the alternate screen before ever constructing the thing that could).
