//! Terminal-constraint degradation (task 4.26): resolves `NO_COLOR` (the env var,
//! <https://no-color.org>) and [`crate::config::TuiConfig`]'s `[ui]` fields (`unicode`, `theme`) into
//! a small, render-time API every screen can consume — [`RenderCtx`] plus [`color_or_none`]/[`glyph`].
//! Centralizing this mapping here (rather than each screen re-deriving its own ASCII/no-color
//! fallback) is what makes "ASCII glyph fallback" and "status conveyed by glyph + label, never color
//! alone" systematic properties instead of scattered per-screen discipline.
//!
//! ## Where the env/config read actually happens
//! `NO_COLOR`/[`crate::config::TuiConfig`] are resolved exactly **once per frame**, inside
//! [`crate::app::App::render`] (this crate's one true "natural boundary" — the single place
//! `terminal.draw` calls into every frame, mirroring `docs/architecture/tui-client.md §4`'s Elm-loop
//! diagram) — never as scattered ad hoc `std::env::var` calls inside a screen's own nested render
//! logic. Every screen-level `render_with_ctx` function below takes the already-resolved [`RenderCtx`]
//! as a plain argument and stays exactly as pure (no I/O, no `.await`) as every other `render` in this
//! crate. The bare `render(state, frame)` entry point each retrofitted screen keeps for backward
//! compatibility (existing tests, any call site that doesn't have a `RenderCtx` handy) delegates to
//! `render_with_ctx` with [`RenderCtx::default`] — the same "unicode on, color on" behavior every
//! screen already had before this task.
//!
//! ## Retrofit scope — which screens consume this, and which don't yet
//! [`crate::screens::contacts`], [`crate::screens::contact_detail`], [`crate::screens::verify`], and
//! [`crate::screens::chat`] are the only screens in this crate that render a
//! [`meridian_core::trust::TrustState`] glyph or a message delivery-state glyph — grep confirms it:
//! every other screen (`onboarding`, `unlock`, `requests`, `settings`, `help`, `palette`,
//! `diagnostics`, and the standalone `crate::statusbar` component) either renders no trust/delivery
//! glyph at all, or (`statusbar`) already uses plain-ASCII glyphs (`o`/`~`/`*`) paired with a label and
//! isn't wired into any live screen yet (see its own module doc). Those four are therefore this task's
//! full, exhaustive retrofit target for [`GlyphKind`]/[`color_or_none`] — not a sampled subset.
//!
//! **Deliberately NOT retrofitted this pass, documented rather than silently left:** the decorative
//! em-dash (`—`) and middle-dot (`·`) punctuation used as prose/footer-hint separators across every
//! screen in this crate (including the four retrofitted above), and the single-character ellipsis
//! (`…`) [`crate::screens::contacts::short_pubkey`] uses to mark key-fingerprint truncation. These are
//! typographic punctuation, not status-conveying glyphs: unlike a trust/delivery glyph, losing them on
//! a true ASCII-only terminal is a cosmetic rendering artifact (most terminals substitute a box or
//! `?`), not a loss of the "glyph + label, never color alone" security property this task is about.
//! Converting every occurrence crate-wide would be a much larger, purely-cosmetic typography pass out
//! of proportion to this task's named scope ("trust-state glyphs.../delivery-state indicators.../any
//! box-drawing/decoration") — flagged here explicitly per this task's own instruction not to leave
//! screens silently half-done with no note, rather than expanded into scope creep.
//!
//! ## Narrow-width contacts collapse (deliverable 4)
//! [`contacts_pane_layout`] is the width-only decision this task's own scope note describes: a pure
//! function, not itself wired into a combined contacts+conversation "Main" screen (none exists yet —
//! see `crate::screens::contacts`'s own module doc and this task's own scope note for why), but applied
//! directly against [`crate::screens::contacts::render_with_ctx`]'s own narrow-width row formatting so
//! the mechanism is real and tested today, ready for whatever future task builds that combined layout
//! to reuse unchanged.

use std::env;

use ratatui::style::Color;

use crate::config::{Theme, TuiConfig};

// ---------------------------------------------------------------------------
// RenderCtx
// ---------------------------------------------------------------------------

/// The render-time degradation inputs every retrofitted screen needs — see the module doc for where
/// this gets resolved and how it flows down to individual screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderCtx {
    /// Whether ANSI color may be emitted at all. `false` when `NO_COLOR` is set (any value, per
    /// <https://no-color.org>'s own convention: "when present... regardless of its value") or when
    /// `ui.theme` is explicitly [`Theme::Mono`] — both are ways a user asks for a colorless terminal,
    /// so both feed the single switch every styled `Span` in a retrofitted screen consults via
    /// [`color_or_none`].
    pub color: bool,
    /// Whether unicode glyphs may be used — [`crate::config::UiConfig::unicode`], verbatim.
    pub unicode: bool,
}

impl Default for RenderCtx {
    /// Matches every screen's pre-existing hardcoded behavior before this task ([`TuiConfig::default`],
    /// no `NO_COLOR`) — the fallback each retrofitted screen's bare `render()` entry point uses until
    /// [`crate::app::App::render`] hands it a freshly resolved one.
    fn default() -> Self {
        Self {
            color: true,
            unicode: true,
        }
    }
}

impl RenderCtx {
    /// The pure half of resolution — independently testable without touching real process
    /// environment. [`Self::from_env`] is the real entry point, supplying `no_color_env` from
    /// `std::env::var`.
    pub fn resolve(config: &TuiConfig, no_color_env: bool) -> Self {
        let mono = matches!(config.ui.theme, Theme::Mono);
        Self {
            color: !(no_color_env || mono),
            unicode: config.ui.unicode,
        }
    }

    /// Resolves a [`RenderCtx`] against the real process environment — see the module doc for why
    /// this is called exactly once per frame, from [`crate::app::App::render`], never from inside a
    /// screen's own nested render logic.
    pub fn from_env(config: &TuiConfig) -> Self {
        Self::resolve(config, env::var("NO_COLOR").is_ok())
    }
}

/// `Some(color)` when [`RenderCtx::color`] allows it, `None` otherwise — the one place a retrofitted
/// screen decides whether a `Style` gets an explicit foreground color at all. Never returns a
/// substitute/dimmed color: when color is off, the caller's own glyph + label text is what carries the
/// distinction (tui-client.md §3 / §6 rule 2: "never color alone"), not a monochrome approximation of
/// the original hue.
pub fn color_or_none(color: Color, ctx: &RenderCtx) -> Option<Color> {
    ctx.color.then_some(color)
}

// ---------------------------------------------------------------------------
// Glyphs
// ---------------------------------------------------------------------------

/// Which status glyph is being rendered — see [`glyph`] for the unicode/ASCII mapping. Deliberately a
/// small, closed enum (mirrors [`crate::config::Theme`]'s own "real enum, not a bare string" choice)
/// rather than passing raw unicode/ASCII strings around at each call site, so the full mapping lives in
/// exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlyphKind {
    /// [`meridian_core::trust::TrustState::New`].
    TrustNew,
    /// [`meridian_core::trust::TrustState::Pinned`] and `Verified` share one glyph (matches
    /// tui-client.md §2's mockup — the adjacent label is what disambiguates, exactly what "glyph +
    /// label, never color alone" requires).
    TrustPinnedOrVerified,
    /// [`meridian_core::trust::TrustState::PinnedKeyChanged`] — the acknowledgeable warning.
    TrustKeyChanged,
    /// [`meridian_core::trust::TrustState::Blocked`] — the un-softenable hard stop.
    TrustBlocked,
    /// [`crate::store::history::MessageState::Sent`].
    DeliverySent,
    /// [`crate::store::history::MessageState::Delivered`].
    DeliveryDelivered,
    /// [`crate::store::history::MessageState::Failed`].
    DeliveryFailed,
    /// The `↑`/`↓` scroll-navigation hint used in `crate::screens::contacts`'s footer hint.
    ScrollHint,
    /// The single `↑` "recall last sent message" hint in `crate::screens::chat`'s composer footer.
    RecallUp,
    /// `crate::screens::chat`'s "── unread ──" transcript divider — genuine box-drawing, not prose
    /// punctuation (see the module doc's "deliberately NOT retrofitted" section for the distinction).
    UnreadDivider,
}

/// The unicode glyph (`ui.unicode = true`, task 4.14's default) or its ASCII fallback
/// (`ui.unicode = false` — a first-class path, not a degraded afterthought, per this task's own scope)
/// for `kind`.
pub fn glyph(kind: GlyphKind, ctx: &RenderCtx) -> &'static str {
    match (kind, ctx.unicode) {
        (GlyphKind::TrustNew, true) => "○",
        (GlyphKind::TrustNew, false) => "o",
        (GlyphKind::TrustPinnedOrVerified, true) => "●",
        (GlyphKind::TrustPinnedOrVerified, false) => "*",
        (GlyphKind::TrustKeyChanged, true) => "▲",
        (GlyphKind::TrustKeyChanged, false) => "!",
        (GlyphKind::TrustBlocked, true) => "✕",
        (GlyphKind::TrustBlocked, false) => "x",
        (GlyphKind::DeliverySent, true) => "✓",
        (GlyphKind::DeliverySent, false) => "v",
        (GlyphKind::DeliveryDelivered, true) => "✓✓",
        (GlyphKind::DeliveryDelivered, false) => "vv",
        (GlyphKind::DeliveryFailed, true) => "✗",
        (GlyphKind::DeliveryFailed, false) => "x",
        (GlyphKind::ScrollHint, true) => "↑↓",
        (GlyphKind::ScrollHint, false) => "Up/Down",
        (GlyphKind::RecallUp, true) => "↑",
        (GlyphKind::RecallUp, false) => "Up",
        (GlyphKind::UnreadDivider, true) => "── unread ──",
        (GlyphKind::UnreadDivider, false) => "-- unread --",
    }
}

// ---------------------------------------------------------------------------
// Narrow-width contacts collapse (deliverable 4)
// ---------------------------------------------------------------------------

/// Below-80-columns, the contacts pane collapses into a toggled overlay rather than sitting
/// side-by-side with (and truncating) the conversation pane — tui-client.md §3. Pure, width-only — see
/// the module doc for why this has no combined layout to integrate into yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactsPaneLayout {
    /// Enough room to sit beside a conversation pane (once one exists) without either being
    /// squeezed — the aligned, fixed-width row format this crate has used since task 4.19.
    SideBySide,
    /// Not enough room for both panes side by side — a denser, unpadded row format more suited to
    /// being toggled on top of the conversation as an overlay.
    Overlay,
}

/// The 80-column threshold this task's own scope note names verbatim ("below-80-columns").
pub const CONTACTS_OVERLAY_WIDTH_THRESHOLD: u16 = 80;

/// Decides [`ContactsPaneLayout`] from a terminal width alone.
pub fn contacts_pane_layout(width: u16) -> ContactsPaneLayout {
    if width < CONTACTS_OVERLAY_WIDTH_THRESHOLD {
        ContactsPaneLayout::Overlay
    } else {
        ContactsPaneLayout::SideBySide
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ctx_matches_pre_task_behavior() {
        let ctx = RenderCtx::default();
        assert!(ctx.color);
        assert!(ctx.unicode);
    }

    #[test]
    fn resolve_honors_no_color_env_regardless_of_theme() {
        let config = TuiConfig::default();
        assert!(RenderCtx::resolve(&config, false).color);
        assert!(!RenderCtx::resolve(&config, true).color);
    }

    #[test]
    fn resolve_honors_mono_theme_even_without_no_color_env() {
        let mut config = TuiConfig::default();
        config.ui.theme = Theme::Mono;
        assert!(!RenderCtx::resolve(&config, false).color);
    }

    #[test]
    fn resolve_honors_ui_unicode_verbatim() {
        let mut config = TuiConfig::default();
        assert!(RenderCtx::resolve(&config, false).unicode);
        config.ui.unicode = false;
        assert!(!RenderCtx::resolve(&config, false).unicode);
    }

    #[test]
    fn color_or_none_reflects_ctx_color() {
        let on = RenderCtx {
            color: true,
            unicode: true,
        };
        let off = RenderCtx {
            color: false,
            unicode: true,
        };
        assert_eq!(color_or_none(Color::Red, &on), Some(Color::Red));
        assert_eq!(color_or_none(Color::Red, &off), None);
    }

    #[test]
    fn glyph_has_a_distinct_ascii_fallback_for_every_kind() {
        let unicode = RenderCtx {
            color: true,
            unicode: true,
        };
        let ascii = RenderCtx {
            color: true,
            unicode: false,
        };
        for kind in [
            GlyphKind::TrustNew,
            GlyphKind::TrustPinnedOrVerified,
            GlyphKind::TrustKeyChanged,
            GlyphKind::TrustBlocked,
            GlyphKind::DeliverySent,
            GlyphKind::DeliveryDelivered,
            GlyphKind::DeliveryFailed,
            GlyphKind::ScrollHint,
            GlyphKind::RecallUp,
            GlyphKind::UnreadDivider,
        ] {
            let u = glyph(kind, &unicode);
            let a = glyph(kind, &ascii);
            assert!(
                !u.is_ascii(),
                "unicode variant for {kind:?} should actually contain non-ASCII glyphs, got {u:?}"
            );
            assert!(
                a.is_ascii(),
                "ASCII fallback for {kind:?} must be pure ASCII, got {a:?}"
            );
            assert_ne!(u, a, "{kind:?} must have distinct unicode/ASCII forms");
        }
    }

    #[test]
    fn contacts_pane_layout_threshold_is_exactly_80() {
        assert!(matches!(
            contacts_pane_layout(79),
            ContactsPaneLayout::Overlay
        ));
        assert!(matches!(
            contacts_pane_layout(80),
            ContactsPaneLayout::SideBySide
        ));
        assert!(matches!(
            contacts_pane_layout(200),
            ContactsPaneLayout::SideBySide
        ));
    }
}
