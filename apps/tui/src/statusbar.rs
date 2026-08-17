//! A persistent status-bar component (task 4.25, deliverable 4): connection state, transport path,
//! and relay policy — the rightmost strip of
//! [tui-client.md §2](../../../docs/architecture/tui-client.md#2-information-architecture)'s mockup
//! (`^K palette ^N contact ^V verify F1 help │ P2P direct │ policy: direct │ ▲2`).
//!
//! ## Placement judgment call: standalone component, not wired into every screen's layout
//! This crate has no "Main" screen yet — the central three-region chat + contacts layout the mockup
//! shows is still unbuilt (`crate::screens::chat`'s own module doc notes it isn't wired into live
//! navigation) — so there is nowhere in today's screen stack that persistently renders across *every*
//! screen the way the mockup's bottom strip implies. Retrofitting a global strip into
//! `crate::app::App::render` would reshuffle the row math of every existing screen's layout (and the
//! checked-in geometry every prior screen-snapshot test in `tests/screens_*.rs` already asserts on),
//! none of which reserved a row for it. Instead this module ships as a **standalone, reusable, pure
//! render function** — [`render`] — that any screen calls into its own layout, exactly like every
//! other shared render helper in this crate. `crate::screens::diagnostics` is the one that does so
//! today (live connection/transport/relay-policy state alongside `doctor`'s output is literally what
//! that screen's own deliverable asks for); a future "Main" screen task can embed it in its own layout
//! the same way, with zero changes needed here — the same "registered/composed, not edited" shape
//! this crate's screen modules already follow for everything else.
//!
//! ## No live data plumbed in yet
//! [`StatusBarInfo::default`] is the only constructor any screen calls today: `crate::app::App` holds
//! no live `Transport`/session handle anywhere to read a real connection/transport state from — the
//! same "future Preflight-shaped task" gap `crate::screens::chat`/`crate::screens::verify`/
//! `crate::screens::requests` all flag in their own module docs for their own not-yet-wired data.
//! Every screen that uses this module today therefore renders the same honest "not connected"
//! defaults rather than a fabricated connected-looking status (tui-client.md §6 rule 10: "failure is
//! visible... never renders an optimistic [state] the transport did not confirm" — the same principle
//! applied here to "connected" as that rule applies to a delivered checkmark). When a real session
//! handle exists somewhere in `App`, building a non-default [`StatusBarInfo`] from it is that future
//! task's job, not this module's.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::config::NetworkPolicy;

/// Coarse connection state — mirrors
/// [tui-client.md §7](../../../docs/architecture/tui-client.md#7-what-the-user-sees-when-things-go-wrong)'s
/// own vocabulary (`● connected` / `● reconnecting (n/m)`), kept as a small closed enum rather than a
/// raw string so a caller cannot accidentally render inconsistent wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Which path a session is using, if any — tui-client.md §2's `P2P direct` / relay wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportPath {
    Unknown,
    Direct,
    Relay(String),
}

/// The status bar's full, renderable state. `#[derive(Debug)]`, no redaction needed: every field is
/// already-public session metadata (connection state, transport path, relay policy) — never a key,
/// passphrase, or message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusBarInfo {
    pub connection: ConnectionState,
    pub transport: TransportPath,
    pub policy: NetworkPolicy,
}

impl Default for StatusBarInfo {
    /// The honest "nothing live yet" state — see the module doc's "no live data plumbed in yet"
    /// section for why this is the only constructor any screen calls today.
    fn default() -> Self {
        Self {
            connection: ConnectionState::Disconnected,
            transport: TransportPath::Unknown,
            policy: NetworkPolicy::Inherit,
        }
    }
}

fn connection_glyph_and_label(state: ConnectionState) -> (&'static str, &'static str) {
    match state {
        ConnectionState::Disconnected => ("o", "not connected"),
        ConnectionState::Connecting => ("~", "connecting"),
        ConnectionState::Connected => ("*", "connected"),
    }
}

fn transport_label(path: &TransportPath) -> String {
    match path {
        TransportPath::Unknown => "path: n/a".to_string(),
        TransportPath::Direct => "P2P direct".to_string(),
        TransportPath::Relay(server) => format!("relayed via {server}"),
    }
}

/// The canonical `direct | prefer-relay | relay-only | inherit` strings — same wording as
/// `crate::screens::settings`'s own (private) `network_policy_str`, kept as a small independent copy
/// here rather than importing that private helper, to avoid widening `settings.rs`'s API surface for
/// a four-line match only this module also needs.
pub fn policy_label(policy: NetworkPolicy) -> &'static str {
    match policy {
        NetworkPolicy::Inherit => "inherit",
        NetworkPolicy::Direct => "direct",
        NetworkPolicy::PreferRelay => "prefer-relay",
        NetworkPolicy::RelayOnly => "relay-only",
    }
}

/// Pure view function — no I/O, same contract as every other `render` in this crate. Renders one line
/// into `area` (callers should size it `Constraint::Length(1)`). Status is conveyed by **glyph +
/// label**, never color alone (tui-client.md §3).
pub fn render(frame: &mut Frame<'_>, area: Rect, info: &StatusBarInfo) {
    let (glyph, label) = connection_glyph_and_label(info.connection);
    let color = match info.connection {
        ConnectionState::Disconnected => Color::Red,
        ConnectionState::Connecting => Color::Yellow,
        ConnectionState::Connected => Color::Green,
    };
    let line = Line::from(vec![
        Span::styled(format!("{glyph} {label}"), Style::default().fg(color)),
        Span::raw("  |  "),
        Span::raw(transport_label(&info.transport)),
        Span::raw("  |  "),
        Span::raw(format!("policy: {}", policy_label(info.policy))),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn default_is_honestly_disconnected() {
        let info = StatusBarInfo::default();
        assert_eq!(info.connection, ConnectionState::Disconnected);
        assert_eq!(info.transport, TransportPath::Unknown);
        assert_eq!(info.policy, NetworkPolicy::Inherit);
    }

    fn render_to_text(info: &StatusBarInfo) -> String {
        let backend = TestBackend::new(80, 1);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area(), info))
            .expect("draw");
        format!("{}", terminal.backend())
    }

    #[test]
    fn renders_every_connection_state_without_panicking() {
        for connection in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ] {
            let info = StatusBarInfo {
                connection,
                transport: TransportPath::Unknown,
                policy: NetworkPolicy::Inherit,
            };
            let text = render_to_text(&info);
            assert!(!text.trim().is_empty());
        }
    }

    #[test]
    fn renders_relay_path_with_server_name() {
        let info = StatusBarInfo {
            connection: ConnectionState::Connected,
            transport: TransportPath::Relay("turn.example.test".to_string()),
            policy: NetworkPolicy::RelayOnly,
        };
        let text = render_to_text(&info);
        assert!(text.contains("turn.example.test"));
        assert!(text.contains("relay-only"));
    }

    #[test]
    fn status_is_conveyed_by_glyph_and_label_not_color_alone() {
        // Every connection state must produce distinguishable *text*, independent of color — the
        // property that makes NO_COLOR / mono themes still legible (tui-client.md §3).
        let disconnected = render_to_text(&StatusBarInfo::default());
        let connected = render_to_text(&StatusBarInfo {
            connection: ConnectionState::Connected,
            transport: TransportPath::Direct,
            policy: NetworkPolicy::Direct,
        });
        assert!(disconnected.contains("not connected"));
        assert!(connected.contains("connected"));
        assert_ne!(disconnected, connected);
    }
}
