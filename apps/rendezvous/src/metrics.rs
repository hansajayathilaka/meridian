//! Prometheus metrics — **only** the allowlisted names (tools/metrics-allowlist.txt,
//! docs/operations/monitoring.md §9.4). Never per-user sizes, contact-graph, or content metrics.
//!
//! Rendered by hand (no macros) so the metrics-allowlist lint has nothing to flag and we stay
//! dependency-light. `prekey_pool_depth` is computed from the store at scrape time.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    connections_active: AtomicI64,
    envelopes_routed_total: AtomicU64,
    turn_credentials_minted_total: AtomicU64,
    /// Currently-established s2s federation links, aggregate across ALL partners (task 2.4).
    /// Deliberately **no per-partner label**: a per-partner counter would materialize the
    /// cross-org contact graph this server talks to, which
    /// docs/security/anonymity-and-retention.md's must-never list forbids. See that task's report
    /// for the open security-reviewer question on whether a `peer_domain` label would ever be
    /// acceptable — until that's answered, this stays a single aggregate gauge.
    federation_links_up: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn conn_opened(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn envelope_routed(&self) {
        self.envelopes_routed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn turn_minted(&self) {
        self.turn_credentials_minted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn connections_active(&self) -> i64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    /// Record a newly-established, mutually authenticated federation link (task 2.4). No
    /// `peer_domain` (or any other per-partner) label — see the field doc on
    /// [`Self::federation_links_up`].
    pub fn federation_link_up(&self) {
        self.federation_links_up.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a federation link going down (peer disconnect, error, or graceful close).
    pub fn federation_link_down(&self) {
        self.federation_links_up.fetch_sub(1, Ordering::Relaxed);
    }

    /// Currently-established federation link count (test hook / direct read).
    pub fn federation_links_up(&self) -> i64 {
        self.federation_links_up.load(Ordering::Relaxed)
    }

    /// Render the Prometheus text exposition. `prekey_pool_depth` is passed in (read from the
    /// store at scrape time).
    pub fn render(&self, prekey_pool_depth: u64) -> String {
        let conns = self.connections_active.load(Ordering::Relaxed);
        let routed = self.envelopes_routed_total.load(Ordering::Relaxed);
        let turn_minted = self.turn_credentials_minted_total.load(Ordering::Relaxed);
        let mut out = String::new();
        metric(
            &mut out,
            "meridian_connections_active",
            "gauge",
            "Currently connected WebSocket clients.",
            conns,
        );
        metric(
            &mut out,
            "meridian_envelopes_routed_total",
            "counter",
            "Envelopes routed to connected peers since start.",
            routed as i64,
        );
        metric(
            &mut out,
            "meridian_prekey_pool_depth",
            "gauge",
            "One-time prekeys currently held across all accounts (depletion breaks first contact).",
            prekey_pool_depth as i64,
        );
        metric(
            &mut out,
            "meridian_turn_credentials_minted_total",
            "counter",
            "Ephemeral TURN credentials minted since start (relay-demand signal, §9.4).",
            turn_minted as i64,
        );
        metric(
            &mut out,
            "meridian_federation_link_up",
            "gauge",
            "Established (mutually authenticated) s2s federation links currently up, aggregate \
             across all partners — no per-partner label (anonymity-and-retention.md must-never #2).",
            self.federation_links_up.load(Ordering::Relaxed),
        );
        out
    }
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: i64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}
