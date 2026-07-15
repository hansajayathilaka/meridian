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
        out
    }
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: i64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}
