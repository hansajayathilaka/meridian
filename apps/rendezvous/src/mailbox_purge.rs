//! Task 8.9: the mailbox TTL-expiry purge job. Proves expired envelopes are provably *purged* —
//! physically deleted from storage — not merely excluded from a query at read time. The feature
//! spec's own acceptance criterion; see this task's Risks/notes on why the distinction matters
//! (a query-time filter would satisfy a weaker, wrong reading while leaving stale ciphertext on
//! disk indefinitely, an ADR 0007 violation: the TTL promise is about server-side data lifetime).
//!
//! `Store::mailbox_list_for_recipient`'s own `SELECT`/lookup never filters on `expires_at` at
//! all (`store.rs`/`store/sqlite.rs`) — this purge job is the *only* place expiry is enforced, by
//! construction, not merely by convention.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

/// One purge pass: delete every row (across all recipients) whose `expires_at <= now`. A thin,
/// directly-testable wrapper around [`crate::store::Store::mailbox_purge_expired`] — kept separate
/// from the interval loop below so a test can inject `now` instead of depending on wall-clock time
/// (same testability rationale [`crate::store::Store::mailbox_enqueue`]'s own doc comment gives for
/// injecting `arrived_at`/`expires_at`). Returns the number of rows purged.
pub async fn run_purge_once(state: &Arc<AppState>, now: u64) -> crate::store::StoreResult<u64> {
    state.store.mailbox_purge_expired(now).await
}

/// Run [`run_purge_once`] on a fixed cadence (`config.mailbox.purge_interval_secs`), forever, using
/// the real wall clock. Spawned once at server startup ([`crate::main`]/`main.rs`), alongside the
/// server's other background tasks (the federation accept loop is the existing precedent for a
/// long-running `tokio::spawn`ed task in this crate). A single purge-pass failure (a `StoreError`)
/// is not fatal to the loop — the next tick tries again; there is no client-id logging to attach
/// context to (this module never sees which envelopes it removes, only counts), consistent with
/// this crate's no-client-id-logging discipline elsewhere.
pub async fn purge_loop(state: Arc<AppState>) {
    let interval_secs = state.config.mailbox.purge_interval_secs.max(1);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // The first tick fires immediately (tokio::time::interval's default), which is desirable here:
    // a server that was down past `expires_at` for many rows should purge them promptly on boot,
    // not wait a full interval first.
    loop {
        ticker.tick().await;
        let now = crate::ws::now_secs();
        let _ = run_purge_once(&state, now).await;
    }
}
