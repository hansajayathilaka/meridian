//! Timer seam (task 12.1): the only place `meridian-core` reaches for an async timer.
//!
//! `tokio::time` has no working driver on `wasm32-unknown-unknown` (no OS clock, no
//! browser-event-loop executor), so `session.rs` goes through this module instead of naming
//! `tokio::time` directly:
//!
//! - **native** — a plain re-export of `tokio::time::{timeout, Instant}`; behavior is byte-for-byte
//!   the pre-seam behavior (the existing `start_paused` virtual-time tests keep exercising it).
//! - **wasm32** — `wasmtimer::{tokio::timeout, std::Instant}`, API-identical mirrors backed by the browser event loop.
//!
//! Two clocks, chosen per call site (task 12.4, deliverable 5):
//!
//! - [`Instant`] — the **timer clock**: tokio's `Instant` natively, so it follows a paused test clock
//!   (`start_paused`) exactly as `timeout` does; used where a deadline is compared against a
//!   `timeout`-driven wait (`session.rs`'s `recv_until`).
//! - [`WallInstant`] — the **wall clock**, for sites that only *measure elapsed real time* for
//!   reporting (`ping`'s RTT, the dial/answer `wait_ms` figure). Natively this stays
//!   `std::time::Instant`, **deliberately not** tokio's: those figures are real elapsed time, and
//!   moving them onto tokio's clock would make them virtual under `start_paused` tests, changing
//!   native test behavior for no reason. On wasm32 it is `wasmtimer::std::Instant` (backed by
//!   `performance.now()`), because `std::time::Instant::now()` panics at runtime on
//!   `wasm32-unknown-unknown` (no OS clock) even though it compiles.
//!
//! Scope is deliberately just what `session.rs` uses; extend it only when a new call site needs more.
//! **Deliberately left:** `apps/streams/src/sender.rs` also calls `std::time::Instant::now()` (file
//! send throughput). `meridian-streams` depends on `meridian-core`, not the reverse, so it is outside
//! `meridian-core`'s wasm32 dependency tree and cannot reach this `pub(crate)` seam; it must be
//! routed when `meridian-streams` itself is brought onto wasm32 (the browser file-send task).

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use std::time::Instant as WallInstant;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use tokio::time::{timeout, Instant};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasmtimer::std::Instant;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasmtimer::std::Instant as WallInstant;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasmtimer::tokio::timeout;
