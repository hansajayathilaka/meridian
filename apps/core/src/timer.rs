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
//! Scope is deliberately just what `session.rs` uses (`timeout` + `Instant`); extend it only when a
//! new call site needs more. **Known gap (owned by task 12.4):** `session.rs` still names
//! `std::time::Instant::now()` directly at three sites (`start` in the ICE-restart path, and
//! `attempt_start` in `dial` and `answer`). That
//! compiles on wasm32 but panics at runtime there (`std::time::SystemTime`/`Instant` are
//! unimplemented on `wasm32-unknown-unknown`). Left untouched here because tokio's `Instant` follows
//! a paused test clock, so swapping the import changes native test behavior and needs its own call.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use tokio::time::{timeout, Instant};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasmtimer::std::Instant;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasmtimer::tokio::timeout;
