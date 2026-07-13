//! Fixed-window rate limiting, keyed by IP (auth) and by account (fetch/route).
//!
//! This is anti-enumeration / anti-abuse (§3.5), not throughput shaping. Keys are hashed-in-spirit
//! transient counters that reset each minute; nothing is persisted, and no identifier is logged.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Window {
    start: Instant,
    count: u32,
}

/// A per-key fixed-window counter. `check(key)` returns `true` if the action is within budget.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    counters: Mutex<HashMap<Vec<u8>, Window>>,
}

impl RateLimiter {
    pub fn per_minute(limit: u32) -> Self {
        Self {
            limit,
            window: Duration::from_secs(60),
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Record one hit for `key`; returns `false` when the key has exceeded its budget this window.
    pub fn check(&self, key: &[u8]) -> bool {
        let now = Instant::now();
        let mut map = self.counters.lock().unwrap();
        let w = map.entry(key.to_vec()).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.duration_since(w.start) >= self.window {
            w.start = now;
            w.count = 0;
        }
        w.count += 1;
        w.count <= self.limit
    }
}
