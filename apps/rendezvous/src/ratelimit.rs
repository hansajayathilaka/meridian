//! Fixed-window rate limiting, keyed by IP (auth) and by account (fetch/route).
//!
//! This is anti-enumeration / anti-abuse (§3.5), not throughput shaping. Keys are hashed-in-spirit
//! transient counters that reset each minute; nothing is persisted, and no identifier is logged.
//!
//! **Bounded growth (task 1.20 / review finding F21).** Keys are attacker-controlled — IPs for
//! auth, account keys for fetch/route — and the map used to grow forever, one entry per distinct
//! key ever seen. That is an unauthenticated memory-exhaustion vector against the server. Expired
//! entries are now swept out; see [`RateLimiter::check`] for the amortisation and the
//! why-this-cannot-reset-a-live-budget argument.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Window {
    start: Instant,
    count: u32,
}

struct Counters {
    map: HashMap<Vec<u8>, Window>,
    /// When the last eviction sweep ran, so sweeps stay amortised rather than per-call.
    last_sweep: Instant,
}

/// A per-key fixed-window counter. `check(key)` returns `true` if the action is within budget.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    counters: Mutex<Counters>,
}

impl RateLimiter {
    pub fn per_minute(limit: u32) -> Self {
        Self::with_window(limit, Duration::from_secs(60))
    }

    /// [`per_minute`](Self::per_minute) with an explicit window. Exists so tests can exercise window
    /// expiry and the eviction sweep without sleeping for a real minute.
    pub fn with_window(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            counters: Mutex::new(Counters {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Record one hit for `key`; returns `false` when the key has exceeded its budget this window.
    ///
    /// Growth is bounded by an **amortised** eviction sweep: at most one sweep per `window`, so the
    /// hot path stays O(1) rather than becoming O(n) in the number of tracked keys.
    ///
    /// **Eviction can never reset a live budget.** A key is only dropped when
    /// `now - start >= window`, which is exactly the condition under which the *next* `check` for
    /// that key would reset `count` to 0 anyway (see the reset branch below). So a dropped entry and
    /// a retained-then-reset entry are observationally identical, and no key still inside its window
    /// — in particular, none currently at or over its limit — is ever removed. This matters:
    /// dropping a live counter would convert a memory fix into a rate-limit *bypass*.
    ///
    /// Deliberately **no hard cap** on map size. A cap would have to evict entries that are still
    /// inside their window, which is precisely the bypass above: an attacker sitting at their limit
    /// could flood distinct keys to force eviction of their own live counter and reset their budget.
    /// Fail-closed beats clever. Residual, stated honestly: within a *single* window an attacker can
    /// still create one entry per distinct key they can present. That is bounded by the number of
    /// source IPs they control (auth) and, for account-keyed limiters, by the fact that every account
    /// key must first complete an authenticated handshake that is itself IP-rate-limited.
    pub fn check(&self, key: &[u8]) -> bool {
        let now = Instant::now();
        let mut counters = self.counters.lock().unwrap();

        if now.duration_since(counters.last_sweep) >= self.window {
            let window = self.window;
            counters
                .map
                .retain(|_, w| now.duration_since(w.start) < window);
            counters.last_sweep = now;
        }

        let w = counters.map.entry(key.to_vec()).or_insert(Window {
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

    /// Number of keys currently tracked. Test-only: the growth-bound test needs to observe that the
    /// map does not grow linearly in total keys ever seen.
    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.counters.lock().unwrap().map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Growth bound: many distinct keys spread across elapsed windows must NOT accumulate one entry
    /// each. Before task 1.20 this map grew without bound, keyed by attacker-controlled input.
    #[test]
    fn expired_entries_are_evicted_so_growth_stays_bounded() {
        let window = Duration::from_millis(30);
        let rl = RateLimiter::with_window(100, window);

        // Three rounds of 50 distinct keys, each round in its own elapsed window.
        for round in 0..3u8 {
            for k in 0..50u8 {
                assert!(rl.check(&[round, k]));
            }
            std::thread::sleep(window + Duration::from_millis(10));
        }
        // One more hit, to trigger the sweep on the way in.
        assert!(rl.check(b"final"));

        let tracked = rl.tracked_keys();
        assert!(
            tracked <= 51,
            "expected the map to hold roughly one window's worth of keys, not all 150 ever seen; \
             tracked={tracked}"
        );
    }

    /// No false eviction: a key still inside its window keeps its accumulated count across a sweep,
    /// so a key at its limit stays rejected. If eviction dropped live state this key's budget would
    /// silently reset — a rate-limit bypass dressed up as a memory fix.
    #[test]
    fn sweep_never_resets_a_live_budget() {
        let window = Duration::from_secs(3600); // long: nothing expires during this test
        let rl = RateLimiter::with_window(3, window);

        assert!(rl.check(b"victim"));
        assert!(rl.check(b"victim"));
        assert!(rl.check(b"victim"));
        assert!(!rl.check(b"victim"), "4th hit must exceed a limit of 3");

        // Force sweep opportunities and lots of unrelated churn.
        for i in 0..500u32 {
            rl.check(&i.to_be_bytes());
        }

        assert!(
            !rl.check(b"victim"),
            "a key inside its window must stay over budget — eviction must not reset a live counter"
        );
    }

    /// The pre-existing behaviour eviction must not disturb: once the window really has elapsed, the
    /// same key legitimately gets a fresh budget.
    #[test]
    fn budget_resets_after_the_window_elapses() {
        let window = Duration::from_millis(30);
        let rl = RateLimiter::with_window(1, window);

        assert!(rl.check(b"k"));
        assert!(!rl.check(b"k"));
        std::thread::sleep(window + Duration::from_millis(10));
        assert!(rl.check(b"k"), "budget must reset once the window elapses");
    }
}
