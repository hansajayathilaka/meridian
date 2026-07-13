//! Safety numbers (system-design §4.4) — the human-verifiable fingerprint of a pair of identity
//! keys. T03 lands the *computation*; T08 builds the compare/verify UX and freezes conformance
//! vectors on top of it.
//!
//! Construction mirrors Signal's numeric fingerprint: an iterated SHA-512 per identity key, then
//! the two per-key fingerprints concatenated in a canonical (sorted) order so both peers derive
//! the **same** 60-digit number regardless of who computes it.

use sha2::{Digest, Sha512};

/// Fingerprint format version, folded into the hash. A bump changes every safety number.
const VERSION: u16 = 1;
/// Iteration count (Signal uses 5200) — deliberate work to harden the truncated output.
const ITERATIONS: u32 = 5200;

fn per_key(key: &[u8; 32]) -> String {
    // hash = SHA-512(version ‖ key ‖ identifier); identifier == the key itself (self-certifying).
    let mut hasher = Sha512::new();
    hasher.update(VERSION.to_be_bytes());
    hasher.update(key);
    hasher.update(key);
    let mut hash = hasher.finalize();

    for _ in 0..ITERATIONS {
        let mut h = Sha512::new();
        h.update(hash);
        h.update(key);
        hash = h.finalize();
    }

    // Six 5-byte chunks → six 5-digit groups = 30 digits.
    let mut out = String::with_capacity(30);
    for chunk in hash[..30].chunks(5) {
        let mut v: u64 = 0;
        for &b in chunk {
            v = (v << 8) | b as u64;
        }
        out.push_str(&format!("{:05}", v % 100_000));
    }
    out
}

/// The order-independent 60-digit safety number for two identity keys. `safety_number(a, b)` and
/// `safety_number(b, a)` are equal.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut s = per_key(first);
    s.push_str(&per_key(second));
    s
}

/// The same digits grouped in fives for display (`"12345 67890 …"`).
pub fn display_groups(number: &str) -> String {
    number
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}
