//! Property & fuzz tests for the frozen ID format (T01 acceptance criteria).
//!
//! - round-trip on 10⁶ fuzzed IDs (`million_roundtrips`);
//! - a flipped bit anywhere in the key part is rejected (`prop_corruption_rejected`);
//! - the same key with two different `@hints` is the same principal (`prop_same_principal`).

use meridian_identity::{encode_key_part, parse_id, same_principal, to_id_string, Identity};
use proptest::prelude::*;

/// Fast, deterministic PRNG so the 10⁶ loop is reproducible and cheap (no syscalls).
struct SplitMix64(u64);
impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn fill_key(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        for chunk in k.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        k
    }
}

#[test]
fn million_roundtrips() {
    // Acceptance: "Round-trip on 10⁶ fuzzed IDs."
    let mut rng = SplitMix64(0x0DDB1A5E5BAD5EED);
    let hint = "chat.example";
    for _ in 0..1_000_000u32 {
        let key = rng.fill_key();
        let id = to_id_string(&key, hint).expect("canonical hint");
        let parsed = parse_id(&id).expect("round-trip must parse");
        assert_eq!(parsed.pubkey(), &key);
        assert_eq!(parsed.hint(), hint);
    }
}

fn any_key() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

// A canonical hint: 1–3 lowercase LDH labels.
fn any_hint() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,9}(\\.[a-z][a-z0-9]{0,9}){0,2}".prop_map(|s| s)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Structured round-trip over arbitrary keys and canonical hints.
    #[test]
    fn prop_roundtrip(key in any_key(), hint in any_hint()) {
        let id = to_id_string(&key, &hint).unwrap();
        let parsed = parse_id(&id).unwrap();
        prop_assert_eq!(parsed.pubkey(), &key);
        prop_assert_eq!(parsed.hint(), hint.as_str());
        // Canonical form is stable under re-encode.
        prop_assert_eq!(parsed.to_id_string(), id);
    }

    /// The same key under two different hints is the same principal; a different key is not.
    #[test]
    fn prop_same_principal(key in any_key(), other in any_key(), h1 in any_hint(), h2 in any_hint()) {
        prop_assume!(key != other);
        let a = Identity::new(key, &h1).unwrap();
        let b = Identity::new(key, &h2).unwrap();
        prop_assert!(same_principal(&a, &b));

        let c = Identity::new(other, &h1).unwrap();
        prop_assert!(!same_principal(&a, &c));
    }

    /// Mutating any non-final symbol of the key part changes ≥1 decoded byte, so the checksum
    /// (or multicodec/length) check must reject it. Acceptance: "a flipped bit anywhere in the
    /// key part is rejected."
    #[test]
    fn prop_corruption_rejected(key in any_key(), idx in 0usize..60, repl in 0u8..32) {
        // rfc4648 base32 lowercase alphabet.
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let key_part = encode_key_part(&key);
        let bytes = key_part.as_bytes();
        // Exclude the final symbol (its low bits are unused padding).
        let i = idx % (bytes.len() - 1);
        let mut new_char = ALPHABET[(repl as usize) % 32];
        if new_char == bytes[i] {
            new_char = ALPHABET[((repl as usize) + 1) % 32];
        }
        let mut corrupted: Vec<u8> = bytes.to_vec();
        corrupted[i] = new_char;
        let corrupted_key = String::from_utf8(corrupted).unwrap();
        let id = format!("mrd1:{corrupted_key}@chat.example");
        prop_assert!(parse_id(&id).is_err(), "corruption at {i} was not rejected: {id}");
    }
}
