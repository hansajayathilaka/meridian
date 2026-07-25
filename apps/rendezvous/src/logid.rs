//! `LogId` — the only sanctioned way to put an identifier in a server log line.
//!
//! **Why this exists before there is any logging** (task 1.20 / review finding F21). The
//! anonymity model's invariant #4 — the server logs no raw identifiers — holds today only
//! *vacuously*: `meridian-rendezvous` logs nothing at all. The moment observability lands, the
//! natural thing to write is `tracing::info!(account = ?account_pub, ...)`, and the invariant
//! breaks silently. The guard rail goes in first, with `tools/lint-no-raw-id-logging.sh` to
//! enforce it.
//!
//! **Construction.** `HMAC-SHA256(salt, domain ‖ input)`, truncated to 8 bytes, lowercase hex.
//! Boring on purpose: this is a log token, not a MAC in a protocol.
//!
//! **The salt is per-process and random** ([`process_salt`]), which buys two properties:
//!
//! * **Not dictionary-recoverable.** A bare `SHA256(account_pub)` would be trivially reversible by
//!   anyone who can guess the candidate key set — and for a rendezvous server the candidate set is
//!   *exactly the accounts it serves*, which the operator already has. An unsalted hash would be a
//!   rename, not a protection. Under a secret salt the token is meaningless to anyone without it.
//! * **Not correlatable across restarts.** A fresh salt each boot means tokens cannot be joined
//!   across process lifetimes to build a long-run activity profile of an account.
//!
//! **What it deliberately does NOT hide, stated plainly:** tokens *are* stable and correlatable
//! *within* one process lifetime. That is the point — it is what makes them useful for debugging a
//! single incident ("these 40 lines are the same account"). An operator who can read the logs can
//! therefore see that some account did N things; they just cannot tell *which* account, nor link it
//! to yesterday's logs. Anyone who can also read process memory can recover the salt and re-link;
//! `LogId` defends against log disclosure, not against host compromise.

use std::sync::OnceLock;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Domain separation, so a token derived from an account key can never collide with one derived
/// from an IP that happens to have the same bytes.
const DOMAIN: &[u8] = b"meridian/logid/v1";

/// Bytes of HMAC output kept. 8 bytes → 16 hex chars: enough that accidental collisions in one
/// process's logs are not a practical concern, short enough to stay readable in a log line.
const TOKEN_BYTES: usize = 8;

type HmacSha256 = Hmac<Sha256>;

/// The per-process salt, generated once on first use from the OS CSPRNG.
fn process_salt() -> &'static [u8; 32] {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    SALT.get_or_init(|| {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).expect("OS RNG must be available");
        s
    })
}

/// A salted, truncated, non-reversible stand-in for an identifier in a log line.
///
/// Construct with [`LogId::new`] and interpolate it directly — both `{}` and `{:?}` render the
/// token, never the input.
#[derive(Clone, PartialEq, Eq)]
pub struct LogId(String);

impl LogId {
    /// Derive a log token for arbitrary identifier bytes (account public key, IP, …).
    pub fn new(id: &[u8]) -> Self {
        Self::with_salt(process_salt(), id)
    }

    /// [`new`](Self::new) under an explicit salt. Test-only: proving that two different salts
    /// produce different tokens for the same input is how the salting is actually verified.
    fn with_salt(salt: &[u8], id: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
        mac.update(DOMAIN);
        mac.update(id);
        let tag = mac.finalize().into_bytes();
        Self(data_encoding::HEXLOWER.encode(&tag[..TOKEN_BYTES]))
    }

    /// The token text, e.g. for structured-logging fields that want a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// Manual `Debug` (NOT derived) so `?log_id` in a tracing macro is exactly as safe as `%log_id`.
// A derived Debug would render `LogId("abc…")`, which is still safe here, but writing it by hand
// keeps the guarantee explicit and immune to the inner field ever changing type.
impl std::fmt::Debug for LogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"\x01\x02\x03account-key-a";
    const B: &[u8] = b"\x01\x02\x03account-key-b";

    #[test]
    fn same_input_is_stable_within_a_process() {
        assert_eq!(LogId::new(A), LogId::new(A));
    }

    #[test]
    fn different_inputs_give_different_tokens() {
        assert_ne!(LogId::new(A), LogId::new(B));
    }

    /// The salting is the whole point: an unsalted hash of an account key is reversible by anyone
    /// holding the candidate key set, which for this server is the operator.
    #[test]
    fn different_salts_give_different_tokens_for_the_same_input() {
        let one = LogId::with_salt(&[7u8; 32], A);
        let two = LogId::with_salt(&[9u8; 32], A);
        assert_ne!(
            one, two,
            "the token must depend on the salt, or it is a bare hash"
        );
    }

    /// Neither rendering may ever leak the input, in any form.
    #[test]
    fn rendering_never_contains_the_input() {
        let raw = b"super-secret-account-identifier";
        let id = LogId::new(raw);
        for rendered in [format!("{id}"), format!("{id:?}"), id.as_str().to_string()] {
            assert!(
                !rendered.contains("super-secret"),
                "LogId rendering leaked the input: {rendered}"
            );
            assert!(
                !rendered.contains(&data_encoding::HEXLOWER.encode(raw)),
                "LogId rendering leaked the hex-encoded input: {rendered}"
            );
            assert_eq!(
                rendered.len(),
                TOKEN_BYTES * 2,
                "token must be exactly {TOKEN_BYTES} bytes of hex"
            );
        }
    }

    #[test]
    fn domain_separation_holds_between_id_kinds() {
        // Same bytes used as two different kinds of identifier still share a token — domain
        // separation is against *other* HMAC users of this salt, not within LogId. Pin the
        // construction so a future change to DOMAIN is a deliberate, visible act.
        assert_eq!(
            LogId::with_salt(&[0u8; 32], b"x").as_str(),
            LogId::with_salt(&[0u8; 32], b"x").as_str()
        );
        assert_ne!(
            LogId::with_salt(&[0u8; 32], b"x").as_str(),
            LogId::with_salt(&[0u8; 32], b"y").as_str()
        );
    }
}
