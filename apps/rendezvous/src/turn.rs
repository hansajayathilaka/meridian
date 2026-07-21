//! Ephemeral TURN credential minting (T05, system-design §5.4, ADR-8).
//!
//! The rendezvous mints time-limited, per-session TURN credentials so clients never hold a static
//! TURN secret (webrtc-nat-traversal invariant 4). We implement the coturn shared-secret
//! (`use-auth-secret`) REST mechanism (draft-uberti-behave-turn-rest-00): the credential is
//!
//! ```text
//! username   = "<expiry-unix>:<nonce-hex>"
//! credential = base64( HMAC-SHA1( shared_secret, username ) )
//! ```
//!
//! coturn recomputes the same HMAC over the presented username and accepts the allocation only
//! while `now < expiry`. Because we mint a **fresh random nonce per request**, every credential is
//! distinct — a captured credential does not let an attacker forge *other* usernames' allocations.
//! It does **not** by itself prevent reuse of that one captured credential: within its TTL window,
//! coturn's `user-quota` (see `infra/coturn/turnserver.conf`) bounds — but does not reject outright —
//! how many concurrent allocations it can mint before expiry. True single-use rejection at the wire
//! level is proven separately (see task 1.25/1.27, the real-coturn netns matrix, split from what
//! was originally 1.16 via 1.23).
//!
//! This module holds only the shared secret and HMAC — no session/ratchet code (the server's
//! "cannot" list §2.3 is unbroken; HMAC-SHA1 here is a primitive, exactly like the Ed25519 verify
//! in [`crate::auth`], and does NOT pull in `meridian-core`).

use data_encoding::BASE64;
use hmac::{Hmac, Mac};
use meridian_proto::TurnGrant;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// TURN minting configuration — the §9.2 "TURN secret + bandwidth caps" surface subset that the
/// rendezvous needs to mint credentials. The secret is provisioned out of band (env/file) and
/// MUST match coturn's `static-auth-secret`; it is never sent to a client.
#[derive(Clone, Debug)]
pub struct TurnConfig {
    /// Shared secret, identical to coturn's `static-auth-secret`. Empty ⇒ minting disabled.
    pub secret: String,
    /// TURN realm (coturn `realm`), echoed to the client.
    pub realm: String,
    /// The candidate ladder in preference order: TURN/UDP → TURN/TCP → TURN/TLS-443 (§5.4).
    pub urls: Vec<String>,
    /// Credential lifetime in seconds. Short by design, and each mint is distinct, so exposure of a
    /// captured credential is time- and quota-bounded (`user-quota` in coturn), not eliminated; a
    /// call that outlives it re-mints on ICE restart.
    pub ttl_secs: u64,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            realm: "localhost".into(),
            // A sensible default ladder; a real deploy overrides the host per turnserver.conf.
            urls: vec![
                "turn:127.0.0.1:3478?transport=udp".into(),
                "turn:127.0.0.1:3478?transport=tcp".into(),
                "turns:127.0.0.1:443?transport=tcp".into(),
            ],
            ttl_secs: 120,
        }
    }
}

impl TurnConfig {
    /// Whether minting is enabled (a shared secret is configured). Air-gapped deploys with no relay
    /// leave the secret empty and clients fall back to the host/STUN ladder.
    pub fn enabled(&self) -> bool {
        !self.secret.is_empty()
    }
}

/// A fresh 16-byte nonce, hex-encoded, from the OS CSPRNG. Uniqueness per mint is what makes each
/// credential distinct from every other request's — it does not by itself bound reuse of a single
/// captured credential (that's coturn's `user-quota`, plus the TTL).
fn new_nonce_hex() -> String {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("OS RNG must be available");
    let mut s = String::with_capacity(32);
    for b in nonce {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Mint a credential valid for `cfg.ttl_secs` from `now_unix`. `now_unix` is injected so tests are
/// deterministic; production passes the wall clock.
pub fn mint_at(cfg: &TurnConfig, now_unix: u64) -> TurnGrant {
    let expiry = now_unix.saturating_add(cfg.ttl_secs);
    let username = format!("{expiry}:{}", new_nonce_hex());
    let credential = sign_username(&cfg.secret, &username);
    TurnGrant {
        urls: cfg.urls.clone(),
        username,
        credential,
        ttl_secs: cfg.ttl_secs,
        realm: cfg.realm.clone(),
    }
}

/// Compute the coturn REST password for a username: `base64(HMAC-SHA1(secret, username))`.
pub fn sign_username(secret: &str, username: &str) -> String {
    let mut mac =
        HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(username.as_bytes());
    BASE64.encode(&mac.finalize().into_bytes())
}

/// Parse the embedded expiry from a `<expiry>:<nonce>` username. Returns `None` if malformed. Used
/// by the credential-lifecycle test to prove creds carry (and enforce) an expiry.
pub fn username_expiry(username: &str) -> Option<u64> {
    username.split(':').next()?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TurnConfig {
        TurnConfig {
            secret: "shared-secret-xyz".into(),
            realm: "chat.example".into(),
            urls: vec![
                "turn:turn.chat.example:3478?transport=udp".into(),
                "turn:turn.chat.example:3478?transport=tcp".into(),
                "turns:turn.chat.example:443?transport=tcp".into(),
            ],
            ttl_secs: 120,
        }
    }

    #[test]
    fn credential_verifies_under_the_shared_secret() {
        let g = mint_at(&cfg(), 1_000);
        // coturn recomputes exactly this — the credential must equal the HMAC over the username.
        assert_eq!(g.credential, sign_username(&cfg().secret, &g.username));
        // A different secret would not verify (coturn would reject the allocation).
        assert_ne!(g.credential, sign_username("other-secret", &g.username));
    }

    #[test]
    fn username_embeds_the_ttl_expiry() {
        let g = mint_at(&cfg(), 1_000);
        assert_eq!(username_expiry(&g.username), Some(1_120));
        assert_eq!(g.ttl_secs, 120);
    }

    #[test]
    fn each_mint_produces_a_distinct_credential() {
        let a = mint_at(&cfg(), 1_000);
        let b = mint_at(&cfg(), 1_000);
        // Same instant, same secret, yet distinct usernames+credentials: the per-mint nonce means
        // one request's credential never collides with another's. This does NOT by itself prevent
        // reuse of a single captured credential across multiple allocations within its own TTL —
        // that reuse is bounded by coturn's `user-quota`, not rejected outright.
        assert_ne!(a.username, b.username);
        assert_ne!(a.credential, b.credential);
    }

    #[test]
    fn ladder_is_udp_then_tcp_then_tls() {
        let g = mint_at(&cfg(), 0);
        assert!(g.urls[0].contains("transport=udp"));
        assert!(g.urls[1].contains("transport=tcp"));
        assert!(g.urls[2].starts_with("turns:") && g.urls[2].contains(":443"));
    }

    #[test]
    fn disabled_without_a_secret() {
        assert!(!TurnConfig::default().enabled());
        assert!(cfg().enabled());
    }
}
