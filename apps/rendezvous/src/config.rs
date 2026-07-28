//! Server configuration — the small §9.2 surface subset relevant to T02.

use serde::Deserialize;

/// Top-level server config, parsed from TOML.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: Server,
    pub limits: Limits,
    pub turn: Turn,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Server {
    /// This rendezvous's own hint-domain; folded into the auth challenge so signatures can't be
    /// replayed against a different server (wire-protocol §2).
    pub domain: String,
    /// Address to bind the WSS listener.
    pub bind: String,
    /// Registration admission: `open` or `invite` (OIDC gating is a later admission trait, §3.2).
    pub admission: Admission,
    /// Valid tokens for `invite` admission.
    pub invite_tokens: Vec<String>,
    /// TEST HOOK: honor a fetch's `tamper` flag by substituting a bundle under a different key.
    /// The substitution logic itself only exists — is only compiled in at all — under the
    /// `test-tamper-hook` cargo feature (off by default; absent from release binaries entirely,
    /// not merely gated at runtime, F17). This flag stays present (harmlessly inert) without the
    /// feature so downstream config/test plumbing that merely sets it keeps compiling.
    pub allow_test_tamper: bool,
    /// TEST HOOK (tasks 1.28 + 1.32): the **umbrella** gate for tampering with the *routed* path —
    /// the malicious-relay attacks that `allow_test_tamper`'s bundle substitution does not cover.
    /// Like that flag, none of the logic exists at all without the `test-tamper-hook` cargo
    /// feature, and this is an *additional* gate on top of `allow_test_tamper`: both must be true.
    /// Separate from `allow_test_tamper` on purpose — the bundle-substitution demo
    /// (`fetch-bundle --tamper`) must keep working without every routed envelope also being
    /// corrupted.
    ///
    /// On its own this flag does nothing: since 1.32 each attack has its own `allow_test_route_*`
    /// mode flag below, and at least one must also be set. (Before 1.32 this flag *was* the
    /// in-transit rewrite; that attack is now `allow_test_route_rewrite`. The change is in the
    /// fail-closed direction — an old config that set only this flag now tampers with nothing.)
    pub allow_test_route_tamper: bool,
    /// TEST HOOK (task 1.28): actively **rewrite a routed blob in transit** (flip one byte inside
    /// the opaque payload). Requires the umbrella gate above. Provably stopped at the envelope
    /// signature — see [`crate::auth::rewrite_routed_blob`].
    pub allow_test_route_rewrite: bool,
    /// TEST HOOK (task 1.32): forge `Deliver.from`. The server asserts that field itself, so
    /// forging it needs no key material and passes the envelope signature check untouched.
    pub allow_test_route_spoof_from: bool,
    /// TEST HOOK (task 1.32): re-deliver a routed blob a second time, byte-identical.
    pub allow_test_route_replay: bool,
    /// TEST HOOK (task 1.32): swallow each sender's first routed blob while still replying
    /// `route_ok{delivered:true}` — the lie a dropping relay tells.
    pub allow_test_route_drop: bool,
    /// TEST HOOK (task 1.32): hold one blob back and release it *behind* the next one (a delay is
    /// the degenerate case). Nothing is lost — a pure permutation.
    pub allow_test_route_reorder: bool,
    /// TEST HOOK (task 1.32): deliver a valid envelope captured from one session to a *different*
    /// recipient, with its original `from` intact.
    pub allow_test_route_cross_deliver: bool,
    /// SQLite/sqlx URL, used only with the `sqlite` feature; ignored by the in-memory default.
    pub database_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Admission {
    Open,
    Invite,
}

/// Per-account and per-IP rate limits (fixed one-minute windows).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub auth_per_ip_per_min: u32,
    pub fetch_per_account_per_min: u32,
    pub route_per_account_per_min: u32,
    pub turn_per_account_per_min: u32,
}

/// TURN credential-minting surface (§9.2 "TURN secret + bandwidth caps"). An empty `secret`
/// disables minting — clients then use the host/STUN ladder only (air-gapped with no relay, or a
/// dev server). The `secret` MUST equal coturn's `static-auth-secret` and is provisioned out of
/// band (env/file), never committed.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Turn {
    /// Shared HMAC secret, identical to coturn's `static-auth-secret`. Empty ⇒ minting disabled.
    pub secret: String,
    /// TURN realm (coturn `realm`).
    pub realm: String,
    /// Candidate-ladder URLs in preference order (TURN/UDP → TURN/TCP → TURN/TLS-443).
    pub urls: Vec<String>,
    /// Credential lifetime in seconds (short by design). Each request mints a distinct credential;
    /// reuse of one captured credential within this window is bounded by coturn's `user-quota`, not
    /// rejected outright.
    pub ttl_secs: u64,
}

impl Default for Turn {
    fn default() -> Self {
        let c = crate::turn::TurnConfig::default();
        Self {
            secret: c.secret,
            realm: c.realm,
            urls: c.urls,
            ttl_secs: c.ttl_secs,
        }
    }
}

impl Turn {
    /// Build the minting config used by [`crate::turn`].
    pub fn to_turn_config(&self) -> crate::turn::TurnConfig {
        crate::turn::TurnConfig {
            secret: self.secret.clone(),
            realm: self.realm.clone(),
            urls: self.urls.clone(),
            ttl_secs: self.ttl_secs,
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            domain: "localhost".into(),
            bind: "127.0.0.1:8443".into(),
            admission: Admission::Open,
            invite_tokens: Vec::new(),
            allow_test_tamper: false,
            allow_test_route_tamper: false,
            allow_test_route_rewrite: false,
            allow_test_route_spoof_from: false,
            allow_test_route_replay: false,
            allow_test_route_drop: false,
            allow_test_route_reorder: false,
            allow_test_route_cross_deliver: false,
            database_url: "sqlite://rendezvous.db".into(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        // Generous defaults; anti-enumeration/anti-abuse, not throughput shaping.
        Self {
            auth_per_ip_per_min: 60,
            fetch_per_account_per_min: 120,
            route_per_account_per_min: 600,
            turn_per_account_per_min: 60,
        }
    }
}

impl Config {
    /// Parse a config from a TOML string. Missing fields fall back to defaults.
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Load a config from a TOML file path.
    pub fn load(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}
