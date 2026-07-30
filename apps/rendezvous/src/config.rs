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

    /// Overlay `MERIDIAN_<SECTION>__<FIELD>` environment variables onto an already-loaded config
    /// (docker-compose / k8s Secrets can then override individual keys without templating
    /// `rendezvous.toml` itself). Every key in the §5 config surface has a matching env var —
    /// see `rendezvous.example.toml` for the full list next to each field.
    ///
    /// Fails closed: an env var that's set but doesn't parse (bad bool/int/admission value) is a
    /// hard error rather than a silent no-op, so a typo can't leave the server running with
    /// weaker-than-intended settings (same principle as the `--config` load failure in `main`).
    pub fn apply_env_overrides(&mut self) -> Result<(), EnvOverrideError> {
        use std::env::var as env;

        if let Ok(v) = env("MERIDIAN_SERVER__DOMAIN") {
            self.server.domain = v;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__BIND") {
            self.server.bind = v;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ADMISSION") {
            self.server.admission = parse_admission("MERIDIAN_SERVER__ADMISSION", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__INVITE_TOKENS") {
            self.server.invite_tokens = parse_list(&v);
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_TAMPER") {
            self.server.allow_test_tamper = parse_bool("MERIDIAN_SERVER__ALLOW_TEST_TAMPER", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_TAMPER") {
            self.server.allow_test_route_tamper =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_TAMPER", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REWRITE") {
            self.server.allow_test_route_rewrite =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REWRITE", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_SPOOF_FROM") {
            self.server.allow_test_route_spoof_from =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_SPOOF_FROM", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REPLAY") {
            self.server.allow_test_route_replay =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REPLAY", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_DROP") {
            self.server.allow_test_route_drop =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_DROP", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REORDER") {
            self.server.allow_test_route_reorder =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_REORDER", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_CROSS_DELIVER") {
            self.server.allow_test_route_cross_deliver =
                parse_bool("MERIDIAN_SERVER__ALLOW_TEST_ROUTE_CROSS_DELIVER", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_SERVER__DATABASE_URL") {
            self.server.database_url = v;
        }

        if let Ok(v) = env("MERIDIAN_LIMITS__AUTH_PER_IP_PER_MIN") {
            self.limits.auth_per_ip_per_min =
                parse_u32("MERIDIAN_LIMITS__AUTH_PER_IP_PER_MIN", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_LIMITS__FETCH_PER_ACCOUNT_PER_MIN") {
            self.limits.fetch_per_account_per_min =
                parse_u32("MERIDIAN_LIMITS__FETCH_PER_ACCOUNT_PER_MIN", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_LIMITS__ROUTE_PER_ACCOUNT_PER_MIN") {
            self.limits.route_per_account_per_min =
                parse_u32("MERIDIAN_LIMITS__ROUTE_PER_ACCOUNT_PER_MIN", &v)?;
        }
        if let Ok(v) = env("MERIDIAN_LIMITS__TURN_PER_ACCOUNT_PER_MIN") {
            self.limits.turn_per_account_per_min =
                parse_u32("MERIDIAN_LIMITS__TURN_PER_ACCOUNT_PER_MIN", &v)?;
        }

        if let Ok(v) = env("MERIDIAN_TURN__SECRET") {
            self.turn.secret = v;
        }
        if let Ok(v) = env("MERIDIAN_TURN__REALM") {
            self.turn.realm = v;
        }
        if let Ok(v) = env("MERIDIAN_TURN__URLS") {
            self.turn.urls = parse_list(&v);
        }
        if let Ok(v) = env("MERIDIAN_TURN__TTL_SECS") {
            self.turn.ttl_secs = parse_u64("MERIDIAN_TURN__TTL_SECS", &v)?;
        }

        Ok(())
    }
}

/// A `MERIDIAN_*` environment variable was set but its value didn't parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EnvOverrideError(String);

fn parse_bool(key: &str, v: &str) -> Result<bool, EnvOverrideError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(EnvOverrideError(format!(
            "{key}: invalid boolean {other:?} (expected true/false)"
        ))),
    }
}

fn parse_u32(key: &str, v: &str) -> Result<u32, EnvOverrideError> {
    v.trim()
        .parse()
        .map_err(|_| EnvOverrideError(format!("{key}: invalid integer {v:?}")))
}

fn parse_u64(key: &str, v: &str) -> Result<u64, EnvOverrideError> {
    v.trim()
        .parse()
        .map_err(|_| EnvOverrideError(format!("{key}: invalid integer {v:?}")))
}

fn parse_admission(key: &str, v: &str) -> Result<Admission, EnvOverrideError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "open" => Ok(Admission::Open),
        "invite" => Ok(Admission::Invite),
        other => Err(EnvOverrideError(format!(
            "{key}: invalid admission {other:?} (expected open|invite)"
        ))),
    }
}

/// Comma-separated list, trimmed, empty elements dropped (so `FOO=` means "empty list", not
/// `[""]`), e.g. `invite_tokens` and `turn.urls`.
fn parse_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `std::env` is process-global; serialize every test in this module so they can't stomp on
    // each other's vars when cargo runs them concurrently.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Sets `MERIDIAN_*` vars for the duration of the guard and clears them all on drop, even if
    /// the test panics (so a failing assertion can't leak an override into a later test).
    struct EnvGuard<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
        keys: Vec<&'static str>,
    }

    impl<'a> EnvGuard<'a> {
        fn set(lock: std::sync::MutexGuard<'a, ()>, vars: &[(&'static str, &str)]) -> Self {
            for (k, v) in vars {
                // SAFETY: serialized by ENV_LOCK above; no other thread touches these vars.
                unsafe { std::env::set_var(k, v) };
            }
            Self {
                _lock: lock,
                keys: vars.iter().map(|(k, _)| *k).collect(),
            }
        }
    }

    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            for k in &self.keys {
                // SAFETY: same justification as `set` above.
                unsafe { std::env::remove_var(k) };
            }
        }
    }

    #[test]
    fn env_overrides_apply_over_file_and_defaults() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[
                ("MERIDIAN_SERVER__DOMAIN", "org.example"),
                ("MERIDIAN_SERVER__BIND", "0.0.0.0:9443"),
                ("MERIDIAN_SERVER__ADMISSION", "invite"),
                ("MERIDIAN_SERVER__INVITE_TOKENS", "tok-a, tok-b ,,tok-c"),
                ("MERIDIAN_SERVER__ALLOW_TEST_TAMPER", "true"),
                ("MERIDIAN_LIMITS__ROUTE_PER_ACCOUNT_PER_MIN", "42"),
                ("MERIDIAN_TURN__SECRET", "s3cr3t"),
                (
                    "MERIDIAN_TURN__URLS",
                    "turn:a:3478?transport=udp,turn:b:3478?transport=tcp",
                ),
                ("MERIDIAN_TURN__TTL_SECS", "300"),
            ],
        );

        let mut config = Config::default();
        config.apply_env_overrides().expect("valid overrides");

        assert_eq!(config.server.domain, "org.example");
        assert_eq!(config.server.bind, "0.0.0.0:9443");
        assert_eq!(config.server.admission, Admission::Invite);
        assert_eq!(config.server.invite_tokens, vec!["tok-a", "tok-b", "tok-c"]);
        assert!(config.server.allow_test_tamper);
        assert_eq!(config.limits.route_per_account_per_min, 42);
        // Unset fields keep the file/default value.
        assert_eq!(
            config.limits.fetch_per_account_per_min,
            Limits::default().fetch_per_account_per_min
        );
        assert_eq!(config.turn.secret, "s3cr3t");
        assert_eq!(
            config.turn.urls,
            vec!["turn:a:3478?transport=udp", "turn:b:3478?transport=tcp"]
        );
        assert_eq!(config.turn.ttl_secs, 300);
    }

    #[test]
    fn env_overrides_reject_bad_bool_fail_closed() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[("MERIDIAN_SERVER__ALLOW_TEST_TAMPER", "sure")],
        );

        let mut config = Config::default();
        let err = config
            .apply_env_overrides()
            .expect_err("non-bool value must be rejected, not silently ignored");
        assert!(err
            .to_string()
            .contains("MERIDIAN_SERVER__ALLOW_TEST_TAMPER"));
        // Fails before or after other fields, but must not silently arm a test hook.
        assert!(!config.server.allow_test_tamper);
    }

    #[test]
    fn env_overrides_reject_bad_admission() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[("MERIDIAN_SERVER__ADMISSION", "sometimes")],
        );

        let mut config = Config::default();
        assert!(config.apply_env_overrides().is_err());
    }

    #[test]
    fn no_env_vars_set_leaves_config_untouched() {
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);

        let mut config = Config::from_toml_str(
            r#"
            [server]
            domain = "from-file.example"
            "#,
        )
        .unwrap();
        config.apply_env_overrides().unwrap();

        assert_eq!(config.server.domain, "from-file.example");
    }
}
