//! Server configuration — the small §9.2 surface subset relevant to T02.

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;

/// Conventional config path used only when no explicit `--config` path is given (see
/// [`Config::load`]).
const DEFAULT_CONFIG_PATH: &str = "rendezvous.toml";

/// Top-level server config, parsed from TOML.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: Server,
    pub limits: Limits,
    pub turn: Turn,
    pub federation: Federation,
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

/// Server↔server (s2s) federation link config (task 2.4, ADR 0017) plus discovery config (task
/// 2.5, ADR 0002). Every field defaults fail-closed: `enabled = false` means federation is
/// entirely inert (no listener bound, no dialing, no DNS lookup) until an operator explicitly opts
/// in and supplies real cert/key/CA material — there is no default cert/key path that could
/// accidentally "just work" with a placeholder identity, and no default discovery behavior that
/// could accidentally make a DNS query the operator didn't ask for.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Federation {
    /// Master switch. `false` ⇒ no federation listener is bound, no outbound federation dial is
    /// ever attempted, and no discovery lookup (SRV or static-map) is ever performed, regardless
    /// of any other field below (fail-closed default).
    pub enabled: bool,
    /// Address to bind the s2s mTLS listener. TLS terminates **in-process** here — never at a
    /// proxy/VIP upstream (ADR 0017 C7), unlike the c2s WSS listener (ADR 0008).
    pub bind: String,
    /// PEM path: this server's own federation identity certificate (leaf, optionally with an
    /// intermediate chain), presented as both the mTLS server cert (accepting inbound links) and
    /// the mTLS client cert (dialing outbound links) — one federation identity per org.
    pub cert_path: String,
    /// PEM path: the private key matching `cert_path`. Never committed; provisioned out of band.
    pub key_path: String,
    /// PEM path: a private-CA trust bundle. Empty ⇒ **WebPKI mode** (validate peer certs against
    /// the OS/system trust store). Non-empty ⇒ **private-CA / air-gap mode**: trust *only* the CAs
    /// in this bundle — never silently fall back to the system store (ADR 0017 (a)/C3/C4; the
    /// whole air-gap trust model depends on this being an exclusive, not additive, trust root).
    pub ca_bundle_path: String,
    /// Discovery mode (task 2.5, [`federation::discovery`](crate::federation::discovery)):
    /// `"static"` resolves partner domains exclusively through `map_path`'s `federation_map.toml`
    /// (no DNS involved at all — the air-gap mode); `"srv"` resolves them via
    /// `_meridian-fed._tcp.<domain>` DNS SRV records, refusing (never falling back to A/AAAA) when
    /// no SRV record exists. Defaults to `"static"`: the fail-closed choice, since it is the mode
    /// that can never *originate* a DNS query on its own — an operator who wants SRV must opt in
    /// explicitly, mirroring `ca_bundle_path`'s "empty means don't do the riskier/networked thing
    /// by default" posture.
    pub discovery: DiscoveryMode,
    /// Path to `federation_map.toml`, read by [`crate::federation::discovery::StaticMap`] when
    /// `discovery = "static"`. Empty by default (no path that could accidentally load a stray file
    /// of the conventional name); ignored when `discovery = "srv"`.
    pub map_path: String,
}

/// Federation discovery mode (task 2.5, ADR 0002 "DNS-SRV/static-map discovery"). See
/// [`Federation::discovery`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// `federation_map.toml` only — no DNS lookup is ever made (air-gap mode).
    Static,
    /// `_meridian-fed._tcp.<domain>` DNS SRV records; refuses (fails closed) if none exist.
    Srv,
}

impl Default for Federation {
    fn default() -> Self {
        Self {
            enabled: false,
            // Federation (s2s mTLS) default port: adjacent to, but distinct from, the c2s WSS
            // default (8443) — TODO: confirm was resolved by picking 8444 (next integer) so both
            // listeners can run on the same host with no config edit and no ambiguity about which
            // port is which. Not an IANA-registered service port as of this writing; operators are
            // free to override via `federation.bind` / `MERIDIAN_RENDEZVOUS_FEDERATION__BIND`.
            bind: "127.0.0.1:8444".into(),
            cert_path: String::new(),
            key_path: String::new(),
            ca_bundle_path: String::new(),
            discovery: DiscoveryMode::Static,
            map_path: String::new(),
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
    /// Parse a config from a TOML string, with no env-var layer. Used directly by tests; `load`
    /// is the real entry point.
    #[cfg(test)]
    fn from_toml_str(s: &str) -> Result<Self, Box<figment::Error>> {
        Figment::from(Toml::string(s)).extract().map_err(Box::new)
    }

    /// Load the server config: an on-disk TOML file (explicit `--config <path>`, or the
    /// conventional `rendezvous.toml` in the working directory when `explicit_path` is `None`)
    /// merged with `MERIDIAN_RENDEZVOUS_<SECTION>__<FIELD>` environment variables, which take
    /// precedence over the file. The prefix is scoped to this service (not bare `MERIDIAN_`) so
    /// it can't collide with other Meridian components' env vars sharing the process environment
    /// (e.g. the CLI's `MERIDIAN_HOME`/`MERIDIAN_POLICY__*`). Every key in the §5 config surface
    /// has a matching env var — see `rendezvous.example.toml` for the full list next to each
    /// field. List values use TOML/JSON bracket syntax, e.g.
    /// `MERIDIAN_RENDEZVOUS_TURN__URLS=["turn:a","turn:b"]`.
    ///
    /// Fails closed, uniformly: a bad env var (unparseable bool/int/admission), an explicitly
    /// supplied `--config` path that doesn't exist, or **any** malformed TOML file (whether
    /// pointed to by `--config` or the conventional `rendezvous.toml`) is a hard `Err` — never a
    /// silent fallback to defaults. Only a **missing** `rendezvous.toml` on the implicit path is
    /// non-fatal (ADR 0018): that's the documented "no config" default-boot path, not a
    /// user-requested load.
    pub fn load(explicit_path: Option<&str>) -> Result<Self, Box<figment::Error>> {
        let mut figment = Figment::new();
        match explicit_path {
            Some(path) => {
                if !std::path::Path::new(path).exists() {
                    return Err(Box::new(format!("config file not found: {path}").into()));
                }
                figment = figment.merge(Toml::file(path));
            }
            None => {
                // `Toml::file` silently contributes nothing if the file is simply absent — that
                // alone gives the "no config" default-boot path its non-fatal behavior. A
                // *malformed* file, missing or not, still surfaces as a hard error below.
                figment = figment.merge(Toml::file(DEFAULT_CONFIG_PATH));
            }
        }
        let config: Self = figment
            .merge(Env::prefixed("MERIDIAN_RENDEZVOUS_").split("__"))
            .extract()
            .map_err(Box::new)?;
        config.validate().map_err(|e| Box::new(e.into()))?;
        Ok(config)
    }

    /// Cross-field fail-closed checks that a single field's `Deserialize` impl can't express.
    fn validate(&self) -> Result<(), String> {
        self.federation.validate()
    }
}

impl Federation {
    /// Reject configuration combinations that are individually valid per-field but collapse a
    /// security invariant when combined.
    ///
    /// `discovery = "srv"` together with a non-empty `ca_bundle_path` (private-CA/air-gap mode)
    /// is exactly that: SRV-resolved [`crate::federation::discovery::Endpoint`]s always carry
    /// `pinned_identity: None` (SRV is unauthenticated discovery only, by design — ADR 0017
    /// (a)), so under private-CA mode the trust check would collapse to "chains to the shared
    /// CA + SAN matches the self-asserted DNS hint domain" — the impersonation hole ADR 0017
    /// (a)'s rejected "Option A" describes: any org enrolled under that CA could present a valid
    /// cert and be accepted as any other org. Rejected here, at config-load time, rather than
    /// left for the dial path to discover at runtime.
    fn validate(&self) -> Result<(), String> {
        if self.discovery == DiscoveryMode::Srv && !self.ca_bundle_path.is_empty() {
            return Err(
                "federation.discovery = \"srv\" is incompatible with a non-empty \
                 federation.ca_bundle_path (private-CA/air-gap mode): SRV-resolved endpoints \
                 never carry a pinned_identity (SRV is unauthenticated discovery only, ADR 0017 \
                 (a)), so combining the two collapses private-CA trust to an unpinned DNS-hint \
                 check — the impersonation hole ADR 0017 (a) rejects. Use \
                 federation.discovery = \"static\" (federation_map.toml, which mandates a \
                 pinned_identity per partner) with a private CA, or clear ca_bundle_path to run \
                 SRV discovery in WebPKI mode."
                    .to_string(),
            );
        }
        Ok(())
    }
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

    fn write_toml(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn env_overrides_apply_over_file_and_defaults() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[
                ("MERIDIAN_RENDEZVOUS_SERVER__DOMAIN", "org.example"),
                ("MERIDIAN_RENDEZVOUS_SERVER__BIND", "0.0.0.0:9443"),
                ("MERIDIAN_RENDEZVOUS_SERVER__ADMISSION", "invite"),
                (
                    "MERIDIAN_RENDEZVOUS_SERVER__INVITE_TOKENS",
                    r#"["tok-a","tok-b"]"#,
                ),
                ("MERIDIAN_RENDEZVOUS_SERVER__ALLOW_TEST_TAMPER", "true"),
                (
                    "MERIDIAN_RENDEZVOUS_LIMITS__ROUTE_PER_ACCOUNT_PER_MIN",
                    "42",
                ),
                ("MERIDIAN_RENDEZVOUS_TURN__SECRET", "s3cr3t"),
                (
                    "MERIDIAN_RENDEZVOUS_TURN__URLS",
                    r#"["turn:a:3478?transport=udp","turn:b:3478?transport=tcp"]"#,
                ),
                ("MERIDIAN_RENDEZVOUS_TURN__TTL_SECS", "300"),
            ],
        );
        let file = write_toml(
            "[server]\ndomain = \"from-file.example\"\nbind = \"file-should-lose.example:1\"\n",
        );

        let config = Config::load(Some(file.path().to_str().unwrap())).expect("valid overrides");

        assert_eq!(config.server.domain, "org.example"); // env wins over file
        assert_eq!(config.server.bind, "0.0.0.0:9443");
        assert_eq!(config.server.admission, Admission::Invite);
        assert_eq!(config.server.invite_tokens, vec!["tok-a", "tok-b"]);
        assert!(config.server.allow_test_tamper);
        assert_eq!(config.limits.route_per_account_per_min, 42);
        // Unset fields keep the built-in default.
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
    fn file_only_value_survives_when_no_env_override() {
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
        let file = write_toml("[server]\ndomain = \"from-file.example\"\n");

        let config = Config::load(Some(file.path().to_str().unwrap())).unwrap();

        assert_eq!(config.server.domain, "from-file.example");
    }

    #[test]
    fn env_overrides_reject_bad_bool_fail_closed() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[("MERIDIAN_RENDEZVOUS_SERVER__ALLOW_TEST_TAMPER", "sure")],
        );
        let file = write_toml("");

        let err = Config::load(Some(file.path().to_str().unwrap()))
            .expect_err("non-bool value must be rejected, not silently ignored");
        // Fails closed: must not silently arm a test hook. The exact message is figment's own
        // (type-mismatch on the offending key), not a custom one.
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn env_overrides_reject_bad_admission() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[("MERIDIAN_RENDEZVOUS_SERVER__ADMISSION", "sometimes")],
        );
        let file = write_toml("");

        assert!(Config::load(Some(file.path().to_str().unwrap())).is_err());
    }

    #[test]
    fn explicit_config_path_that_does_not_exist_is_fatal() {
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);

        let err = Config::load(Some("/nonexistent/path/rendezvous.toml")).unwrap_err();

        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn implicit_path_missing_file_is_non_fatal_but_malformed_file_is_now_fatal() {
        // Exercises ADR 0018's fail-closed tightening: on the implicit (no `--config`) path, a
        // *missing* rendezvous.toml still falls back to defaults, but a *malformed* one — which
        // used to fall back silently too — is now a hard error, same as the explicit path.
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
        let dir = tempfile::tempdir().unwrap();
        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let missing = Config::load(None);
        std::fs::write(dir.path().join(DEFAULT_CONFIG_PATH), "not valid toml =====").unwrap();
        let malformed = Config::load(None);

        std::env::set_current_dir(&orig_cwd).unwrap();

        let config = missing.expect("missing implicit rendezvous.toml is non-fatal");
        assert_eq!(config.server.domain, Server::default().domain);
        assert!(
            malformed.is_err(),
            "malformed implicit rendezvous.toml must now be fatal"
        );
    }

    #[test]
    fn federation_defaults_to_disabled_with_no_cert_material() {
        // Fail-closed: federation must be entirely inert until an operator opts in.
        let f = Federation::default();
        assert!(!f.enabled);
        assert!(f.cert_path.is_empty());
        assert!(f.key_path.is_empty());
        assert!(f.ca_bundle_path.is_empty());
        // Discovery defaults to `static`, the mode that can never originate a DNS query on its
        // own (task 2.5) — mirrors `ca_bundle_path`'s "empty means don't do the networked thing
        // by default" posture.
        assert_eq!(f.discovery, DiscoveryMode::Static);
        assert!(f.map_path.is_empty());

        let config = Config::from_toml_str("").unwrap();
        assert!(!config.federation.enabled);
        assert_eq!(config.federation.discovery, DiscoveryMode::Static);
    }

    #[test]
    fn federation_discovery_env_overrides_apply() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[
                ("MERIDIAN_RENDEZVOUS_FEDERATION__DISCOVERY", "srv"),
                (
                    "MERIDIAN_RENDEZVOUS_FEDERATION__MAP_PATH",
                    "/etc/meridian/federation_map.toml",
                ),
            ],
        );
        let file = write_toml("");

        let config = Config::load(Some(file.path().to_str().unwrap())).unwrap();

        assert_eq!(config.federation.discovery, DiscoveryMode::Srv);
        assert_eq!(
            config.federation.map_path,
            "/etc/meridian/federation_map.toml"
        );
    }

    #[test]
    fn federation_discovery_rejects_unknown_mode_fail_closed() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[(
                "MERIDIAN_RENDEZVOUS_FEDERATION__DISCOVERY",
                "dns-over-carrier-pigeon",
            )],
        );
        let file = write_toml("");

        assert!(Config::load(Some(file.path().to_str().unwrap())).is_err());
    }

    #[test]
    fn federation_env_overrides_apply() {
        let _guard = EnvGuard::set(
            ENV_LOCK.lock().unwrap(),
            &[
                ("MERIDIAN_RENDEZVOUS_FEDERATION__ENABLED", "true"),
                ("MERIDIAN_RENDEZVOUS_FEDERATION__BIND", "0.0.0.0:8444"),
                (
                    "MERIDIAN_RENDEZVOUS_FEDERATION__CERT_PATH",
                    "/etc/meridian/fed.crt",
                ),
                (
                    "MERIDIAN_RENDEZVOUS_FEDERATION__KEY_PATH",
                    "/etc/meridian/fed.key",
                ),
                (
                    "MERIDIAN_RENDEZVOUS_FEDERATION__CA_BUNDLE_PATH",
                    "/etc/meridian/fed-ca.pem",
                ),
            ],
        );
        let file = write_toml("");

        let config = Config::load(Some(file.path().to_str().unwrap())).unwrap();

        assert!(config.federation.enabled);
        assert_eq!(config.federation.bind, "0.0.0.0:8444");
        assert_eq!(config.federation.cert_path, "/etc/meridian/fed.crt");
        assert_eq!(config.federation.key_path, "/etc/meridian/fed.key");
        assert_eq!(config.federation.ca_bundle_path, "/etc/meridian/fed-ca.pem");
    }

    #[test]
    fn discovery_srv_with_private_ca_bundle_rejected_at_config_load() {
        // Security-reviewer HIGH finding on task 2.5: `discovery = "srv"` combined with a
        // non-empty `ca_bundle_path` (private-CA/air-gap mode) must fail closed at config-load
        // time — SRV-resolved endpoints never carry a `pinned_identity`, so this combination
        // would otherwise collapse private-CA trust to an unpinned DNS-hint check (ADR 0017
        // (a)'s rejected "Option A" impersonation hole).
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
        let file = write_toml(
            "[federation]\ndiscovery = \"srv\"\nca_bundle_path = \"/etc/meridian/fed-ca.pem\"\n",
        );

        let err = Config::load(Some(file.path().to_str().unwrap()))
            .expect_err("srv discovery + private CA bundle must be rejected, not silently loaded");

        assert!(err.to_string().contains("ca_bundle_path"));
    }

    #[test]
    fn discovery_srv_without_ca_bundle_is_accepted() {
        // The rejected combination is specifically SRV + private CA — plain SRV discovery in
        // WebPKI mode (the common case) must still load cleanly.
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
        let file = write_toml("[federation]\ndiscovery = \"srv\"\n");

        let config = Config::load(Some(file.path().to_str().unwrap()))
            .expect("srv discovery without a private CA bundle must be accepted");

        assert_eq!(config.federation.discovery, DiscoveryMode::Srv);
    }

    #[test]
    fn static_discovery_with_private_ca_bundle_is_accepted() {
        // Private-CA mode is exactly what `discovery = "static"` (federation_map.toml, mandatory
        // per-partner `pinned_identity`) is designed for — must not be caught by the srv-specific
        // rejection.
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
        let file = write_toml(
            "[federation]\ndiscovery = \"static\"\nca_bundle_path = \"/etc/meridian/fed-ca.pem\"\n",
        );

        let config = Config::load(Some(file.path().to_str().unwrap()))
            .expect("static discovery with a private CA bundle must be accepted");

        assert_eq!(config.federation.ca_bundle_path, "/etc/meridian/fed-ca.pem");
    }

    #[test]
    fn no_env_vars_set_leaves_config_untouched() {
        let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);

        let config = Config::from_toml_str(
            r#"
            [server]
            domain = "from-file.example"
            "#,
        )
        .unwrap();

        assert_eq!(config.server.domain, "from-file.example");
    }
}
