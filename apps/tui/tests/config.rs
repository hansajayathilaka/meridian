//! `meridian_tui::config` — precedence, missing/malformed-file handling, and the CLI-override
//! seam (task 4.14). Mirrors `apps/rendezvous/src/config.rs`'s own test shape (in-process TOML
//! strings for file content, a guarded `Env` layer for the one test that genuinely needs real
//! process env vars) rather than inventing a different harness.

use std::io::Write;
use std::sync::Mutex;

use meridian_tui::config::{self, Bell, NetworkPolicy, Theme, Timestamps, TuiConfig};

/// `std::env` is process-global; serialize every test in this module that touches it so parallel
/// test threads can't stomp on each other's `MERIDIAN_TUI__*` vars — same pattern as
/// `apps/rendezvous/src/config.rs`'s `ENV_LOCK`/`EnvGuard`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Sets the given vars for the guard's lifetime and clears them on drop, even on panic.
struct EnvGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
    keys: Vec<&'static str>,
}

impl<'a> EnvGuard<'a> {
    fn set(lock: std::sync::MutexGuard<'a, ()>, vars: &[(&'static str, &str)]) -> Self {
        for (k, v) in vars {
            // SAFETY: serialized by ENV_LOCK above; no other thread in this test binary touches
            // these MERIDIAN_TUI__* vars.
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
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(contents.as_bytes()).expect("write");
    f
}

/// A missing `config.toml` is not an error — every field falls back to [`TuiConfig::default`].
#[test]
fn missing_file_yields_defaults_not_an_error() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does-not-exist").join("config.toml");

    let cfg = config::load_from(&path, &[]).expect("missing file must not be an error");
    assert_eq!(cfg, TuiConfig::default());
}

/// A file that exists but isn't valid TOML — or sets a field to a value outside its schema — is a
/// hard, fail-closed error, never a silent fallback to defaults.
#[test]
fn malformed_toml_fails_closed() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("this is not [ valid toml");

    let err = config::load_from(file.path(), &[])
        .expect_err("malformed TOML must be a hard error, not a fallback to defaults");
    assert!(!err.is_empty());
}

/// A schema violation (a value outside the field's closed enum) is caught the same way a
/// malformed-syntax file is — figment's deserialize step rejects it.
#[test]
fn unknown_enum_value_fails_closed() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("[ui]\ntheme = \"neon\"\n");

    assert!(config::load_from(file.path(), &[]).is_err());
}

/// A value set only in `config.toml` (nothing in env, nothing overridden) is used as-is; fields
/// the file doesn't mention keep their defaults.
#[test]
fn file_only_value_is_used_and_other_fields_default() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("[ui]\ntheme = \"dark\"\ncompact = true\n");

    let cfg = config::load_from(file.path(), &[]).expect("valid file");
    assert_eq!(cfg.ui.theme, Theme::Dark);
    assert!(cfg.ui.compact);
    // Untouched fields keep their documented defaults.
    assert_eq!(cfg.ui.bell, Bell::Message);
    assert_eq!(cfg.network.policy, NetworkPolicy::Inherit);
}

/// `MERIDIAN_TUI__<SECTION>__<FIELD>` overrides a value `config.toml` also sets.
#[test]
fn env_var_overrides_file_value() {
    let _guard = EnvGuard::set(
        ENV_LOCK.lock().unwrap(),
        &[("MERIDIAN_TUI__UI__THEME", "light")],
    );
    let file = write_toml("[ui]\ntheme = \"dark\"\n");

    let cfg = config::load_from(file.path(), &[]).expect("valid overrides");
    assert_eq!(cfg.ui.theme, Theme::Light);
}

/// An env var can also set a field `config.toml` never mentions.
#[test]
fn env_var_sets_a_value_absent_from_the_file() {
    let _guard = EnvGuard::set(
        ENV_LOCK.lock().unwrap(),
        &[("MERIDIAN_TUI__HISTORY__RETAIN_DAYS", "30")],
    );
    let file = write_toml("");

    let cfg = config::load_from(file.path(), &[]).expect("valid overrides");
    assert_eq!(cfg.history.retain_days, 30);
}

/// Full precedence chain: defaults < file < env < CLI overrides, all four layers disagreeing on
/// the same key, constructed deterministically in-process (only the env layer needs a real
/// process env var; the CLI-override layer is the in-process `Vec<(String, String)>` seam).
#[test]
fn precedence_order_cli_beats_env_beats_file_beats_defaults() {
    let _guard = EnvGuard::set(
        ENV_LOCK.lock().unwrap(),
        &[("MERIDIAN_TUI__NETWORK__POLICY", "relay-only")],
    );
    let file = write_toml("[network]\npolicy = \"direct\"\n");

    // No overrides yet: env (relay-only) beats file (direct) beats the "inherit" default.
    let cfg = config::load_from(file.path(), &[]).expect("valid");
    assert_eq!(cfg.network.policy, NetworkPolicy::RelayOnly);

    // Adding a CLI override for the same key must win over all three lower layers.
    let overrides = vec![("network.policy".to_string(), "prefer-relay".to_string())];
    let cfg = config::load_from(file.path(), &overrides).expect("valid");
    assert_eq!(cfg.network.policy, NetworkPolicy::PreferRelay);
}

/// A CLI override for a list-typed field parses the same bracketed syntax `Env` accepts.
#[test]
fn cli_override_parses_structured_values() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("");

    let overrides = vec![(
        "network.reconnect_backoff_ms".to_string(),
        "[100,200,300]".to_string(),
    )];
    let cfg = config::load_from(file.path(), &overrides).expect("valid");
    assert_eq!(cfg.network.reconnect_backoff_ms, vec![100, 200, 300]);
}

/// A CLI override for a bool-typed field also parses correctly, not as the literal string
/// `"true"`.
#[test]
fn cli_override_parses_bool_values() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("");

    let overrides = vec![("ui.unicode".to_string(), "false".to_string())];
    let cfg = config::load_from(file.path(), &overrides).expect("valid");
    assert!(!cfg.ui.unicode);
}

/// `[keys]` is a free-form map: an arbitrary rebind round-trips.
#[test]
fn keys_table_round_trips_as_a_free_form_map() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("[keys]\nquit = \"ctrl-q\"\n");

    let cfg = config::load_from(file.path(), &[]).expect("valid");
    assert_eq!(cfg.keys.get("quit").map(String::as_str), Some("ctrl-q"));
}

/// `Timestamps`/`Bell` round-trip through the file the same way `Theme` does, for coverage of the
/// remaining closed-enum fields.
#[test]
fn timestamps_and_bell_parse_from_file() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("[ui]\ntimestamps = \"off\"\nbell = \"never\"\n");

    let cfg = config::load_from(file.path(), &[]).expect("valid");
    assert_eq!(cfg.ui.timestamps, Timestamps::Off);
    assert_eq!(cfg.ui.bell, Bell::Never);
}

/// A field that has never existed in this schema, at the top level of the file, is a load-time
/// error — never silently discarded. Without `deny_unknown_fields`, `#[serde(default)]` alone
/// would make this vanish instead of erroring, which is exactly the silent-data-loss failure mode
/// the module doc's "No `\"v\"` field" reasoning depends on not happening.
#[test]
fn unknown_top_level_field_fails_closed() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("nonexistent_top_level_field = true\n");

    let err = config::load_from(file.path(), &[])
        .expect_err("an unrecognized top-level key must be a hard error, not silently dropped");
    assert!(!err.is_empty());
}

/// Same as above, but for a field inside a known section — the case a future field rename
/// (`[ui] theme` → `[ui] color-theme`, say) would actually hit: the *section* is still recognized,
/// only one field within it is stale.
#[test]
fn unknown_field_in_a_section_fails_closed() {
    let _guard = EnvGuard::set(ENV_LOCK.lock().unwrap(), &[]);
    let file = write_toml("[ui]\nthem_typo = \"dark\"\n");

    let err = config::load_from(file.path(), &[]).expect_err(
        "an unrecognized field inside a known section must be a hard error, not silently \
         dropped while the rest of the section loads normally",
    );
    assert!(!err.is_empty());
}
