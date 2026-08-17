//! `$MERIDIAN_HOME/tui/config.toml` loader (task 4.14,
//! [ADR 0021](../../../docs/adr/0021-client-local-store-config-formats.md) condition 3).
//!
//! `config.toml` is the one file in the client-local store family that is human-authored and
//! **never rewritten wholesale by the app** (tui-client.md §5) — UI-driven setting changes either
//! write back preserving comments (a later task's concern, `toml_edit`-based) or are stated as
//! session-only. This module only *reads* it.
//!
//! Loaded with `figment`, mirroring `apps/cli/src/policy.rs` and
//! [ADR 0018](../../../docs/adr/0018-rendezvous-config-loading.md)'s pattern exactly:
//! `Toml::file(config.toml)` merged with `Env::prefixed("MERIDIAN_TUI__").split("__")`. A missing
//! file is not an error — [`TuiConfig::default`] applies field-by-field via `#[serde(default)]` —
//! but a malformed one (bad TOML syntax, or a value that doesn't fit the schema, e.g.
//! `theme = "neon"`) is a hard `Err`: fail closed, never a silent fallback.
//!
//! Precedence, lowest to highest: **defaults < `config.toml` < environment < CLI overrides.**
//! `meridian-tui` has no `clap` flags of its own yet (`apps/cli/src/tui.rs`'s environment gate,
//! task 4.12, doesn't accept any that would override TUI settings), so nothing calls
//! [`load`]/[`load_from`] with a non-empty `cli_overrides` today. The slot exists so a future CLI
//! flag parser can plug in without changing this function's signature — see the doc comment on
//! [`load_from`] for the exact shape and why.
//!
//! **No `"v"` field.** Every *sealed* JSON store this ADR governs (`contacts.json`,
//! `history/*.jsonl`, `outbox.json`, and `state.json`) carries a top-level `"v"` for the forward-
//! migration story tui-client.md §5's "Migrations" subsection describes. `config.toml` is
//! deliberately excluded: it is hand-authored TOML, not a sealed/opaque document one version of
//! this binary writes and a later version must read back and migrate in place. Its own key
//! structure (which `[section]`s and fields a given binary understands) already *is* the schema
//! version, in the sense that matters here — an old config loaded by a newer binary just leaves
//! new fields at their defaults (`#[serde(default)]` is field-additive-safe), and — load-bearing on
//! [`deny_unknown_fields`], not merely on `#[serde(default)]` alone, which would otherwise silently
//! *discard* an unrecognized field rather than error on it — a config field renamed or removed in a
//! future schema change is a hard `figment`-reported error at load time, never a silent data-loss
//! migration. If a genuinely breaking, non-additive schema change is ever needed here (e.g. a
//! section itself renamed, not just a field within one), that is new ground this module doesn't
//! cover yet — a `TODO: confirm` in spirit, called out explicitly rather than silently mirroring
//! the JSON stores' `"v"` mechanism where it doesn't apply.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Serialized, Toml};
use figment::value::Value;
use figment::Figment;
use serde::{Deserialize, Serialize};

/// The full `config.toml` schema (tui-client.md §5). Every field has a working default, so a
/// missing file — or a file that only sets a few fields — is never an error.
///
/// `deny_unknown_fields` on every struct in this schema (except the intentionally free-form
/// `[keys]` map) so a typo'd or since-renamed field is a load-time `Err`, not a silently-discarded
/// key — see `unknown_top_level_field_fails_closed`/`unknown_field_in_a_section_fails_closed` in
/// `tests/config.rs`. Without this, `#[serde(default)]` alone would make an unrecognized field
/// vanish rather than error, which is exactly the silent-data-loss ADR 0021's/tui-client.md §5's
/// migration story rules out for every file in this store family.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TuiConfig {
    pub account: AccountConfig,
    pub ui: UiConfig,
    pub history: HistoryConfig,
    pub network: NetworkConfig,
    /// Free-form command → keybinding rebinds (`quit = "ctrl-q"`). Deliberately stringly-typed:
    /// the set of rebindable commands is the palette's own, open-ended set (task 4.16+), not a
    /// small closed enum this crate can enumerate today.
    pub keys: BTreeMap<String, String>,
}

/// `[account]` — currently just an optional server override; the registration-time value is used
/// when absent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    pub server: Option<String>,
}

/// `[ui]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub theme: Theme,
    pub unicode: bool,
    pub mouse: bool,
    pub timestamps: Timestamps,
    pub compact: bool,
    pub bell: Bell,
    /// Opt-in OSC 52 clipboard copy — off by default (ADR 0021 / tui-client.md §6.6: some
    /// multiplexers log clipboard writes).
    pub osc52_copy: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            unicode: true,
            mouse: false,
            timestamps: Timestamps::default(),
            compact: false,
            bell: Bell::default(),
            osc52_copy: false,
        }
    }
}

/// A small, closed set of values — a real enum rather than a bare `String` (unlike
/// `apps/cli/src/policy.rs`'s stored policy strings, which stay loosely typed because they're
/// validated against `meridian_core::relay`'s own parser instead of re-declaring its variants
/// here). `#[serde(rename_all = "kebab-case")]` matches the TOML strings verbatim (`auto`, `dark`,
/// `light`, `mono` all happen to have no internal word boundary, so kebab-case and lowercase
/// coincide for this one).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    #[default]
    Auto,
    Dark,
    Light,
    Mono,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Timestamps {
    #[default]
    Relative,
    Clock,
    Off,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bell {
    Never,
    #[default]
    Message,
    Mention,
}

/// `[history]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// `0` = keep forever; `N` = prune older than N days at startup.
    pub retain_days: u32,
    /// `0` = unlimited.
    pub max_messages_per_conversation: u32,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            retain_days: 0,
            max_messages_per_conversation: 10_000,
        }
    }
}

/// `[network]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub policy: NetworkPolicy,
    pub reconnect_backoff_ms: Vec<u64>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            policy: NetworkPolicy::default(),
            reconnect_backoff_ms: vec![500, 1000, 2000, 5000, 15000],
        }
    }
}

/// `inherit` (the default — follow `policy.json`, ADR 0018) or a direct pin, using the same
/// canonical strings as `meridian_core::relay::{policy_from_str, policy_str}`
/// (`direct | prefer-relay | relay-only`), plus the TUI-only `inherit` value that isn't part of
/// that enum. Kept as a distinct type rather than reusing `meridian_transport::IcePolicy` directly
/// so `inherit` — which has no `IcePolicy` equivalent — has somewhere to live; resolving `inherit`
/// against the loaded `policy.json` is the caller's job (task 4.24 and friends), not this loader's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    #[default]
    Inherit,
    Direct,
    PreferRelay,
    RelayOnly,
}

/// The default on-disk path: `$MERIDIAN_HOME/tui/config.toml` (tui-client.md §5's layout),
/// reusing `meridian_core::account::config_dir` — the same `$MERIDIAN_HOME` resolution
/// `account.json`/`policy.json`/`sessions.bin` already use, so a `MERIDIAN_HOME` override affects
/// this file identically to the rest of the client-local store.
pub fn default_config_path() -> Result<PathBuf, String> {
    Ok(meridian_core::account::config_dir()?
        .join("tui")
        .join("config.toml"))
}

/// Loads [`TuiConfig`] from `$MERIDIAN_HOME/tui/config.toml`, with no CLI overrides. The common
/// case until `meridian tui` (or `meridian-tui`'s own entry point) grows real flags — see
/// [`load_from`] for the override seam this delegates to.
pub fn load(cli_overrides: &[(String, String)]) -> Result<TuiConfig, String> {
    load_from(&default_config_path()?, cli_overrides)
}

/// Loads [`TuiConfig`] from an explicit `config_path`, merged with `MERIDIAN_TUI__<SECTION>__
/// <FIELD>` environment variables and then `cli_overrides`, in ascending precedence order —
/// defaults, then the file, then the environment, then `cli_overrides` win in that order (last
/// merge wins for any given key, same rule ADR 0018/`apps/rendezvous/src/config.rs` document).
///
/// **The override seam.** `cli_overrides` is a list of `("section.field", "raw value")` pairs —
/// dotted key paths matching the TOML section/field names (`"ui.theme"`, `"network.policy"`, …),
/// values as they'd appear on the right-hand side of a TOML/env assignment (`"dark"`,
/// `"true"`, `"[100,200]"`). Each is parsed the same way `figment::providers::Env` parses an
/// environment variable's value — bare `true`/`false`, bare integers/floats, `[...]`/`{...}`
/// structured values, `"..."` quoted strings, anything else as a plain string (see
/// [`figment::value::Value`]'s `FromStr` impl) — so a future flag parser can hand this function
/// raw flag strings without pre-converting them to a typed [`Value`] itself. Nothing constructs a
/// non-empty `cli_overrides` today: `meridian-tui` has no flags of its own (out of scope for this
/// task; see the module doc comment), so every real caller currently passes `&[]`. This is
/// intentionally a `Vec<(String, String)>`-shaped function parameter rather than, say, a second
/// `Figment` parameter — simpler for a future `clap`-derived flag list to build directly, at the
/// cost of one extra parse step this function performs internally.
pub fn load_from(
    config_path: &Path,
    cli_overrides: &[(String, String)],
) -> Result<TuiConfig, String> {
    let mut figment = Figment::new()
        // `Toml::file` silently contributes nothing if the file is simply absent (same reasoning
        // as apps/rendezvous/src/config.rs's `Config::load`) — that alone gives the "no config"
        // default-boot path its non-fatal behavior. A *malformed* file still surfaces as a hard
        // error from `.extract()` below.
        .merge(Toml::file(config_path))
        .merge(Env::prefixed("MERIDIAN_TUI__").split("__"));

    for (key, raw) in cli_overrides {
        // Infallible: `Value::from_str` always succeeds, falling back to a plain string when the
        // input doesn't parse as a bool/number/array/dict (see figment::value::parse).
        let value: Value = raw.parse().unwrap_or_else(|_: std::convert::Infallible| {
            unreachable!("Value::from_str is infallible")
        });
        figment = figment.merge(Serialized::default(key, value));
    }

    figment
        .extract()
        .map_err(|e| format!("loading {}: {e}", config_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_documented_toml_defaults() {
        let cfg = TuiConfig::default();
        assert_eq!(cfg.account.server, None);
        assert_eq!(cfg.ui.theme, Theme::Auto);
        assert!(cfg.ui.unicode);
        assert!(!cfg.ui.mouse);
        assert_eq!(cfg.ui.timestamps, Timestamps::Relative);
        assert!(!cfg.ui.compact);
        assert_eq!(cfg.ui.bell, Bell::Message);
        assert!(!cfg.ui.osc52_copy);
        assert_eq!(cfg.history.retain_days, 0);
        assert_eq!(cfg.history.max_messages_per_conversation, 10_000);
        assert_eq!(cfg.network.policy, NetworkPolicy::Inherit);
        assert_eq!(
            cfg.network.reconnect_backoff_ms,
            vec![500, 1000, 2000, 5000, 15000]
        );
        assert!(cfg.keys.is_empty());
    }
}
