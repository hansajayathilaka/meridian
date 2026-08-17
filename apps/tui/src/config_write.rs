//! Comment-preserving write-back for `config.toml` (task 4.24) — the write-side counterpart to
//! [`crate::config`]'s figment-based *read* path. That module's own doc comment names exactly this:
//! "UI-driven setting changes either write back preserving comments (a later task's concern,
//! `toml_edit`-based) or are stated as session-only. This module only *reads* it." — this module is
//! that later write-back.
//!
//! ## Why `toml_edit`, not round-tripping through `TuiConfig`
//! [`crate::config::load_from`] discards comments/formatting the moment it deserializes into
//! [`crate::config::TuiConfig`] via `figment`/`serde` — there is no comment-tracking anywhere in
//! that path, so re-serializing a `TuiConfig` snapshot back to disk could never reproduce a
//! hand-authored file's comments. [`toml_edit::DocumentMut`] parses/edits the *raw* document
//! instead: [`write_setting_at`] re-parses `config.toml` fresh from disk on every call, mutates only
//! the one key the caller named, and leaves every other byte — comments, blank lines, key order,
//! even the untouched sections' own formatting — exactly as it was.
//!
//! ## Not part of `crate::store`'s sealed-JSON family
//! `crate::store`'s own module doc is explicit that `config.toml` is "not this module's concern" —
//! it is hand-authored plaintext TOML, never sealed, never migrated via that module's `"v"`-tagged
//! mechanism. This module deliberately does not reuse `crate::store::atomic_write` for that reason
//! (a few duplicated lines of temp-file-then-rename rather than reaching into a sealed-store-shaped
//! helper for a file that is neither sealed nor part of that family) — see [`atomic_write`] below.
//!
//! ## When this honestly refuses (→ the caller's job to mark the change session-only)
//! [`write_setting_at`] never invents a fresh `config.toml` from nothing and never silently drops a
//! requested change — every refusal is a plain, named [`ConfigWriteError`]:
//! - [`ConfigWriteError::NoFile`] — no file exists at the given path yet. tui-client.md §5's "hand-
//!   authored, never rewritten wholesale" rule reads naturally as "there must already be a
//!   hand-authored document to preserve"; authoring one from nothing here would make this module
//!   the very thing it exists to avoid — an app-authored `config.toml` indistinguishable from a
//!   real one, the first version of which was never actually written by a human.
//! - [`ConfigWriteError::Malformed`] — the file doesn't parse as TOML at all (`toml_edit`'s own
//!   parse error, surfaced verbatim). Patching a document this module cannot understand is exactly
//!   the "malformed in a way `toml_edit` can't safely patch" case the task names.
//! - [`ConfigWriteError::NotATable`] — the target section exists but isn't a table (e.g. a
//!   hand-edited file with `account = "oops"` instead of `[account]`). Not reachable through any
//!   `config.toml` this crate's own schema would produce; defensive only.
//! - [`ConfigWriteError::Io`] — any other filesystem failure (permissions, disk full, …).
//!
//! `crate::screens::settings` (the only intended caller, via a future worker executing
//! [`crate::app::Effect::SaveSetting`] — see that variant's own doc for why this module doesn't wire
//! itself into `run_worker` yet, mirroring every other `Effect` in this crate today) turns any of
//! the above into an explicit "session-only, not saved" notice rather than silently discarding the
//! outcome — see that module's own doc for the "never silent" property this exists to support.

use std::fs;
use std::path::{Path, PathBuf};

use toml_edit::{value, Array, DocumentMut, Item, Table};

use crate::app::SettingValue;
use crate::config::{Bell, NetworkPolicy, Theme, Timestamps};

/// Why [`write_setting_at`] refused (or otherwise failed) to persist a change — see the module doc.
#[derive(Debug, thiserror::Error)]
pub enum ConfigWriteError {
    #[error(
        "no config.toml exists yet at {0} — nothing to preserve, refusing to author one from \
         scratch"
    )]
    NoFile(PathBuf),
    #[error("config.toml is not valid TOML: {0}")]
    Malformed(#[source] toml_edit::TomlError),
    #[error("config.toml's [{0}] section is not a table")]
    NotATable(&'static str),
    #[error("writing config.toml: {0}")]
    Io(#[source] std::io::Error),
}

/// Reads `path`, applies `value` to the one key it corresponds to (see [`target`]), and writes the
/// result back to `path` — preserving every comment, blank line, and untouched key exactly. See the
/// module doc for the honest-refusal cases this returns instead of ever silently no-op'ing or
/// authoring a fresh file.
pub fn write_setting_at(path: &Path, value: &SettingValue) -> Result<(), ConfigWriteError> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigWriteError::NoFile(path.to_path_buf()))
        }
        Err(e) => return Err(ConfigWriteError::Io(e)),
    };

    let mut doc: DocumentMut = raw.parse().map_err(ConfigWriteError::Malformed)?;

    let (section, key, item) = target(value);
    let table = doc
        .as_table_mut()
        .entry(section)
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or(ConfigWriteError::NotATable(section))?;

    match item {
        // **`table[key] = item`, deliberately not `Table::insert`.** `Table::insert`'s
        // occupied-entry branch unconditionally calls `key_mut().fmt()` on an already-present key —
        // it resets that key's own decor (the raw text immediately preceding it, which is exactly
        // where a `# comment` line directly above `key = value` lives) to `toml_edit`'s canonical
        // default, silently dropping it. Indexing instead goes through `Table::entry`/`or_insert`,
        // which never touches the key's decor at all — only the `Item` (the value half of the pair)
        // is replaced, which is exactly the "leave every other byte untouched" contract this
        // function exists for. `config_write::tests::
        // write_setting_preserves_comments_and_only_changes_the_targeted_key` pins this directly;
        // this comment exists because an earlier version of this function used `insert` and passed
        // every other test in this file while silently failing that one.
        Some(item) => table[key] = item,
        // `None` values (e.g. `server = None`) are represented by the key's *absence*, mirroring
        // `TuiConfig`'s own `#[serde(default)]` — matches figment/serde's read side exactly, and
        // removing the key (rather than writing `server = ""`/some sentinel) also means a user who
        // clears this field back to "inherit" ends up with a `config.toml` no different from one
        // that never mentioned it, not a lingering empty-string artifact.
        None => {
            table.remove(key);
        }
    }

    atomic_write(path, doc.to_string().as_bytes()).map_err(ConfigWriteError::Io)
}

/// The `(section, key, new Item)` a [`SettingValue`] writes to — `None` for the `Item` means "remove
/// the key" (see [`write_setting_at`]'s `None` arm). String values use the exact same kebab-case
/// spellings [`crate::config`]'s `#[serde(rename_all = "kebab-case")]` enums parse on the way back
/// in — `tests` below round-trips every variant through the real
/// [`crate::config::load_from`] to prove that, rather than merely asserting it by inspection.
fn target(setting_value: &SettingValue) -> (&'static str, &'static str, Option<Item>) {
    match setting_value {
        SettingValue::ServerUrl(v) => ("account", "server", v.as_deref().map(value_item)),
        SettingValue::RelayPolicy(v) => (
            "network",
            "policy",
            Some(value_item(network_policy_str(*v))),
        ),
        SettingValue::Theme(v) => ("ui", "theme", Some(value_item(theme_str(*v)))),
        SettingValue::Timestamps(v) => ("ui", "timestamps", Some(value_item(timestamps_str(*v)))),
        SettingValue::Bell(v) => ("ui", "bell", Some(value_item(bell_str(*v)))),
        SettingValue::RetainDays(v) => ("history", "retain_days", Some(value(*v as i64))),
        SettingValue::MaxMessagesPerConversation(v) => (
            "history",
            "max_messages_per_conversation",
            Some(value(*v as i64)),
        ),
        SettingValue::ReconnectBackoffMs(v) => {
            let arr: Array = v.iter().map(|n| *n as i64).collect();
            ("network", "reconnect_backoff_ms", Some(value(arr)))
        }
    }
}

fn value_item(s: &str) -> Item {
    value(s)
}

fn network_policy_str(p: NetworkPolicy) -> &'static str {
    match p {
        NetworkPolicy::Inherit => "inherit",
        NetworkPolicy::Direct => "direct",
        NetworkPolicy::PreferRelay => "prefer-relay",
        NetworkPolicy::RelayOnly => "relay-only",
    }
}

fn theme_str(t: Theme) -> &'static str {
    match t {
        Theme::Auto => "auto",
        Theme::Dark => "dark",
        Theme::Light => "light",
        Theme::Mono => "mono",
    }
}

fn timestamps_str(t: Timestamps) -> &'static str {
    match t {
        Timestamps::Relative => "relative",
        Timestamps::Clock => "clock",
        Timestamps::Off => "off",
    }
}

fn bell_str(b: Bell) -> &'static str {
    match b {
        Bell::Never => "never",
        Bell::Message => "message",
        Bell::Mention => "mention",
    }
}

/// Writes `bytes` to `path` via a same-directory temp file + rename, so a crash mid-write leaves
/// either the old file or the new one intact, never a truncated/partial one — the same shape
/// `crate::store::atomic_write` uses, deliberately duplicated rather than shared (see the module
/// doc's "not part of `crate::store`'s sealed-JSON family" section).
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    if let Err(e) = fs::write(&tmp_path, bytes) {
        // Best-effort cleanup: the real `path` is untouched either way, but don't leave a stray
        // `.tmp` file behind on e.g. a disk-full failure. Its own result is deliberately ignored —
        // this is cleanup, not load-bearing, and the original `e` is what the caller needs to see.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_from, NetworkPolicy};

    /// A representative hand-authored `config.toml` — comments, blank lines, an out-of-order
    /// section, and a value this test never touches (`ui.unicode`) — everything
    /// [`write_setting_at`] must leave byte-identical except the one line it's asked to change.
    const SAMPLE: &str = r#"# Meridian TUI configuration
# See docs/architecture/tui-client.md §5 for the full schema.

[account]
# Override the server this account registered against.
server = "old.example"

[ui]
theme = "dark"
unicode = true # keep box-drawing characters

[network]
policy = "direct"
reconnect_backoff_ms = [500, 1000, 2000]
"#;

    fn write_sample(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        path
    }

    /// **The load-bearing round-trip**: editing one field via [`write_setting_at`] leaves every
    /// comment, blank line, and untouched key byte-identical — only the targeted line's value
    /// changes. This is the "genuinely persist with comments intact" branch of this task's own
    /// "never silent" deliverable; see `apps/tui/tests/screens_settings.rs` for the sibling
    /// session-only branch exercised through the screen itself.
    #[test]
    fn write_setting_preserves_comments_and_only_changes_the_targeted_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(&dir);

        write_setting_at(
            &path,
            &SettingValue::ServerUrl(Some("new.example".to_string())),
        )
        .expect("write-back succeeds against a real, existing config.toml");

        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(
            updated.contains("# Meridian TUI configuration"),
            "top comment survived"
        );
        assert!(
            updated.contains("# Override the server this account registered against."),
            "the field's own comment survived"
        );
        assert!(
            updated.contains("unicode = true # keep box-drawing characters"),
            "an untouched key + its trailing comment survived verbatim"
        );
        assert!(
            updated.contains(r#"server = "new.example""#),
            "the targeted key actually changed"
        );
        assert!(
            !updated.contains("old.example"),
            "the old value is really gone, not merely shadowed"
        );
        // Every other section/key is untouched too.
        assert!(updated.contains(r#"theme = "dark""#));
        assert!(updated.contains(r#"policy = "direct""#));
        assert!(updated.contains("reconnect_backoff_ms = [500, 1000, 2000]"));
    }

    /// Clearing an `Option<String>` field back to `None` removes the key entirely rather than
    /// writing an empty-string sentinel — see [`write_setting_at`]'s own doc on its `None` arm.
    #[test]
    fn clearing_server_url_removes_the_key_rather_than_writing_empty_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(&dir);

        write_setting_at(&path, &SettingValue::ServerUrl(None)).unwrap();

        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(!updated.contains("server ="));
        assert!(updated.contains("[account]"), "the section header stays");
    }

    /// A missing file is an honest, named refusal — never a fabricated fresh `config.toml`.
    #[test]
    fn no_file_is_an_honest_refusal_not_a_fabricated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");

        let err = write_setting_at(&path, &SettingValue::RetainDays(30)).unwrap_err();
        assert!(matches!(err, ConfigWriteError::NoFile(_)));
        assert!(!path.exists(), "never created from nothing");
    }

    /// A file that doesn't parse as TOML at all is also an honest refusal, not a silent skip or a
    /// panic.
    #[test]
    fn malformed_file_is_an_honest_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is [ not valid toml").unwrap();

        let err = write_setting_at(&path, &SettingValue::RetainDays(30)).unwrap_err();
        assert!(matches!(err, ConfigWriteError::Malformed(_)));
        // The file itself is left untouched, not partially rewritten.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "this is [ not valid toml"
        );
    }

    /// A section written as a scalar rather than a table is a defensive, named refusal, not a
    /// panic.
    #[test]
    fn non_table_section_is_an_honest_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "account = \"oops\"\n").unwrap();

        let err = write_setting_at(
            &path,
            &SettingValue::ServerUrl(Some("x.example".to_string())),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigWriteError::NotATable("account")));
    }

    /// Every enum [`SettingValue`] variant, round-tripped through the *real* config loader
    /// ([`crate::config::load_from`]) — proves this module's hand-written kebab-case strings
    /// actually match what `crate::config`'s `#[serde(rename_all = "kebab-case")]` enums parse,
    /// rather than trusting that by inspection alone.
    #[test]
    fn enum_values_round_trip_through_the_real_config_loader() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(&dir);

        for policy in [
            NetworkPolicy::Inherit,
            NetworkPolicy::Direct,
            NetworkPolicy::PreferRelay,
            NetworkPolicy::RelayOnly,
        ] {
            write_setting_at(&path, &SettingValue::RelayPolicy(policy)).unwrap();
            let loaded = load_from(&path, &[]).expect("still valid TOML after write-back");
            assert_eq!(loaded.network.policy, policy);
        }

        for theme in [Theme::Auto, Theme::Dark, Theme::Light, Theme::Mono] {
            write_setting_at(&path, &SettingValue::Theme(theme)).unwrap();
            let loaded = load_from(&path, &[]).unwrap();
            assert_eq!(loaded.ui.theme, theme);
        }

        for timestamps in [Timestamps::Relative, Timestamps::Clock, Timestamps::Off] {
            write_setting_at(&path, &SettingValue::Timestamps(timestamps)).unwrap();
            let loaded = load_from(&path, &[]).unwrap();
            assert_eq!(loaded.ui.timestamps, timestamps);
        }

        for bell in [Bell::Never, Bell::Message, Bell::Mention] {
            write_setting_at(&path, &SettingValue::Bell(bell)).unwrap();
            let loaded = load_from(&path, &[]).unwrap();
            assert_eq!(loaded.ui.bell, bell);
        }
    }

    /// The two numeric fields and the backoff list, also round-tripped through the real loader.
    #[test]
    fn numeric_and_list_values_round_trip_through_the_real_config_loader() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(&dir);

        write_setting_at(&path, &SettingValue::RetainDays(45)).unwrap();
        assert_eq!(load_from(&path, &[]).unwrap().history.retain_days, 45);

        write_setting_at(&path, &SettingValue::MaxMessagesPerConversation(0)).unwrap();
        assert_eq!(
            load_from(&path, &[])
                .unwrap()
                .history
                .max_messages_per_conversation,
            0
        );

        write_setting_at(
            &path,
            &SettingValue::ReconnectBackoffMs(vec![100, 200, 400, 800]),
        )
        .unwrap();
        assert_eq!(
            load_from(&path, &[]).unwrap().network.reconnect_backoff_ms,
            vec![100, 200, 400, 800]
        );

        // An empty backoff list is representable too (an empty TOML array, not key removal).
        write_setting_at(&path, &SettingValue::ReconnectBackoffMs(Vec::new())).unwrap();
        assert_eq!(
            load_from(&path, &[]).unwrap().network.reconnect_backoff_ms,
            Vec::<u64>::new()
        );
    }
}
