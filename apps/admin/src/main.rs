//! meridian-admin — operator inspection tooling (task 8.11, feature T07).
//!
//! `mailbox dump <pubkey>` is the ONLY subcommand this binary has, on purpose (task file's Scope:
//! "no other `meridian-admin` subcommands... do not scope-creep into a general admin CLI here").
//! It opens the SAME store a real `meridian-rendezvous` deployment would — the same `Config`
//! (`--config <path>`, following that binary's own established flag and fail-closed load
//! behavior) and the same `default_store` helper that picks `SqliteStore`/`MemoryStore` — and
//! prints exactly what an admin with DB access (threat A7) can see. It is not a network client:
//! the feature spec's demo pseudocode shows an illustrative `--server org-b`, which is aspirational
//! demo-script shorthand for "point this at that org's config", not a literal flag — this tool
//! reads a local on-disk store directly, exactly like the server itself does.

use clap::{Parser, Subcommand};
use meridian_rendezvous::{default_store, Config};

#[derive(Parser)]
#[command(
    name = "meridian-admin",
    about = "Meridian operator inspection tooling (T07's mailbox honesty demo)"
)]
struct Args {
    /// Path to the same rendezvous TOML config the target server was started with (see
    /// `meridian-rendezvous --config`) — this tool opens that server's configured store directly.
    /// Same fail-closed behavior as the server binary: an explicitly supplied path that fails to
    /// load is fatal, never a silent fallback to defaults.
    #[arg(long)]
    config: Option<String>,
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Offline ciphertext mailbox inspection (T07's "honesty demo").
    Mailbox {
        #[command(subcommand)]
        cmd: MailboxCommand,
    },
}

#[derive(Subcommand)]
enum MailboxCommand {
    /// Dump exactly what threat A7 (an admin with DB access) can see about one recipient's
    /// mailbox: envelope count, sizes, `arrived_at`/`expires_at`, and an opaque marker per blob —
    /// never its contents. Deliberately has no `--preview`/search/any other convenience flag.
    Dump {
        /// The recipient account's public key, hex-encoded (64 hex chars / 32 bytes) — the same
        /// raw-pubkey format `meridian directory import --org-key` already uses in `apps/cli`.
        pubkey: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Same fail-closed posture as `meridian-rendezvous`'s own `main.rs`: a missing explicit
    // `--config`, a malformed TOML file, or a bad env var are all fatal — never silently proceed
    // against defaults that may not be the deployment actually being inspected.
    let config = match Config::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}; refusing to open a store with an ambiguous config");
            std::process::exit(1);
        }
    };

    // (devops review, task 8.11) `default_store`'s SQLite backend opens with
    // `create_if_missing(true)` — correct for the server's own first-boot bootstrapping, but
    // WRONG for a read-only inspection tool whose entire purpose is honesty about what's really
    // there: a typo'd `--config` path or a `database_url` resolved from the wrong working
    // directory would otherwise silently create a fresh, empty database and report "0 envelopes"
    // indistinguishable from a genuinely empty mailbox — exactly the one case an operator in an
    // incident/audit is least equipped to catch by other means. Fail closed instead: refuse to
    // proceed against a database file that doesn't already exist.
    if let Err(e) = require_existing_database(&config) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    let TopCommand::Mailbox { cmd } = args.command;
    match cmd {
        MailboxCommand::Dump { pubkey } => {
            let recipient = match parse_pubkey(&pubkey) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };
            let store = default_store(&config).await;
            match meridian_admin::dump_mailbox(store.as_ref(), recipient).await {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Refuse to proceed if `config.server.database_url` names a SQLite file that doesn't already
/// exist — see the call site's doc comment for why `default_store`'s own `create_if_missing(true)`
/// (correct for the server, wrong here) must not be allowed to silently fabricate an empty
/// database for this tool. An in-memory URL (`sqlite::memory:` or similar `:memory:` variants) is
/// exempt: it's inherently ephemeral, "created" fresh on every connection by design, not a
/// deployment file a typo could miss.
fn require_existing_database(config: &meridian_rendezvous::Config) -> Result<(), String> {
    let url = &config.server.database_url;
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(url);
    if path.contains(":memory:") {
        return Ok(());
    }
    if !std::path::Path::new(path).exists() {
        return Err(format!(
            "database file {path:?} (from database_url = {url:?}) does not exist — refusing to \
             silently create a fresh, empty one and report it as this deployment's real mailbox. \
             Check --config points at the right server's config and that its database_url is \
             correct."
        ));
    }
    Ok(())
}

/// Parse a raw account public key argument: 64 hex chars / 32 bytes. Errors cleanly (never
/// panics) on malformed input.
fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|_| format!("'{s}' is not a valid hex-encoded pubkey"))?;
    bytes.as_slice().try_into().map_err(|_| {
        format!(
            "pubkey must be 32 bytes (64 hex chars), got {} byte(s)",
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pubkey_accepts_valid_hex() {
        let hex64 = "11".repeat(32);
        let parsed = parse_pubkey(&hex64).unwrap();
        assert_eq!(parsed, [0x11u8; 32]);
    }

    #[test]
    fn parse_pubkey_rejects_non_hex() {
        assert!(parse_pubkey("not-hex-at-all").is_err());
    }

    #[test]
    fn parse_pubkey_rejects_wrong_length() {
        assert!(parse_pubkey("aa").is_err());
        assert!(parse_pubkey(&"aa".repeat(33)).is_err());
    }

    // -- require_existing_database (devops review, task 8.11) --------------------------------

    #[test]
    fn require_existing_database_rejects_a_missing_sqlite_file() {
        let mut config = meridian_rendezvous::Config::default();
        config.server.database_url = "sqlite:///nonexistent/path/rendezvous.db".to_string();
        let err = require_existing_database(&config)
            .expect_err("a database_url pointing at a nonexistent file must be rejected");
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn require_existing_database_accepts_a_real_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut config = meridian_rendezvous::Config::default();
        config.server.database_url = format!("sqlite://{}", file.path().display());
        require_existing_database(&config).expect("an existing file must be accepted");
    }

    #[test]
    fn require_existing_database_exempts_in_memory_urls() {
        let mut config = meridian_rendezvous::Config::default();
        config.server.database_url = "sqlite::memory:".to_string();
        require_existing_database(&config)
            .expect("an in-memory database is inherently ephemeral, never 'missing'");
    }
}
