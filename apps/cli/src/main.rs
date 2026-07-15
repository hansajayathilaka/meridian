//! meridian-cli — terminal client entry point and the T01 identity demo driver.
//!
//! Feature spec + demo script: ../../docs/architecture/features/01-identity-keystore-core.md
//! Frozen ID format: ../../docs/api/identity-format.md
//!
//! Subcommands (all under `meridian id`): `new`, `show [--qr]`, `parse`, `sign`, `verify`,
//! `export`, `import`. Identity logic lives in `meridian-core`; this binary is only orchestration
//! + terminal I/O.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use meridian_core::identity::{
    self, generate_account, parse_id, pubkey_from_seed, sign, verify, FileSecretStore, KeyHandle,
    MemorySecretStore, OsSecretStore, PublicKey, SecretStore, Signature,
};
use meridian_core::signaling::{SignalError, SignalingClient, DEFAULT_OTK_COUNT};

mod account;
mod chat;
mod doctor;
mod opacity;
mod policy;
mod session;
use account::{AccountDescriptor, StoreKind};

const OS_KEYSTORE_SERVICE: &str = "meridian";

#[derive(Parser)]
#[command(
    name = "meridian",
    version,
    about = "Meridian terminal client (T01: identity)"
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Identity & keystore operations.
    Id {
        #[command(subcommand)]
        cmd: IdCommand,
    },
    /// Register the current account with a rendezvous server and publish a prekey bundle.
    Register {
        /// Rendezvous WebSocket URL (e.g. `ws://127.0.0.1:8443`; `wss://` needs a TLS build/proxy).
        #[arg(long, default_value = "ws://127.0.0.1:8443")]
        server: String,
        /// Admission token for invite-only servers.
        #[arg(long)]
        invite: Option<String>,
    },
    /// Fetch and verify a peer's prekey bundle by their `mrd1:…@domain` ID.
    FetchBundle {
        /// The peer's full ID (exact key — no prefixes).
        id: String,
        /// Rendezvous WebSocket URL to ask (your own server).
        #[arg(long, default_value = "ws://127.0.0.1:8443")]
        server: String,
        /// TEST HOOK: ask the server to substitute a key (malicious-server demo); honored only by
        /// a server started with `allow_test_tamper = true`.
        #[arg(long)]
        tamper: bool,
    },
    /// Open an end-to-end-encrypted chat with a peer, relayed through the rendezvous (T03).
    Chat {
        /// The peer's full `mrd1:…@domain` ID.
        id: String,
        /// Rendezvous WebSocket URL.
        #[arg(long, default_value = "ws://127.0.0.1:8443")]
        server: String,
        /// Headless line mode: emit/consume one JSON object per line instead of a TUI.
        #[arg(long)]
        json: bool,
    },
    /// P2P session substrate (T04): run the direct-connection demo (servers out of the data path).
    Session {
        #[command(subcommand)]
        cmd: SessionCommand,
    },
    /// Connectivity diagnostic (T05): which candidate classes work and where the path is blocked.
    Doctor {
        /// Headless: emit one JSON object per NAT cell instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Client configuration (T05): the relay policy knob (`direct|prefer-relay|relay-only`).
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
    /// Demos and audits (T03: opacity audit).
    Demo {
        #[command(subcommand)]
        cmd: DemoCommand,
    },
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Establish a P2P session between two in-process peers, drop the rendezvous, and show chat
    /// continuing over the data channel (the T04 headline demo). `--nat`/`--policy` reproduce the
    /// T05 relay-policy ladder so the `session info` line shows the selected path and *why*.
    Demo {
        /// Headless: emit one JSON status object instead of the human-readable transcript.
        #[arg(long)]
        json: bool,
        /// Relay policy: `direct` (default), `prefer-relay`, or `relay-only`.
        #[arg(long, default_value = "direct")]
        policy: String,
        /// Simulated NAT/egress cell: `full-cone` (default), `port-restricted`,
        /// `symmetric` (=symmetric:symmetric), or `udp-blocked`.
        #[arg(long, default_value = "full-cone")]
        nat: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the effective relay policy at each scope.
    Show,
    /// Set the relay policy. Defaults to the per-user scope; `--org` sets the org default and
    /// `--contact <id>` pins a single peer (per-contact overrides per-user overrides org-default).
    Set {
        /// The setting to change. Only `policy` is supported today.
        key: String,
        /// The value: `direct | prefer-relay | relay-only`.
        value: String,
        /// Set the org-default level instead of per-user.
        #[arg(long)]
        org: bool,
        /// Pin this policy to a single contact (`mrd1:…@domain` ID or 64-hex key).
        #[arg(long)]
        contact: Option<String>,
    },
}

#[derive(Subcommand)]
enum DemoCommand {
    /// Run the opacity audit: scripted E2EE conversation, assert the server sees only opaque blobs.
    OpacityAudit {
        /// Where to write the captured "pcapish" transcript of routed bytes.
        #[arg(default_value = "transcript.pcapish")]
        out: PathBuf,
        /// Number of ping-pong rounds to script.
        #[arg(long, default_value_t = 100)]
        rounds: usize,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum StoreArg {
    /// OS keystore (Keychain / DPAPI / Secret Service). Keys never touch disk in plaintext.
    Os,
    /// Passphrase-wrapped keyfile (age/scrypt) for headless use.
    File,
}

#[derive(Subcommand)]
enum IdCommand {
    /// Create a new account key and store it.
    New {
        /// Where to keep the private key.
        #[arg(long, value_enum, default_value_t = StoreArg::File)]
        store: StoreArg,
        /// Keyfile path for `--store file` (the wrapped private key).
        #[arg(long, default_value = "meridian.key")]
        out: PathBuf,
        /// Home-domain routing hint for the ID.
        #[arg(long, default_value = "chat.example")]
        hint: String,
    },
    /// Show the current account's ID (optionally as a scannable QR).
    Show {
        /// Render a QR code in the terminal.
        #[arg(long)]
        qr: bool,
    },
    /// Parse and validate an `mrd1:…@domain` ID.
    Parse { id: String },
    /// Sign a file with the current account key; writes the hex signature to stdout.
    Sign { file: PathBuf },
    /// Verify a detached signature: `verify <file> <sig> <id>`.
    Verify {
        file: PathBuf,
        sig: PathBuf,
        id: String,
    },
    /// Export the current account as a passphrase-encrypted portable keyfile.
    Export {
        #[arg(long)]
        out: PathBuf,
    },
    /// Import an account from a portable keyfile.
    Import {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = StoreArg::File)]
        store: StoreArg,
        /// Keyfile path for `--store file`.
        #[arg(long, default_value = "meridian.key")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        TopCommand::Id { cmd } => run_id(cmd),
        TopCommand::Register { server, invite } => cmd_register(&server, invite),
        TopCommand::FetchBundle { id, server, tamper } => cmd_fetch_bundle(&id, &server, tamper),
        TopCommand::Chat { id, server, json } => cmd_chat(&id, &server, json),
        TopCommand::Session { cmd } => run_session(cmd),
        TopCommand::Doctor { json } => run_doctor(json),
        TopCommand::Config { cmd } => run_config(cmd),
        TopCommand::Demo { cmd } => run_demo(cmd),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_id(cmd: IdCommand) -> Result<ExitCode, String> {
    match cmd {
        IdCommand::New { store, out, hint } => cmd_new(store, out, hint),
        IdCommand::Show { qr } => cmd_show(qr),
        IdCommand::Parse { id } => cmd_parse(&id),
        IdCommand::Sign { file } => cmd_sign(&file),
        IdCommand::Verify { file, sig, id } => cmd_verify(&file, &sig, &id),
        IdCommand::Export { out } => cmd_export(&out),
        IdCommand::Import { path, store, out } => cmd_import(&path, store, out),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_new(store: StoreArg, out: PathBuf, hint: String) -> Result<ExitCode, String> {
    let descriptor = match store {
        StoreArg::File => {
            let passphrase = read_passphrase(true)?;
            let fs = FileSecretStore::new(&out, passphrase);
            let account = generate_account(&fs, &hint).map_err(|e| e.to_string())?;
            AccountDescriptor::new_file(&account, &out)
        }
        StoreArg::Os => {
            init_os_keystore()?;
            let os = OsSecretStore::new(OS_KEYSTORE_SERVICE);
            let account = generate_account(&os, &hint).map_err(|e| e.to_string())?;
            AccountDescriptor::new_os(&account, OS_KEYSTORE_SERVICE)
        }
    };
    descriptor.save()?;
    println!("Created {}", descriptor.id_string()?);
    Ok(ExitCode::SUCCESS)
}

fn cmd_show(qr: bool) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let id = descriptor.id_string()?;
    if qr {
        let rendered = identity::render_terminal(&id).map_err(|e| e.to_string())?;
        println!("{rendered}");
    }
    println!("{id}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_parse(id: &str) -> Result<ExitCode, String> {
    let identity = parse_id(id).map_err(|e| e.to_string())?;
    println!("key:  {}", hex::encode(identity.pubkey()));
    println!("hint: {}", identity.hint());
    println!("id:   {identity}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_sign(file: &Path) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let msg = std::fs::read(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let handle = KeyHandle::from_label(&descriptor.label);
    let signature = with_store(&descriptor, |store| sign(store, &handle, &msg))?;
    println!("{}", hex::encode(signature.as_bytes()));
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(file: &Path, sig: &Path, id: &str) -> Result<ExitCode, String> {
    let identity = parse_id(id).map_err(|e| e.to_string())?;
    let msg = std::fs::read(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let sig_hex =
        std::fs::read_to_string(sig).map_err(|e| format!("reading {}: {e}", sig.display()))?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|_| "signature file is not valid hex")?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| "signature must be 64 bytes")?;
    let pk = PublicKey::from_bytes(*identity.pubkey()).map_err(|e| e.to_string())?;
    if verify(&pk, &msg, &signature) {
        println!("OK");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("verification failed");
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_export(out: &Path) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let seed = extract_seed(&descriptor)?;
    let passphrase = read_passphrase_labeled(true, "export passphrase")?;
    account::write_portable(out, &seed, &descriptor.hint, &passphrase)?;
    println!("Exported {} to {}", descriptor.id_string()?, out.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_import(path: &Path, store: StoreArg, out: PathBuf) -> Result<ExitCode, String> {
    let passphrase = read_passphrase_labeled(false, "import passphrase")?;
    let (seed, hint) = account::read_portable(path, &passphrase)?;
    let seed_arr: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    let label = hex::encode(pubkey_from_seed(&seed_arr).as_bytes());
    let descriptor = match store {
        StoreArg::File => {
            let keyfile_pass = read_passphrase_labeled(true, "keyfile passphrase")?;
            let fs = FileSecretStore::new(&out, keyfile_pass);
            fs.store(&label, &seed).map_err(|e| e.to_string())?;
            AccountDescriptor::from_parts(
                &seed_arr,
                &hint,
                StoreKind::File,
                Some(out),
                None,
                &label,
            )?
        }
        StoreArg::Os => {
            init_os_keystore()?;
            let os = OsSecretStore::new(OS_KEYSTORE_SERVICE);
            os.store(&label, &seed).map_err(|e| e.to_string())?;
            AccountDescriptor::from_parts(
                &seed_arr,
                &hint,
                StoreKind::Os,
                None,
                Some(OS_KEYSTORE_SERVICE.into()),
                &label,
            )?
        }
    };
    descriptor.save()?;
    println!("Imported {}", descriptor.id_string()?);
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Rendezvous (T02): register + fetch-bundle
// ---------------------------------------------------------------------------

fn cmd_register(server: &str, invite: Option<String>) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let account_pub = account_pub_bytes(&descriptor)?;
    let store = load_store(&descriptor)?;
    let handle = KeyHandle::from_label(&descriptor.label);

    let published = runtime()?.block_on(async {
        let mut client =
            SignalingClient::connect(server, store.as_ref(), &handle, account_pub, invite, 1)
                .await
                .map_err(|e| e.to_string())?;
        let generated = client
            .publish_bundle(store.as_ref(), &handle, DEFAULT_OTK_COUNT)
            .await
            .map_err(|e| e.to_string())?;
        let count = generated.bundle.otk_count();
        let _ = client.close().await;
        Ok::<usize, String>(count)
    })?;

    println!(
        "registered {} — published bundle with {published} one-time prekeys",
        descriptor.id_string()?
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_fetch_bundle(id: &str, server: &str, tamper: bool) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let account_pub = account_pub_bytes(&descriptor)?;
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let target = *peer.pubkey();
    let store = load_store(&descriptor)?;
    let handle = KeyHandle::from_label(&descriptor.label);

    let outcome = runtime()?.block_on(async {
        let mut client =
            SignalingClient::connect(server, store.as_ref(), &handle, account_pub, None, 1).await?;
        let bundle = client.fetch_bundle(target, tamper).await;
        let _ = client.close().await;
        bundle
    });

    match outcome {
        Ok(bundle) => {
            println!(
                "bundle OK, signed by {}, {} OTKs",
                peer.to_id_string(),
                bundle.otk_count()
            );
            Ok(ExitCode::SUCCESS)
        }
        // The security-critical failure: a substituted/mismatched bundle. Fail closed, non-zero.
        Err(e @ SignalError::BundleVerification(_)) => {
            eprintln!("FATAL: {e}");
            Ok(ExitCode::FAILURE)
        }
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Chat (T03) + demos
// ---------------------------------------------------------------------------

fn cmd_chat(id: &str, server: &str, json: bool) -> Result<ExitCode, String> {
    let descriptor = AccountDescriptor::load()?;
    let account_pub = account_pub_bytes(&descriptor)?;
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let peer_ik = *peer.pubkey();
    let store = load_store(&descriptor)?;
    let handle = KeyHandle::from_label(&descriptor.label);

    runtime()?.block_on(chat::run(chat::ChatArgs {
        server: server.to_string(),
        store: store.as_ref(),
        handle: &handle,
        account_pub,
        peer_ik,
        peer_label: peer.to_id_string(),
        json,
    }))?;
    Ok(ExitCode::SUCCESS)
}

fn run_session(cmd: SessionCommand) -> Result<ExitCode, String> {
    match cmd {
        SessionCommand::Demo { json, policy, nat } => {
            let policy = meridian_core::relay::policy_from_str(&policy).ok_or_else(|| {
                format!("unknown policy '{policy}' (expected direct | prefer-relay | relay-only)")
            })?;
            let scenario = meridian_core::transport::NatScenario::parse(&nat).ok_or_else(|| {
                format!(
                    "unknown nat '{nat}' (expected full-cone | port-restricted | symmetric | udp-blocked)"
                )
            })?;
            runtime()?.block_on(session::run_demo(session::DemoOpts {
                json,
                policy,
                scenario,
            }))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_doctor(json: bool) -> Result<ExitCode, String> {
    runtime()?.block_on(doctor::run(json))?;
    Ok(ExitCode::SUCCESS)
}

fn run_config(cmd: ConfigCommand) -> Result<ExitCode, String> {
    match cmd {
        ConfigCommand::Show => {
            policy::show()?;
            Ok(ExitCode::SUCCESS)
        }
        ConfigCommand::Set {
            key,
            value,
            org,
            contact,
        } => {
            if key != "policy" {
                return Err(format!(
                    "unknown config key '{key}' (only 'policy' is supported)"
                ));
            }
            let scope = match (org, contact) {
                (true, _) => policy::SetScope::Org,
                (false, Some(id)) => policy::SetScope::Contact(id),
                (false, None) => policy::SetScope::User,
            };
            policy::set(&value, scope)?;
            println!("set policy {value}");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_demo(cmd: DemoCommand) -> Result<ExitCode, String> {
    match cmd {
        DemoCommand::OpacityAudit { out, rounds } => {
            let report = opacity::run_audit(rounds)?;
            std::fs::write(&out, &report.transcript)
                .map_err(|e| format!("writing {}: {e}", out.display()))?;
            println!(
                "→ {} plaintext leaks; {} envelopes; sizes only observable field",
                report.leaks, report.envelopes
            );
            println!(
                "  transcript ({} bytes) written to {}",
                report.transcript.len(),
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn account_pub_bytes(descriptor: &AccountDescriptor) -> Result<[u8; 32], String> {
    let raw = hex::decode(&descriptor.pubkey).map_err(|_| "descriptor pubkey is not valid hex")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| "descriptor pubkey is not 32 bytes".to_string())
}

/// Open a secret store for signing the auth challenge and the ~100 published prekeys.
///
/// For a passphrase keyfile we unlock it **once** into an in-memory store: signing a bundle means
/// ~100 signatures, and re-running scrypt key-derivation per signature would take minutes. The seed
/// lives in a zeroizing in-memory store for the duration of this one command — equivalent security
/// to per-op unlock for a software keyfile, but O(1) scrypt work instead of O(prekeys). Enclave/OS
/// stores sign per-op (no scrypt) and are used directly.
fn load_store(descriptor: &AccountDescriptor) -> Result<Box<dyn SecretStore>, String> {
    match descriptor.store {
        StoreKind::File => {
            let keyfile = descriptor
                .keyfile
                .as_ref()
                .ok_or("file-store descriptor is missing its keyfile path")?;
            let passphrase = read_passphrase(false)?;
            let fs = FileSecretStore::new(keyfile, passphrase);
            let seed = fs.export_seed().map_err(|e| e.to_string())?;
            let mem = MemorySecretStore::new();
            mem.store(&descriptor.label, seed.as_slice())
                .map_err(|e| e.to_string())?;
            Ok(Box::new(mem))
        }
        StoreKind::Os => {
            init_os_keystore()?;
            Ok(Box::new(OsSecretStore::new(
                descriptor.service.as_deref().unwrap_or(OS_KEYSTORE_SERVICE),
            )))
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting async runtime: {e}"))
}

// ---------------------------------------------------------------------------
// Store plumbing
// ---------------------------------------------------------------------------

/// Run `f` against the secret store the descriptor points at, prompting for a passphrase if the
/// store is a keyfile.
fn with_store<T>(
    descriptor: &AccountDescriptor,
    f: impl FnOnce(&dyn SecretStore) -> Result<T, meridian_core::store::StoreError>,
) -> Result<T, String> {
    match descriptor.store {
        StoreKind::File => {
            let keyfile = descriptor
                .keyfile
                .as_ref()
                .ok_or("file-store descriptor is missing its keyfile path")?;
            let passphrase = read_passphrase(false)?;
            let fs = FileSecretStore::new(keyfile, passphrase);
            f(&fs).map_err(|e| e.to_string())
        }
        StoreKind::Os => {
            init_os_keystore()?;
            let os =
                OsSecretStore::new(descriptor.service.as_deref().unwrap_or(OS_KEYSTORE_SERVICE));
            f(&os).map_err(|e| e.to_string())
        }
    }
}

fn extract_seed(descriptor: &AccountDescriptor) -> Result<Vec<u8>, String> {
    match descriptor.store {
        StoreKind::File => {
            let keyfile = descriptor
                .keyfile
                .as_ref()
                .ok_or("file-store descriptor is missing its keyfile path")?;
            let passphrase = read_passphrase(false)?;
            let fs = FileSecretStore::new(keyfile, passphrase);
            Ok(fs.export_seed().map_err(|e| e.to_string())?.to_vec())
        }
        StoreKind::Os => {
            init_os_keystore()?;
            let os =
                OsSecretStore::new(descriptor.service.as_deref().unwrap_or(OS_KEYSTORE_SERVICE));
            let handle = KeyHandle::from_label(&descriptor.label);
            Ok(os.export_seed(&handle).map_err(|e| e.to_string())?.to_vec())
        }
    }
}

/// Install the platform credential store (via the keyring v1 wrapper). Fails clearly on headless
/// systems that have no Keychain / DPAPI / Secret Service.
fn init_os_keystore() -> Result<(), String> {
    // Constructing any keyring v1 Entry registers the platform store into keyring-core, which our
    // OsSecretStore then uses.
    keyring::Entry::new(OS_KEYSTORE_SERVICE, "__probe__").map_err(|e| {
        format!("OS keystore unavailable ({e}). On headless systems use `--store file` instead.")
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Passphrase input
// ---------------------------------------------------------------------------

/// Read a passphrase. `MERIDIAN_PASSPHRASE` overrides the interactive prompt (for scripting/CI).
fn read_passphrase(confirm: bool) -> Result<String, String> {
    read_passphrase_labeled(confirm, "Passphrase")
}

fn read_passphrase_labeled(confirm: bool, label: &str) -> Result<String, String> {
    if let Ok(p) = std::env::var("MERIDIAN_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password(format!("{label}: ")).map_err(|e| e.to_string())?;
    if confirm {
        let p2 =
            rpassword::prompt_password(format!("Confirm {label}: ")).map_err(|e| e.to_string())?;
        if p != p2 {
            return Err("passphrases do not match".into());
        }
    }
    if p.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    Ok(p)
}
