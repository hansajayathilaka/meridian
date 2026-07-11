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
    OsSecretStore, PublicKey, SecretStore, Signature,
};

mod account;
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
