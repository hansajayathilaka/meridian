//! `meridian verify <mrd1-id>` — the safety-number compare/verify UX (task 4.5) on top of T03's
//! already-landed computation (`meridian_crypto::fingerprint::safety_number`/`display_groups`,
//! re-exported as `meridian_core::crypto::{safety_number, display_groups}`) and T01's QR primitives
//! (`meridian_core::identity::{render_terminal, decode_luma}`). No new cryptography lives here —
//! this module only displays/compares the already-frozen fingerprint and, on a confirmed match,
//! calls the existing [`TrustStore::mark_verified`] (task 4.3/4.4); see `verification-ux.md` for
//! the canonical, un-softenable wording this flow must preserve.
//!
//! Two modes, matching the task's scope:
//! - Interactive (no `--scan-file`): prints the 60-digit number (grouped for readability) and a
//!   terminal QR encoding the raw digits, then asks the operator to confirm the numbers matched
//!   what the peer is showing — the actual comparison happens **out-of-band** (in person, an
//!   existing trusted channel, or a video call), never over the channel being verified
//!   (`verification-ux.md` "Safety-number verification"). A blank/non-affirmative answer is
//!   treated as "not verified" (fail closed) — mirrors `contact.rs`'s prompt style.
//! - Headless (`--scan-file <path>`): decodes a QR image (e.g. one the peer displayed and this
//!   operator photographed/scanned) via [`decode_luma`] and compares the decoded digits against
//!   the number computed locally; only an exact match marks the contact verified.
//!
//! Either way, marking verified requires the peer to already be a known contact (`meridian contact
//! add` first) — [`TrustStore::mark_verified`] errors [`TrustError::UnknownContact`] otherwise,
//! which this module reports the same way `contact.rs` does.

use std::io::{IsTerminal, Write};
use std::path::Path;

use meridian_core::identity::{
    decode_luma, parse_id, render_terminal, Identity, KeyHandle, SecretStore,
};
use meridian_core::trust::{TrustError, TrustStore};

use crate::account;

/// `meridian verify <id> [--scan-file <path>]`.
pub fn cmd_verify(
    id: &str,
    own_pubkey: &[u8; 32],
    scan_file: Option<&Path>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let peer_pubkey = *peer.pubkey();
    let number = meridian_core::crypto::safety_number(own_pubkey, &peer_pubkey);

    let confirmed = match scan_file {
        Some(path) => scan_and_compare(path, &number, &peer)?,
        None => display_and_confirm(&number, &peer)?,
    };

    if !confirmed {
        return Err(format!(
            "safety number NOT verified for {} — contact remains unverified",
            peer.to_id_string()
        ));
    }

    let mut trust = load_trust(store, handle)?;
    trust
        .mark_verified(&peer_pubkey)
        .map_err(|e| unknown_contact_message(e, &peer))?;
    save_trust(&trust, store, handle)?;
    println!("contact marked VERIFIED for {}", peer.to_id_string());
    Ok(())
}

/// Headless `--scan-file` compare: decode the QR image at `path` and compare its digits against
/// the locally computed `number`, byte-for-byte.
fn scan_and_compare(path: &Path, number: &str, peer: &Identity) -> Result<bool, String> {
    let img = image::open(path)
        .map_err(|e| format!("reading QR image {}: {e}", path.display()))?
        .to_luma8();
    let decoded = decode_luma(&img).map_err(|e| e.to_string())?;

    if decoded == number {
        println!(
            "MATCH — safety number for {} confirmed.",
            peer.to_id_string()
        );
        Ok(true)
    } else {
        println!(
            "MISMATCH — the scanned code does not match the safety number computed locally for \
             {}. This can mean a stale/wrong scan, or that someone is intercepting your \
             messages. Do not mark this contact verified; re-check the code with them directly \
             through a channel you trust.",
            peer.to_id_string()
        );
        Ok(false)
    }
}

/// Interactive display + confirm: print the number/QR, then ask the operator whether both sides
/// saw the same thing.
fn display_and_confirm(number: &str, peer: &Identity) -> Result<bool, String> {
    println!("Safety number for {}:", peer.to_id_string());
    println!();
    println!("  {}", meridian_core::crypto::display_groups(number));
    println!();
    let qr = render_terminal(number).map_err(|e| e.to_string())?;
    println!("{qr}");
    println!(
        "Compare this number and QR code with {} out-of-band — in person, over an existing \
         trusted channel, or on a video call. Never confirm over the channel you are trying to \
         verify.",
        peer.to_id_string()
    );

    if !std::io::stdin().is_terminal() {
        println!(
            "(not an interactive terminal — re-run with --scan-file, or run this interactively, \
             to complete verification)"
        );
        return Ok(false);
    }

    print!("Did both sides see the identical number/QR? [y/N] ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(is_affirmative(&line))
}

/// The confirm prompt's yes/no parse, pulled out as a pure function so the fail-closed behavior
/// gating [`TrustState::Verified`](meridian_core::trust::TrustState::Verified) — the strongest
/// trust guarantee in the system — has a direct regression test independent of a real TTY.
/// Anything other than an exact (trimmed, case-insensitive) `"y"`/`"yes"` is a "no": empty input
/// (bare Enter), `"n"`/`"no"`, garbage, and EOF (an empty `read_line` result) all fail closed.
fn is_affirmative(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn unknown_contact_message(e: TrustError, peer: &Identity) -> String {
    match e {
        TrustError::UnknownContact => format!(
            "no contact recorded for {} — run `meridian contact add` first",
            peer.to_id_string()
        ),
        other => other.to_string(),
    }
}

/// Mirrors `contact.rs`'s `load_trust` exactly (task 4.4's fail-closed-on-tamper contract).
fn load_trust(store: &dyn SecretStore, handle: &KeyHandle) -> Result<TrustStore, String> {
    let path = account::trust_path()?;
    match std::fs::read(&path) {
        Ok(sealed) => TrustStore::open_at_rest(store, handle, &sealed)
            .map_err(|e| format!("opening trust store {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Mirrors `contact.rs`'s `save_trust` exactly.
fn save_trust(
    trust: &TrustStore,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let path = account::trust_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let sealed = trust
        .seal_at_rest(store, handle)
        .map_err(|e| format!("sealing trust store: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    //! Direct, non-interactive coverage of the fail-closed y/N parse gating
    //! `TrustState::Verified` — the integration suite in `apps/cli/tests/verify.rs` deliberately
    //! skips the TTY-gated interactive path (same convention `contact_mgmt.rs` uses for its own
    //! interactive prompt), so this is the only regression coverage for it.
    use super::is_affirmative;

    #[test]
    fn bare_enter_is_not_affirmative() {
        assert!(!is_affirmative("\n"));
        assert!(!is_affirmative(""));
    }

    #[test]
    fn explicit_no_is_not_affirmative() {
        assert!(!is_affirmative("n\n"));
        assert!(!is_affirmative("no\n"));
        assert!(!is_affirmative("N\n"));
    }

    #[test]
    fn garbage_is_not_affirmative() {
        assert!(!is_affirmative("maybe\n"));
        assert!(!is_affirmative("y please\n"));
        assert!(!is_affirmative("yesish\n"));
    }

    #[test]
    fn only_exact_y_or_yes_is_affirmative() {
        assert!(is_affirmative("y\n"));
        assert!(is_affirmative("yes\n"));
        // Case-insensitive and whitespace-trimmed, but still an exact token match.
        assert!(is_affirmative("Y\n"));
        assert!(is_affirmative("YES\n"));
        assert!(is_affirmative("  yes  \n"));
    }
}
