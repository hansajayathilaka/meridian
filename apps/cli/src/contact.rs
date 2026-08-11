//! `meridian contact add/list/rename/block` — the reference CLI surface over
//! [`meridian_core::trust::TrustStore`] (task 4.6).
//!
//! **Petnames are assigned only by explicit local user input** — never populated from a QR
//! payload, an `mrd1:` ID, or any wire field (`docs/architecture/system-design.md` §3.1; feature
//! spec 08 §3.1). This is a threat-model invariant, not a style choice: a spoofed "petname"
//! arriving via any wire path is exactly the kind of thing a malicious peer or server would try.
//!
//! Concretely, the only two sources this module ever reads a petname *value* from are:
//! 1. the `--petname` flag on `contact add` / the required positional argument on `contact
//!    rename`, both plain `String`s typed by the operator invoking this CLI; and
//! 2. [`prompt_petname`], an interactive terminal prompt, used only when `--petname` was omitted
//!    and stdin is actually a TTY (never when piped/scripted, so automated flows never block on
//!    stdin and never silently pick up unrelated data).
//!
//! Every other value derived from the peer's `mrd1:…@domain` id — `peer.hint()`, `peer.pubkey()`,
//! the raw `id` string itself — is used **only** for [`TrustStore::observe`]'s `hint` parameter
//! (which `trust.rs` already documents as "never authoritative on its own for principal identity")
//! and for display of the id itself; none of it is ever passed to
//! [`TrustStore::set_petname`]. See `apps/cli/tests/contact_mgmt.rs` for the test that pins this
//! down: an id whose hint contains a name-like string never ends up as that contact's petname.

use std::io::{IsTerminal, Write};

use meridian_core::identity::{parse_id, KeyHandle, SecretStore};
use meridian_core::trust::{Contact, TrustError, TrustState, TrustStore};

use crate::account;

/// `meridian contact add <id> [--petname <name>]`: TOFU-pins the peer's current key (via
/// [`TrustStore::observe`], identical to what `chat.rs` does on first contact) and, only from
/// `--petname` or the interactive prompt, assigns a local display name.
pub fn cmd_add(
    id: &str,
    petname: Option<String>,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let pubkey = *peer.pubkey();
    let mut trust = load_trust(store, handle)?;

    // `peer.hint()` is the `@domain` portion of the id — an advisory routing hint, never a
    // petname. It is passed to `observe` exactly as `chat.rs` passes it, and nowhere else.
    trust.observe(pubkey, peer.hint(), crate::now_unix());

    // The petname comes ONLY from `--petname`, or — if that was omitted and we're actually
    // talking to a human (stdin is a TTY) — an interactive prompt. Never from `id`/`peer`.
    let petname = match petname {
        Some(p) => Some(p),
        None if std::io::stdin().is_terminal() => prompt_petname()?,
        None => None,
    };
    if let Some(name) = petname {
        trust
            .set_petname(&pubkey, Some(name))
            .map_err(|e| e.to_string())?;
    }

    save_trust(&trust, store, handle)?;
    println!("added {}", peer.to_id_string());
    Ok(())
}

/// `meridian contact list [--json]`.
pub fn cmd_list(json: bool, store: &dyn SecretStore, handle: &KeyHandle) -> Result<(), String> {
    let trust = load_trust(store, handle)?;
    let contacts: Vec<&Contact> = trust.contacts().collect();

    if json {
        for c in &contacts {
            let id = c.id_string().map_err(|e| e.to_string())?;
            let petname = match &c.petname {
                Some(p) => json_string(p),
                None => "null".to_string(),
            };
            println!(
                "{{\"id\":{},\"petname\":{petname},\"hint\":{},\"state\":\"{}\",\"user_blocked\":{}}}",
                json_string(&id),
                json_string(&c.hint),
                state_str(c.state),
                c.user_blocked,
            );
        }
        return Ok(());
    }

    if contacts.is_empty() {
        println!("(no contacts)");
        return Ok(());
    }
    for c in &contacts {
        let id = c.id_string().map_err(|e| e.to_string())?;
        let label = c
            .petname
            .clone()
            .unwrap_or_else(|| "(no petname)".to_string());
        let blocked = if c.user_blocked { "  [blocked]" } else { "" };
        println!("{label:<24} {:<18} {id}{blocked}", state_str(c.state));
    }
    Ok(())
}

/// `meridian contact rename <id> <new-petname>`. An empty `petname` clears it (mirrors
/// [`TrustStore::set_petname`]'s `None`/empty-string equivalence).
pub fn cmd_rename(
    id: &str,
    petname: &str,
    store: &dyn SecretStore,
    handle: &KeyHandle,
) -> Result<(), String> {
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let pubkey = *peer.pubkey();
    let mut trust = load_trust(store, handle)?;

    let value = if petname.is_empty() {
        None
    } else {
        Some(petname.to_string())
    };
    trust
        .set_petname(&pubkey, value)
        .map_err(|e| unknown_contact_message(e, &peer))?;

    save_trust(&trust, store, handle)?;
    if petname.is_empty() {
        println!("cleared petname for {}", peer.to_id_string());
    } else {
        println!("renamed {} to \"{petname}\"", peer.to_id_string());
    }
    Ok(())
}

/// `meridian contact block <id>` — a purely local, user-initiated block
/// ([`meridian_core::trust::Contact::user_blocked`]), independent of the key-change
/// `TrustState::Blocked` the trust module already enforces.
pub fn cmd_block(id: &str, store: &dyn SecretStore, handle: &KeyHandle) -> Result<(), String> {
    let peer = parse_id(id).map_err(|e| e.to_string())?;
    let pubkey = *peer.pubkey();
    let mut trust = load_trust(store, handle)?;

    trust
        .set_user_blocked(&pubkey, true)
        .map_err(|e| unknown_contact_message(e, &peer))?;

    save_trust(&trust, store, handle)?;
    println!("blocked {}", peer.to_id_string());
    Ok(())
}

fn unknown_contact_message(e: TrustError, peer: &meridian_core::identity::Identity) -> String {
    match e {
        TrustError::UnknownContact => format!(
            "no contact recorded for {} — run `meridian contact add` first",
            peer.to_id_string()
        ),
        other => other.to_string(),
    }
}

fn state_str(state: TrustState) -> &'static str {
    match state {
        TrustState::New => "new",
        TrustState::Pinned => "pinned",
        TrustState::Verified => "verified",
        TrustState::Blocked => "blocked (key change)",
        TrustState::PinnedKeyChanged => "warn (key change)",
    }
}

/// Interactive petname prompt — only ever reached when stdin is a TTY (see [`cmd_add`]). An empty
/// line (just pressing Enter) skips assigning a petname.
fn prompt_petname() -> Result<Option<String>, String> {
    print!("Petname for this contact (optional, Enter to skip): ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// (task 4.4) Load the sealed [`TrustStore`] — identical shape/behavior to `chat.rs`'s
/// `load_trust` (same fail-closed-on-tamper contract; ADR 0021 condition 5b).
fn load_trust(store: &dyn SecretStore, handle: &KeyHandle) -> Result<TrustStore, String> {
    let path = account::trust_path()?;
    match std::fs::read(&path) {
        Ok(sealed) => TrustStore::open_at_rest(store, handle, &sealed)
            .map_err(|e| format!("opening trust store {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Mirrors `chat.rs`'s `save_trust` exactly.
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

/// Minimal JSON string escaping for `--json` output — mirrors `chat.rs`'s `json_string`.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    //! Unit coverage for the petname-never-from-wire invariant at the `TrustStore` call boundary
    //! this module owns — the end-to-end CLI-process version (constructing a real `mrd1:` id/QR
    //! payload with a name-like string embedded in its hint) lives in
    //! `apps/cli/tests/contact_mgmt.rs`, since that needs a real account + real ID parsing this
    //! unit test would otherwise have to hand-fake.
    use meridian_core::trust::TrustStore;

    /// If a caller (correctly) only ever passes `observe`'s wire-observed `hint` — never as a
    /// petname — the resulting contact has no petname at all. This is the property `cmd_add`
    /// relies on: it calls `observe(pubkey, peer.hint(), …)` unconditionally, then *separately*
    /// (and only conditionally) calls `set_petname`. Simulating a hostile/attacker-chosen hint
    /// containing a name-like string, this asserts `observe` alone — with no `set_petname` call —
    /// never results in a populated petname.
    #[test]
    fn observe_alone_never_populates_petname() {
        let mut trust = TrustStore::default();
        let pubkey = [7u8; 32];
        // A hint crafted to look exactly like a petname a naive implementation might mistakenly
        // promote — e.g. by splitting on '@' and using the local part.
        let hostile_hint = "TotallyLegitAlice.example";
        trust.observe(pubkey, hostile_hint, 1_000);

        let contact = trust.contact(&pubkey).expect("contact recorded");
        assert_eq!(
            contact.hint, hostile_hint,
            "hint is still recorded as advisory metadata"
        );
        assert_eq!(
            contact.petname, None,
            "observe() must never populate petname from the hint, no matter what it looks like"
        );
    }

    /// `set_petname` is the only write path — and it is a distinct call the wire-observation path
    /// never makes on its own behalf.
    #[test]
    fn set_petname_is_the_only_way_to_populate_it() {
        let mut trust = TrustStore::default();
        let pubkey = [9u8; 32];
        trust.observe(pubkey, "attacker-hint.example", 1_000);
        assert_eq!(trust.contact(&pubkey).unwrap().petname, None);

        trust
            .set_petname(&pubkey, Some("Alice (real friend)".to_string()))
            .expect("known contact");
        assert_eq!(
            trust.contact(&pubkey).unwrap().petname.as_deref(),
            Some("Alice (real friend)")
        );
    }
}
