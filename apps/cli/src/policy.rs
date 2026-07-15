//! Client-side relay-policy configuration (T05, system-design §5.4): the
//! `direct | prefer-relay | relay-only` knob at **org-default → per-user → per-contact** scope,
//! persisted next to the account descriptor as `policy.json`.
//!
//! This is the CLI's `meridian config set policy …` surface. The resolution logic itself lives in
//! [`meridian_core::relay::RelayPolicy`]; this module only loads/saves the raw values and maps them
//! onto it, so the precedence rule (contact > user > org) is defined and tested in exactly one
//! place.

use std::collections::BTreeMap;
use std::path::PathBuf;

use meridian_core::identity::parse_id;
use meridian_core::relay::{self, PolicyScope, RelayPolicy};
use meridian_core::transport::IcePolicy;
use serde::{Deserialize, Serialize};

use crate::account;

/// The persisted policy config. Values are the canonical strings (`direct|prefer-relay|relay-only`);
/// `per_contact` is keyed by lowercase-hex account key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredPolicy {
    /// Org-pushed default (the base level). Absent ⇒ `direct`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_default: Option<String>,
    /// This account's override of the org default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    per_user: Option<String>,
    /// Per-contact pins, keyed by hex account key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    per_contact: BTreeMap<String, String>,
}

fn policy_path() -> Result<PathBuf, String> {
    Ok(account::config_dir()?.join("policy.json"))
}

fn load_stored() -> Result<StoredPolicy, String> {
    let path = policy_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("parsing {}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoredPolicy::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn save_stored(p: &StoredPolicy) -> Result<(), String> {
    let path = policy_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(p).map_err(|e| format!("serializing policy: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Build the resolvable [`RelayPolicy`] from stored config (used by `session info` / diagnostics).
pub fn load() -> Result<RelayPolicy, String> {
    let stored = load_stored()?;
    let org_default = stored
        .org_default
        .as_deref()
        .and_then(relay::policy_from_str)
        .unwrap_or(IcePolicy::Direct);
    let per_user = stored.per_user.as_deref().and_then(relay::policy_from_str);
    let mut per_contact = std::collections::HashMap::new();
    for (k, v) in &stored.per_contact {
        if let (Ok(key), Some(pol)) = (decode_key(k), relay::policy_from_str(v)) {
            per_contact.insert(key, pol);
        }
    }
    Ok(RelayPolicy {
        org_default,
        per_user,
        per_contact,
    })
}

/// The scope a `config set` targets.
pub enum SetScope {
    User,
    Org,
    Contact(String),
}

/// `meridian config set policy <value> [--org|--contact <id>]`.
pub fn set(value: &str, scope: SetScope) -> Result<(), String> {
    // Validate the value up front so a typo can't be persisted.
    if relay::policy_from_str(value).is_none() {
        return Err(format!(
            "unknown policy '{value}' (expected direct | prefer-relay | relay-only)"
        ));
    }
    let mut stored = load_stored()?;
    match scope {
        SetScope::User => stored.per_user = Some(value.to_string()),
        SetScope::Org => stored.org_default = Some(value.to_string()),
        SetScope::Contact(id) => {
            let key = decode_key(&id)?;
            stored
                .per_contact
                .insert(hex::encode(key), value.to_string());
        }
    }
    save_stored(&stored)?;
    Ok(())
}

/// `meridian config show` — print the effective policy at each scope.
pub fn show() -> Result<Vec<String>, String> {
    let stored = load_stored()?;
    let policy = load()?;
    let mut lines = Vec::new();
    lines.push(format!(
        "org-default: {}",
        relay::policy_str(policy.org_default)
    ));
    lines.push(format!(
        "per-user:    {}",
        stored
            .per_user
            .as_deref()
            .unwrap_or("(unset — inherits org-default)")
    ));
    if stored.per_contact.is_empty() {
        lines.push("per-contact: (none)".to_string());
    } else {
        lines.push("per-contact:".to_string());
        for (k, v) in &stored.per_contact {
            lines.push(format!("  {k}: {v}"));
        }
    }
    // Show what a peer *with no per-contact pin* resolves to, and which scope wins.
    let (eff, scope) = policy.resolve_scoped(&[0u8; 32]);
    lines.push(format!(
        "→ default effective policy: {} (from {})",
        relay::policy_str(eff),
        match scope {
            PolicyScope::OrgDefault => "org-default",
            PolicyScope::PerUser => "per-user",
            PolicyScope::PerContact => "per-contact",
        }
    ));
    for l in &lines {
        println!("{l}");
    }
    Ok(lines)
}

/// Decode a contact key from either a full `mrd1:…@domain` ID or 64 hex chars.
fn decode_key(s: &str) -> Result<[u8; 32], String> {
    if let Ok(id) = parse_id(s) {
        return Ok(*id.pubkey());
    }
    let raw = hex::decode(s).map_err(|_| format!("'{s}' is neither an mrd1 ID nor 64-hex key"))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| "contact key must be 32 bytes".to_string())
}
