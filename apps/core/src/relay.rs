//! Relay policy — the `direct | prefer-relay | relay-only` knob at org-default, per-user, and
//! per-contact scope (T05, system-design §5.4).
//!
//! This is the client-side resolution of the P2P-latency vs. IP-privacy tension. The policy governs
//! **which ICE candidate classes are gathered at all**: `relay-only` strips host/srflx *before*
//! gathering, so a peer never learns our addresses (webrtc-nat-traversal invariant 3). We resolve a
//! single effective policy per peer from three levels, then hand the transport an [`IceConfig`]
//! carrying that policy plus the ephemeral TURN servers minted by the rendezvous.
//!
//! The precedence — **per-contact overrides per-user overrides org-default** — lets an org set a
//! floor (e.g. `prefer-relay` for everyone) while a user tightens a single sensitive contact to
//! `relay-only`, or (never the reverse of intent) an org that mandates `relay-only` cannot be
//! loosened per-contact below its default. We surface the trade; we do not decide it (§5.4).

use std::collections::HashMap;

use meridian_transport::{IceConfig, IcePolicy, IceServer};

/// Parse the three policy positions from their canonical CLI/config strings.
pub fn policy_from_str(s: &str) -> Option<IcePolicy> {
    match s {
        "direct" => Some(IcePolicy::Direct),
        "prefer-relay" => Some(IcePolicy::PreferRelay),
        "relay-only" => Some(IcePolicy::RelayOnly),
        _ => None,
    }
}

/// The canonical string for a policy (round-trips with [`policy_from_str`]).
pub fn policy_str(p: IcePolicy) -> &'static str {
    match p {
        IcePolicy::Direct => "direct",
        IcePolicy::PreferRelay => "prefer-relay",
        IcePolicy::RelayOnly => "relay-only",
    }
}

/// Which scope supplied the effective policy — reported by `meridian session info`/`config` so the
/// operator can see *why* a session is on the path it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyScope {
    OrgDefault,
    PerUser,
    PerContact,
}

impl PolicyScope {
    pub fn label(self) -> &'static str {
        match self {
            PolicyScope::OrgDefault => "org-default",
            PolicyScope::PerUser => "per-user",
            PolicyScope::PerContact => "per-contact",
        }
    }
}

/// The three-level relay policy. `org_default` is the base (pushed by the org, §9.2); `per_user` is
/// the local account's override; `per_contact` pins individual peers.
#[derive(Clone, Debug)]
pub struct RelayPolicy {
    pub org_default: IcePolicy,
    pub per_user: Option<IcePolicy>,
    pub per_contact: HashMap<[u8; 32], IcePolicy>,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            org_default: IcePolicy::Direct,
            per_user: None,
            per_contact: HashMap::new(),
        }
    }
}

impl RelayPolicy {
    /// A policy with just an org default.
    pub fn with_org_default(org_default: IcePolicy) -> Self {
        Self {
            org_default,
            per_user: None,
            per_contact: HashMap::new(),
        }
    }

    /// Resolve the effective policy for `peer`, and which scope won. Precedence: contact > user >
    /// org.
    pub fn resolve_scoped(&self, peer: &[u8; 32]) -> (IcePolicy, PolicyScope) {
        if let Some(p) = self.per_contact.get(peer) {
            (*p, PolicyScope::PerContact)
        } else if let Some(p) = self.per_user {
            (p, PolicyScope::PerUser)
        } else {
            (self.org_default, PolicyScope::OrgDefault)
        }
    }

    /// The effective policy for `peer`.
    pub fn resolve(&self, peer: &[u8; 32]) -> IcePolicy {
        self.resolve_scoped(peer).0
    }
}

/// Which candidate classes a policy offers to a peer — used for the `candidates offered:` line in
/// `session info` and `doctor`, and to prove `relay-only` offers *only* relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatherClasses {
    pub host: bool,
    pub srflx: bool,
    pub relay: bool,
}

impl GatherClasses {
    /// A short description, e.g. `relay only` or `host+srflx+relay`.
    pub fn describe(self) -> String {
        if self.host || self.srflx {
            let mut parts = Vec::new();
            if self.host {
                parts.push("host");
            }
            if self.srflx {
                parts.push("srflx");
            }
            if self.relay {
                parts.push("relay");
            }
            parts.join("+")
        } else if self.relay {
            "relay only".to_string()
        } else {
            "none".to_string()
        }
    }
}

/// The candidate classes a policy gathers. `relay-only` never offers host/srflx (invariant 3).
pub fn gather_classes(policy: IcePolicy) -> GatherClasses {
    match policy {
        IcePolicy::RelayOnly => GatherClasses {
            host: false,
            srflx: false,
            relay: true,
        },
        // direct / prefer-relay both gather everything; they differ only in pair *preference*.
        _ => GatherClasses {
            host: true,
            srflx: true,
            relay: true,
        },
    }
}

/// Build the [`IceConfig`] for a session: the resolved policy plus the ephemeral TURN servers minted
/// by the rendezvous (and optional STUN). The transport enforces the policy at gather time.
pub fn ice_config(
    policy: IcePolicy,
    ice_servers: Vec<IceServer>,
    stun_servers: Vec<String>,
) -> IceConfig {
    IceConfig {
        stun_servers,
        ice_servers,
        policy,
    }
}
