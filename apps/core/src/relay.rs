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

/// The candidate classes a policy *intends* to gather. `relay-only` never offers host/srflx
/// (invariant 3) — but this is the policy's promise, not a measurement. [`observed_classes`] is
/// the corresponding measurement of what a transport actually produced (F20); prefer it wherever a
/// live session is available. This function stays useful before a session exists (e.g. `doctor`'s
/// static preview of what a policy *would* gather).
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

/// The class of one *actually gathered* ICE candidate line (F20) — the observation-based
/// counterpart to the policy's mere intent. Recognizes both the standard ICE-SDP form
/// (`candidate:<foundation> <component> <proto> <priority> <addr> <port> typ <type> ...`, as
/// produced by a real backend) and `LoopbackTransport`'s shorthand (`candidate:<type> ...`, the
/// type immediately after the `candidate:` prefix instead of a separate `typ` field), so the same
/// classifier works against both the simulated and the real transport. Peer-reflexive (`prflx`) is
/// folded into `Srflx`: both reveal a real, routable address to the far side, which is exactly what
/// `relay-only` must never do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateClass {
    Host,
    Srflx,
    Relay,
}

fn classify_token(tok: &str) -> Option<CandidateClass> {
    match tok {
        "host" => Some(CandidateClass::Host),
        "srflx" | "prflx" => Some(CandidateClass::Srflx),
        "relay" => Some(CandidateClass::Relay),
        _ => None,
    }
}

/// Classify a raw candidate line. `None` means the line didn't parse as either recognized format —
/// callers enforcing the relay-only invariant must treat that as worst-case, not as "relay", since
/// silently accepting an unrecognized line would defeat the whole point of observing reality instead
/// of trusting intent.
pub fn candidate_class(line: &str) -> Option<CandidateClass> {
    let mut tokens = line.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "typ" {
            return classify_token(tokens.next()?);
        }
    }
    let first = line.strip_prefix("candidate:")?.split_whitespace().next()?;
    classify_token(first)
}

/// The candidate classes **actually gathered**, from the raw lines a transport produced — the
/// measurement backing the `candidates offered:` line in `session info`/`doctor` once a session
/// exists (F20). An unparseable line is folded into both `host` and `srflx` (worst case) so a
/// malformed or unexpected candidate format can never silently read as clean.
pub fn observed_classes(candidates: &[String]) -> GatherClasses {
    let mut classes = GatherClasses {
        host: false,
        srflx: false,
        relay: false,
    };
    for c in candidates {
        match candidate_class(c) {
            Some(CandidateClass::Host) => classes.host = true,
            Some(CandidateClass::Srflx) => classes.srflx = true,
            Some(CandidateClass::Relay) => classes.relay = true,
            None => {
                classes.host = true;
                classes.srflx = true;
            }
        }
    }
    classes
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_standard_ice_sdp_form() {
        // The form a real backend (webrtc-rs) produces.
        assert_eq!(
            candidate_class("candidate:1 1 udp 2122260223 192.168.1.5 51268 typ host generation 0"),
            Some(CandidateClass::Host)
        );
        assert_eq!(
            candidate_class("candidate:2 1 udp 1686052607 203.0.113.9 51269 typ srflx raddr 192.168.1.5 rport 51268"),
            Some(CandidateClass::Srflx)
        );
        assert_eq!(
            candidate_class("candidate:3 1 udp 41886047 203.0.113.9 3478 typ prflx"),
            Some(CandidateClass::Srflx)
        );
        assert_eq!(
            candidate_class(
                "candidate:4 1 udp 25108223 198.51.100.7 3478 typ relay raddr 0.0.0.0 rport 0"
            ),
            Some(CandidateClass::Relay)
        );
    }

    #[test]
    fn classifies_loopback_shorthand_form() {
        // `LoopbackTransport`'s own format: type right after `candidate:`, no `typ` token.
        assert_eq!(
            candidate_class("candidate:host 7 127.0.0.1"),
            Some(CandidateClass::Host)
        );
        assert_eq!(
            candidate_class("candidate:srflx 7 203.0.113.7"),
            Some(CandidateClass::Srflx)
        );
        assert_eq!(
            candidate_class("candidate:relay 7 turn.example.org gen=1"),
            Some(CandidateClass::Relay)
        );
    }

    #[test]
    fn unrecognized_line_classifies_as_none() {
        assert_eq!(candidate_class("not a candidate at all"), None);
        assert_eq!(candidate_class(""), None);
    }

    #[test]
    fn observed_classes_folds_unparseable_lines_into_worst_case() {
        let g = observed_classes(&["garbage".to_string()]);
        assert!(g.host && g.srflx && !g.relay);
    }

    #[test]
    fn observed_classes_matches_the_actual_lines() {
        let g = observed_classes(&[
            "candidate:relay 1 turn.example.org".to_string(),
            "candidate:relay 2 turn.example.org".to_string(),
        ]);
        assert_eq!(
            g,
            GatherClasses {
                host: false,
                srflx: false,
                relay: true
            }
        );
    }
}
