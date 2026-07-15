//! T05 acceptance: relay-policy resolution across org-default / per-user / per-contact scope, and
//! the candidate-class gathering that makes `relay-only` a real privacy guarantee
//! (docs/architecture/features/05-nat-traversal-relay-policy.md, system-design §5.4).

use std::collections::HashMap;

use meridian_core::relay::{self, GatherClasses, PolicyScope, RelayPolicy};
use meridian_core::transport::IcePolicy;

#[test]
fn policy_strings_round_trip() {
    for p in [
        IcePolicy::Direct,
        IcePolicy::PreferRelay,
        IcePolicy::RelayOnly,
    ] {
        assert_eq!(relay::policy_from_str(relay::policy_str(p)), Some(p));
    }
    assert_eq!(relay::policy_from_str("nonsense"), None);
}

#[test]
fn precedence_is_contact_over_user_over_org() {
    let peer = [7u8; 32];
    let other = [9u8; 32];

    // Only an org default: everyone resolves to it.
    let p = RelayPolicy::with_org_default(IcePolicy::PreferRelay);
    assert_eq!(
        p.resolve_scoped(&peer),
        (IcePolicy::PreferRelay, PolicyScope::OrgDefault)
    );

    // A per-user override shadows the org default for every peer without a contact pin.
    let mut per_contact = HashMap::new();
    per_contact.insert(peer, IcePolicy::RelayOnly);
    let p = RelayPolicy {
        org_default: IcePolicy::Direct,
        per_user: Some(IcePolicy::PreferRelay),
        per_contact,
    };
    // The pinned contact wins with relay-only…
    assert_eq!(
        p.resolve_scoped(&peer),
        (IcePolicy::RelayOnly, PolicyScope::PerContact)
    );
    // …an unpinned contact falls to the per-user override…
    assert_eq!(
        p.resolve_scoped(&other),
        (IcePolicy::PreferRelay, PolicyScope::PerUser)
    );
    // …and the plain resolver agrees.
    assert_eq!(p.resolve(&peer), IcePolicy::RelayOnly);
    assert_eq!(p.resolve(&other), IcePolicy::PreferRelay);
}

#[test]
fn default_policy_is_direct_from_org() {
    let p = RelayPolicy::default();
    assert_eq!(
        p.resolve_scoped(&[0u8; 32]),
        (IcePolicy::Direct, PolicyScope::OrgDefault)
    );
}

#[test]
fn relay_only_gathers_no_host_or_srflx() {
    // The load-bearing privacy fact: relay-only never offers host/srflx (invariant 3).
    let g = relay::gather_classes(IcePolicy::RelayOnly);
    assert_eq!(
        g,
        GatherClasses {
            host: false,
            srflx: false,
            relay: true
        }
    );
    assert_eq!(g.describe(), "relay only");

    // direct and prefer-relay both gather all classes (they differ only in pair preference).
    for p in [IcePolicy::Direct, IcePolicy::PreferRelay] {
        let g = relay::gather_classes(p);
        assert!(g.host && g.srflx && g.relay);
        assert_eq!(g.describe(), "host+srflx+relay");
    }
}
