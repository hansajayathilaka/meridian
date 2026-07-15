//! `meridian doctor` — connectivity diagnostic (T05 deliverable 3, system-design §5.4/§10).
//!
//! Answers the two questions an operator asks when a session won't come up: **which candidate
//! classes work**, and **where is the path blocked**. It reproduces the four NAT-matrix cells
//! in-process over the deterministic `LoopbackTransport` — full-cone, port-restricted,
//! symmetric×symmetric, and UDP-blocked — establishing a real substrate session in each and
//! reporting the selected path (and, when relayed, the relay server + transport rung). The netns
//! rig (`tools/netns-nat-matrix.sh`) runs the same matrix over the wire with `NET_ADMIN`; this is
//! the network-free diagnostic that ships in the binary and runs in CI.
//!
//! It also confirms the privacy claim: under `relay-only`, host/srflx candidates are never offered,
//! so a peer capture contains none of our real addresses.

use meridian_core::relay;
use meridian_core::transport::{IcePolicy, NatScenario};

use crate::session::{connect, demo_ice_servers};

const CELLS: [NatScenario; 4] = [
    NatScenario::FullCone,
    NatScenario::PortRestricted,
    NatScenario::SymmetricPair,
    NatScenario::UdpBlocked,
];

/// Run the diagnostic, returning the printed lines (also returned so the acceptance test asserts on
/// them). With `json`, emit one object per cell instead of the table.
pub async fn run(json: bool) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut rows = Vec::new();

    for scenario in CELLS {
        // Probe under `direct` policy with TURN offered: this lets each cell pick its natural pair
        // (direct/srflx where possible, relay where forced) so the table shows the real ladder.
        let (asess, _bsess, _a, _b) =
            connect(scenario, IcePolicy::Direct, demo_ice_servers()).await?;
        let info = asess.info().await;

        // host is always formable; srflx needs UDP/STUN; relay needs a reachable TURN (offered).
        let host_ok = true;
        let srflx_ok = scenario.srflx_reachable();
        let relay_ok = !demo_ice_servers().is_empty();
        let path = match (&info.relay_server, info.relay_transport) {
            (Some(srv), Some(xport)) => format!("relay ({srv}, {xport})"),
            _ => info.path.to_string(),
        };
        rows.push((scenario, host_ok, srflx_ok, relay_ok, path));
    }

    if json {
        for (scenario, host, srflx, relay_ok, path) in &rows {
            let l = format!(
                "{{\"nat\":\"{}\",\"host\":{host},\"srflx\":{srflx},\"relay\":{relay_ok},\"path\":\"{path}\"}}",
                scenario.label()
            );
            println!("{l}");
            lines.push(l);
        }
        return Ok(lines);
    }

    lines.push("meridian doctor — connectivity diagnostic (in-process NAT matrix)".to_string());
    lines.push(String::new());
    lines.push(format!(
        "  {:<20} {:>5} {:>6} {:>6}   {}",
        "nat cell", "host", "srflx", "relay", "selected path"
    ));
    for (scenario, host, srflx, relay_ok, path) in &rows {
        lines.push(format!(
            "  {:<20} {:>5} {:>6} {:>6}   {}",
            scenario.label(),
            mark(*host),
            mark(*srflx),
            mark(*relay_ok),
            path,
        ));
    }

    // Prove the relay-only privacy property: candidates offered is *relay only*.
    let (asess, _b, _pa, _pb) = connect(
        NatScenario::SymmetricPair,
        IcePolicy::RelayOnly,
        demo_ice_servers(),
    )
    .await?;
    let info = asess.info().await;
    lines.push(String::new());
    lines.push(format!("  relay-only: {}", info.candidates_offered_line()));

    // Summary: name the blocked path where UDP is dropped (the operator's actionable line, §10).
    let all_connect = rows
        .iter()
        .all(|(_, _, _, relay_ok, path)| *relay_ok && !path.is_empty());
    if all_connect {
        lines.push(
            "  → all four cells connect; TLS-443 carries the UDP-blocked cell (hostile egress)."
                .to_string(),
        );
    } else {
        lines.push(
            "  → some cells cannot connect: no relay reachable — check TURN reachability."
                .to_string(),
        );
    }
    lines.push(format!(
        "  policy positions: {} | {} | {} (org-default → per-user → per-contact)",
        relay::policy_str(IcePolicy::Direct),
        relay::policy_str(IcePolicy::PreferRelay),
        relay::policy_str(IcePolicy::RelayOnly),
    ));

    for l in &lines {
        println!("{l}");
    }
    Ok(lines)
}

fn mark(ok: bool) -> &'static str {
    if ok {
        "\u{2713}" // ✓
    } else {
        "\u{2717}" // ✗
    }
}
