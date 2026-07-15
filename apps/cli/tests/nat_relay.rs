//! T05 acceptance: the relay-policy demo, the NAT matrix (`meridian doctor`), and the policy config
//! surface, driven through the real binary
//! (docs/architecture/features/05-nat-traversal-relay-policy.md "Working output").

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

fn run(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().expect("run meridian");
    assert!(
        out.status.success(),
        "`meridian {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn symmetric_nat_relays_over_udp() {
    // ./testrig up --nat symmetric:symmetric → path=relay (turn-a, udp)
    let text = run(&["session", "demo", "--nat", "symmetric"]);
    assert!(
        text.contains("path=relay (turn-a, udp)"),
        "expected relay/udp path: {text}"
    );
}

#[test]
fn udp_blocked_falls_back_to_tls_443() {
    // ./testrig up --block-udp → path=relay (turn-a, tls-443) ← hostile-egress fallback
    let text = run(&["session", "demo", "--nat", "udp-blocked"]);
    assert!(
        text.contains("path=relay (turn-a, tls-443)"),
        "expected TLS-443 fallback: {text}"
    );
}

#[test]
fn relay_only_never_offers_host_or_srflx() {
    // meridian session info → candidates offered: relay only; peer never saw our host/srflx IPs
    let text = run(&["session", "demo", "--policy", "relay-only"]);
    assert!(
        text.contains("candidates offered: relay only; peer never saw our host/srflx IPs"),
        "missing relay-only privacy line: {text}"
    );
    assert!(
        text.contains("policy=relay-only"),
        "policy not surfaced: {text}"
    );
}

#[test]
fn doctor_connects_all_four_cells() {
    let text = run(&["doctor"]);
    for cell in [
        "full-cone",
        "port-restricted",
        "symmetric:symmetric",
        "udp-blocked",
    ] {
        assert!(text.contains(cell), "doctor missing cell {cell}: {text}");
    }
    assert!(
        text.contains("relay (turn-a, tls-443)"),
        "doctor should show TLS-443 for the udp-blocked cell: {text}"
    );
    assert!(
        text.contains("all four cells connect"),
        "doctor should report all cells connect: {text}"
    );
}

#[test]
fn config_set_and_show_policy_round_trips() {
    // Persist under an isolated MERIDIAN_HOME so the test never touches the developer's config.
    let tmp = std::env::temp_dir().join(format!("meridian-t05-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let home = tmp.to_str().unwrap();

    let set = Command::new(BIN)
        .args(["config", "set", "policy", "relay-only"])
        .env("MERIDIAN_HOME", home)
        .output()
        .expect("run config set");
    assert!(set.status.success());

    let show = Command::new(BIN)
        .args(["config", "show"])
        .env("MERIDIAN_HOME", home)
        .output()
        .expect("run config show");
    let text = String::from_utf8_lossy(&show.stdout);
    assert!(
        text.contains("per-user:    relay-only"),
        "per-user policy not persisted: {text}"
    );
    assert!(
        text.contains("effective policy: relay-only (from per-user)"),
        "effective policy wrong: {text}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
