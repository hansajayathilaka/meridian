//! Task 2.9 acceptance: client-side federation error taxonomy.
//!
//! Drives two real, in-process `meridian-rendezvous` servers ("A" = alice's home server, "B" =
//! bob's) connected over a real s2s mTLS link (task 2.4, mirrors
//! `apps/rendezvous/tests/federation_fetch.rs`'s PKI/harness), then runs the real `meridian` CLI
//! binary as a subprocess (mirrors `apps/cli/tests/rendezvous_demo.rs`) fetching a cross-org
//! bundle through it — end to end, exactly the path a user drives.
//!
//! Two scenarios, matching the task's acceptance criteria:
//! - a `closed`-policy org B → `meridian fetch-bundle` exits clean and non-zero, naming the cause
//!   (`federation denied`), and does so **quickly** — never a hang.
//! - the stale-hint case (B has no record of the target — indistinguishable, from this one wire
//!   response, from "never registered" and "re-registered at a different org", task 2.9's own risk
//!   note) → the output says **"unreachable at hint"**.
//!
//! Both assertions additionally grep the full output (stdout + stderr) for the canonical
//! security-warning/verification vocabulary (`docs/security/verification-ux.md`) and assert its
//! **absence** — the reachability-vs-security distinction this task exists to keep, checked as
//! code rather than merely claimed in a doc comment.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use meridian_proto::{fed_error_codes, FedErr, FedFrame, FedOp};
use meridian_rendezvous::config::{DiscoveryMode, Federation, FederationPolicyMode};
use meridian_rendezvous::federation::{FederationListener, FederationTlsPaths};
use meridian_rendezvous::{AppState, MemoryStore};

mod support;
use support::{base_config, spawn_c2s, spawn_federation, write_federation_map, TestCa, BIN};

/// Generous enough for two real in-process servers + one real s2s round trip on a loaded CI box,
/// while still being a real, enforced bound: a genuine hang (the failure mode this task exists to
/// close off) would sit at "forever", not "a few seconds late" — this catches that distinction
/// without being so tight it flakes on a slow machine.
const NO_HANG_TIMEOUT: Duration = Duration::from_secs(20);

/// A's federation config: dials out to B, pinning to B's own domain (a straightforward,
/// non-adversarial private-CA setup — the pinned-identity mismatch attack is 2.7's job, not this
/// task's).
fn org_a_federation(
    dir: &Path,
    ca: &TestCa,
    a_domain: &str,
    b_domain: &str,
    b_fed_addr: SocketAddr,
) -> Federation {
    let id = ca.issue(dir, "a", a_domain);
    let map_path = write_federation_map(dir, &[(b_domain, b_fed_addr, b_domain)]);
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: map_path.to_str().unwrap().to_string(),
        // A's own OUTBOUND admission policy (task 3.1, review finding F1) — always `open` here:
        // both scenarios in this file are about B's response (closed-policy denial or a stale
        // hint), never about A refusing to dial out in the first place. `Federation::default()`'s
        // fail-closed `Closed` would otherwise make A deny before ever reaching B, which is a
        // different, untested code path in this file.
        policy: FederationPolicyMode::Open,
        ..Federation::default()
    }
}

/// B's federation config: never dials out in these tests, but still needs a syntactically valid
/// (partner-less) map, per `AppState::new`'s fail-loud-at-boot federation runtime.
fn org_b_federation(
    dir: &Path,
    ca: &TestCa,
    b_domain: &str,
    policy: FederationPolicyMode,
) -> Federation {
    let id = ca.issue(dir, "b", b_domain);
    let empty_map = support::write(dir, "b-federation_map.toml", "");
    Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: id.cert_path_str().to_string(),
        key_path: id.key_path_str().to_string(),
        ca_bundle_path: id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: empty_map.to_str().unwrap().to_string(),
        policy,
        ..Federation::default()
    }
}

/// Stand up org-a (dialing out) + org-b (the federation target), returning A's c2s URL — the only
/// endpoint the CLI ever talks to (the routing invariant).
async fn stand_up_two_orgs(dir: &Path, ca: &TestCa, b_policy: FederationPolicyMode) -> String {
    let mut b_config = base_config("org-b.test");
    b_config.federation = org_b_federation(dir, ca, "org-b.test", b_policy);
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state).await;

    let mut a_config = base_config("org-a.test");
    a_config.federation = org_a_federation(dir, ca, "org-a.test", "org-b.test", b_fed_addr);
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    spawn_c2s(a_state).await
}

// -- CLI driver (mirrors apps/cli/tests/rendezvous_demo.rs) --------------------------------------
//
// NOTE: this file's `Client::run` is bounded by `NO_HANG_TIMEOUT` on EVERY call (not just the
// explicit fetch-bundle one under test) — a real, deliberate difference from the shared
// `support::Client` (whose `run` is unbounded, matching `federation_route_hint.rs`/
// `session_connect_federation.rs`/`two_orgs_walkthrough.rs`'s original shape). Migrating this
// file's CLI-driver bits onto the shared `Client` would silently weaken that bound, so this small
// piece stays local (only the PKI/server-boot harness above moved to `support`) — see this task's
// report for why.

struct Client {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Client {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }

    /// Run `meridian <args>` to completion, but **bounded**: a real hang (the exact failure mode
    /// this task exists to close off) fails the test loudly instead of wedging the whole suite.
    /// `Command::output()` alone has no timeout at all, which would make "no hang" unfalsifiable.
    fn run_bounded(&self, args: &[&str], timeout: Duration) -> Output {
        let mut child = Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn meridian binary");
        let start = Instant::now();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_status) => return child.wait_with_output().expect("collect output"),
                None => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!(
                            "meridian {args:?} did not exit within {timeout:?} — treated as a \
                             hang, exactly the failure mode task 2.9 exists to close off"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_bounded(args, NO_HANG_TIMEOUT)
    }

    fn new_account(&self, keyfile: &str, hint: &str) {
        let out = self.run(&[
            "id", "new", "--store", "file", "--out", keyfile, "--hint", hint,
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The canonical security/verification vocabulary this task's whole point is to keep OUT of a
/// reachability failure's copy (docs/security/verification-ux.md; `BundleVerification`'s own
/// wording in `apps/signaling/src/error.rs`). Checked as a real, explicit assertion rather than
/// merely asserted in prose — this is the "no security warning" property from the task file.
const SECURITY_COPY_MARKERS: &[&str] = &[
    "FATAL",
    "signature does not match",
    "safety number",
    "intercept",
    "verify the new safety number",
    "key change",
    "substitut",
];

fn assert_no_security_copy(combined: &str) {
    let lower = combined.to_ascii_lowercase();
    for marker in SECURITY_COPY_MARKERS {
        assert!(
            !lower.contains(&marker.to_ascii_lowercase()),
            "a reachability/policy failure must NEVER emit security-warning copy — found \
             {marker:?} in output:\n{combined}"
        );
    }
}

// -- Scenario 1: closed-policy org -> clean, non-zero, no hang, named cause ----------------------

#[test]
fn closed_policy_org_produces_a_clean_non_zero_exit_never_a_hang() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let a_c2s_url = rt.block_on(stand_up_two_orgs(
        dir.path(),
        &ca,
        FederationPolicyMode::Closed,
    ));

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");

    // Bob's identity never needs to exist at B for this scenario — B's `closed` policy rejects on
    // policy alone, before any target lookup (mirrors
    // `federation_fetch.rs::closed_policy_at_b_is_reported_as_fed_denied`).
    let bob = Client::new();
    bob.new_account("bob.key", "org-b.test");
    let bob_id = bob.id();

    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &a_c2s_url]);

    // Clean, non-zero exit — never a panic/crash, never a hang (enforced above by `run_bounded`).
    assert!(
        !out.status.success(),
        "a closed-policy org must fail the fetch, non-zero exit; stdout={}",
        stdout(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must exit cleanly (a defined exit code), not be killed/signalled"
    );

    let combined = format!("{}{}", stdout(&out), stderr(&out));
    // A named, diagnosable cause — not a bare "error" with no context.
    assert!(
        combined.to_ascii_lowercase().contains("denied") && combined.contains("org-b.test"),
        "expected a named federation-denied cause mentioning org-b.test, got: {combined}"
    );
    assert_no_security_copy(&combined);
}

// -- Scenario 2: stale hint -> "unreachable at hint", never a security warning -------------------

#[test]
fn stale_hint_reports_unreachable_at_hint_never_a_security_warning() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let rt = tokio::runtime::Runtime::new().unwrap();
    // B is Open — the point here is that B genuinely has no record of the target, exactly the
    // stale-hint acceptance scenario (Bob re-registered at org-c, so org-b either never had him or
    // no longer does — indistinguishable from this one wire response, task 2.9's own risk note).
    let a_c2s_url = rt.block_on(stand_up_two_orgs(
        dir.path(),
        &ca,
        FederationPolicyMode::Open,
    ));

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");

    // A syntactically valid id hinting at org-b.test that never published anything there.
    let ghost = Client::new();
    ghost.new_account("ghost.key", "org-b.test");
    let ghost_id = ghost.id();

    let out = alice.run(&["fetch-bundle", &ghost_id, "--server", &a_c2s_url]);

    assert!(
        !out.status.success(),
        "a stale/unknown hint must fail the fetch, non-zero exit; stdout={}",
        stdout(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must exit cleanly (a defined exit code), not be killed/signalled"
    );

    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        combined.contains("unreachable at hint"),
        "expected the literal phrase 'unreachable at hint', got: {combined}"
    );
    assert!(
        combined.contains("org-b.test"),
        "expected the hint domain to be named, got: {combined}"
    );
    assert_no_security_copy(&combined);
}

// -- Scenario 3: a hostile foreign server's free-form FedErr.msg must never reach the client -----
// (task 3.21, finding N1). Scenarios 1/2 above drive a real, honest `meridian-rendezvous` as org B,
// which only ever emits FIXED, code-mapped copy — so they cannot, by construction, prove this
// property: an honest B never sends attacker-chosen text in the first place. This scenario stands
// up a ROGUE B that speaks the real s2s wire protocol directly (real mTLS handshake, real `FedHello`,
// real `FedFrame`/`FedErr` bytes — never a Rust value handed straight to a function under test) and
// have it answer with a `FedErr.msg` a hostile/compromised partner might actually send, then assert
// that text never survives into what `meridian fetch-bundle` prints.

/// A suspicious `FedErr.msg` string: a plausible fake system message (the kind of text that would
/// be actively harmful if forwarded verbatim into a victim's terminal) plus a control character (a
/// bell, `\x07`) that has no legitimate business in this CLI's output at all — either fragment
/// leaking is sufficient to prove the free-form-message passthrough this task closes off.
const HOSTILE_FED_ERR_MSG: &str =
    "SYSTEM ALERT: your account is compromised, call +1-555-0199 immediately\u{7}";

/// Bind a rogue s2s mTLS listener presenting a cert for `domain`, signed by `ca` — the SAME
/// private CA `org_a_federation` pins org A's dial to, so the handshake succeeds exactly as it
/// would against a real, honest B — that answers the very first frame of the very first inbound
/// link with `FedFrame{op: Err, body: FedErr{policy_denied, HOSTILE_FED_ERR_MSG}}`, regardless of
/// what op that frame actually was. One reply is all either code path under test
/// (`federated_fetch_error_reply`'s or `federated_route_error_reply`'s `Fed(fed_err)` arm) needs to
/// see.
async fn rogue_hostile_federation_server(dir: &Path, ca: &TestCa, domain: &str) -> SocketAddr {
    let identity = ca.issue(dir, "rogue", domain);
    let paths = FederationTlsPaths {
        cert_path: identity.cert_path_str(),
        key_path: identity.key_path_str(),
        ca_bundle_path: identity.ca_bundle_path_str(),
    };
    let listener = FederationListener::bind("127.0.0.1:0", &paths, domain, None)
        .await
        .expect("bind rogue federation listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut link, _peer_addr)) = listener.accept().await {
            if let Ok(req) = link.recv_frame().await {
                let err = FedErr {
                    code: fed_error_codes::POLICY_DENIED.to_string(),
                    msg: HOSTILE_FED_ERR_MSG.to_string(),
                };
                if let Ok(reply) = FedFrame::new(FedOp::Err, req.id, &err) {
                    let _ = link.send_frame(&reply).await;
                }
            }
        }
    });
    addr
}

#[test]
fn hostile_foreign_fed_err_msg_never_reaches_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let a_c2s_url = rt.block_on(async {
        let b_fed_addr = rogue_hostile_federation_server(dir.path(), &ca, "org-b.test").await;

        let mut a_config = base_config("org-a.test");
        a_config.federation =
            org_a_federation(dir.path(), &ca, "org-a.test", "org-b.test", b_fed_addr);
        let a_store = Arc::new(MemoryStore::new());
        let a_state = AppState::new(a_config, a_store);
        spawn_c2s(a_state).await
    });

    let alice = Client::new();
    alice.new_account("alice.key", "org-a.test");

    // A syntactically valid id hinting at org-b.test — the rogue server never inspects the
    // request, so what account it names is irrelevant to this scenario.
    let ghost = Client::new();
    ghost.new_account("ghost.key", "org-b.test");
    let ghost_id = ghost.id();

    let out = alice.run(&["fetch-bundle", &ghost_id, "--server", &a_c2s_url]);

    assert!(
        !out.status.success(),
        "a policy-denied fetch must fail, non-zero exit; stdout={}",
        stdout(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must exit cleanly (a defined exit code), not be killed/signalled"
    );

    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !combined.contains(HOSTILE_FED_ERR_MSG),
        "the hostile FedErr.msg leaked verbatim into client-visible output: {combined}"
    );
    assert!(
        !combined.to_ascii_lowercase().contains("system alert") && !combined.contains("555-0199"),
        "a fragment of the hostile FedErr.msg leaked into client-visible output: {combined}"
    );
    assert!(
        !combined.chars().any(|c| c == '\u{7}'),
        "a raw control character from the hostile FedErr.msg leaked into client-visible output"
    );
    // Only the mapped local code's fixed copy — never the foreign server's own text.
    assert!(
        combined.contains("federation denied") && combined.contains("org-b.test"),
        "expected the fixed fed_denied copy naming org-b.test, got: {combined}"
    );
    assert_no_security_copy(&combined);
}
