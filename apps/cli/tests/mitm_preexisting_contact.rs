//! Task 4.10 (T08 trust-state matrix) — the malicious-substitution defense proven in
//! `rendezvous_demo.rs::full_rendezvous_demo` (T02) holds when the victim already has a
//! **pre-existing relationship** with the target identity, not only on first contact.
//!
//! `full_rendezvous_demo` only ever fetches a tampered bundle for a peer alice has never seen
//! before. That leaves a real question unanswered: does the defense still hold once alice already
//! has a trust record for bob, and — the part that test genuinely does not check — does a *failed*
//! substitution attempt leave that pre-existing record completely alone? A gate that happened to
//! only run for brand-new contacts, or that silently mutated an existing one on the way to failing,
//! would both be real defects this file exists to catch.
//!
//! **What this proves, precisely.** Two things, both against a real `meridian-rendezvous` +
//! `test-tamper-hook` server, driven the same subprocess way `rendezvous_demo.rs` is:
//! 1. `fetch-bundle --tamper` against bob still fails exactly like the fresh-contact case (same
//!    `SignalError::BundleVerification` FATAL abort, non-zero exit), even though alice already has
//!    a trust record for bob's real key when the attempt is made.
//! 2. Alice's pre-existing `meridian_core::trust::TrustStore` record for bob — established here via
//!    `meridian contact add`, `contact.rs`'s reference CLI surface over `TrustStore::observe`, the
//!    same primitive `chat.rs` calls on first contact — is **byte-identical**, snapshotted via
//!    `contact list --json`, before and after the failed tampered fetch: no phantom
//!    `PinnedKeyChanged`/`Blocked` state, and no new contact row silently created for the
//!    attacker's substituted key.
//!
//! **What this does NOT prove (scope boundary, house style per `apps/rendezvous/src/auth.rs` and
//! `harnesses/mitm-sim/README.md`).** `meridian fetch-bundle` is a standalone verify-and-print
//! command (`main.rs::cmd_fetch_bundle`) that never reads or writes `TrustStore` at all today —
//! so assertion 2 above is, on today's code, also a **structural** guarantee (there is no call
//! path from a bundle fetch into the trust store for this command to have taken), not merely an
//! empirically-observed one. It is still real, non-vacuous coverage: it pins that fact down as a
//! regression test, so that a future change wiring `fetch-bundle` (or a `chat`-flow equivalent)
//! into trust bookkeeping cannot silently start writing a failed/tampered fetch's substituted key
//! into an existing contact's record without this test catching it. The *decision-gate* half of
//! "does a substituted key ever reach `TrustStore` while a recovery flow is already in progress" —
//! the case that genuinely does exercise `TrustStore::observe_key_change`/`can_send` — is covered
//! in-process, without a live network layer, by
//! `apps/core/tests/desync_recovery.rs::attempt_recovery_routes_a_surfaced_key_change_through_the_gate_never_bypassing_it`
//! (both the `Pinned` and `Verified` starting states). This file's contribution is the network+CLI
//! layer's own share of the property: that layer's failure path touches nothing, for a contact
//! that already existed before the attack was attempted.

use std::process::{Command, Output};
use std::sync::mpsc;

use meridian_rendezvous::{serve, AppState, Config, MemoryStore};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Mirrors `rendezvous_demo.rs::spawn_server` exactly.
fn spawn_server(allow_tamper: bool) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut config = Config::default();
            config.server.allow_test_tamper = allow_tamper;
            let store = std::sync::Arc::new(MemoryStore::new());
            let state = AppState::new(config, store);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            let _ = serve(state, listener).await;
        });
    });
    format!("ws://{}", rx.recv().unwrap())
}

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

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.work.path())
            .env("MERIDIAN_HOME", self.home.path())
            .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("failed to run meridian binary")
    }

    fn new_account(&self, keyfile: &str) {
        let out = self.run(&[
            "id",
            "new",
            "--store",
            "file",
            "--out",
            keyfile,
            "--hint",
            "localhost",
        ]);
        assert!(out.status.success(), "id new: {}", stderr(&out));
    }

    fn id(&self) -> String {
        let out = self.run(&["id", "show"]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `meridian contact list --json` stdout — used as the before/after trust-state snapshot.
    fn contact_list_json(&self) -> String {
        let out = self.run(&["contact", "list", "--json"]);
        assert!(out.status.success(), "contact list: {}", stderr(&out));
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn tampered_fetch_against_a_preexisting_contact_fails_closed_and_leaves_trust_untouched() {
    let server = spawn_server(true);

    let alice = Client::new();
    let bob = Client::new();
    alice.new_account("alice.key");
    bob.new_account("bob.key");
    let bob_id = bob.id();

    for (who, client) in [("bob", &bob), ("alice", &alice)] {
        let out = client.run(&["register", "--server", &server]);
        assert!(out.status.success(), "{who} register: {}", stderr(&out));
    }

    // Alice already has a relationship with bob BEFORE any attack is attempted — the real CLI
    // surface a user would actually use (`contact add`), which TOFU-pins bob's identity key via
    // the same `TrustStore::observe` primitive `chat.rs` calls on ordinary first contact.
    let out = alice.run(&["contact", "add", &bob_id]);
    assert!(out.status.success(), "contact add: {}", stderr(&out));

    let before = alice.contact_list_json();
    assert!(
        before.contains("\"state\":\"pinned\""),
        "sanity: bob must already be an ordinary pinned contact before the attack: {before}"
    );
    assert!(
        !before.is_empty() && before.lines().count() == 1,
        "sanity: exactly one pre-existing contact row: {before:?}"
    );

    // THE ATTACK: the malicious rendezvous substitutes bob's bundle under a fresh, unrelated key —
    // the identical `substitute_bundle` hook T02 exercises — while alice already has the
    // pre-existing pinned record above for bob's REAL key.
    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &server, "--tamper"]);
    assert!(
        !out.status.success(),
        "tampered fetch must exit non-zero even against a pre-existing contact; stdout={}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("FATAL: bundle signature does not match requested identity"),
        "expected the identical FATAL abort T02 proves for a fresh contact, got: {}",
        stderr(&out)
    );

    // THE NEW ASSERTION: alice's pre-existing trust record for bob is completely untouched by the
    // failed attempt — no phantom key-change state, no new contact row for the attacker's key.
    let after = alice.contact_list_json();
    assert_eq!(
        before, after,
        "a failed tampered-bundle fetch must leave the pre-existing trust store byte-identical: \
         no PinnedKeyChanged/Blocked state and no new contact row for the attacker's substituted \
         key may appear just because a fetch attempt happened to fail"
    );

    // And the pre-existing relationship is still fully usable afterwards: an honest fetch for the
    // same peer still succeeds, proving the failed attack didn't wedge anything.
    let out = alice.run(&["fetch-bundle", &bob_id, "--server", &server]);
    assert!(
        out.status.success(),
        "honest fetch after attack: {}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("bundle OK"), "{}", stdout(&out));

    let final_state = alice.contact_list_json();
    assert_eq!(
        before, final_state,
        "an honest fetch for an already-pinned contact must not touch trust state either"
    );
}
