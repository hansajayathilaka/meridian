//! Task 4.7 — message-request finalization: the glue between T06/2.10's first-contact gate
//! (`meridian_core::chat::MessageRequest`/`accept_request`/`reject_request`) and T08's trust store
//! (`meridian_core::trust::TrustStore`), exercised exactly as it happens in `apps/cli/src/chat.rs`'s
//! `answer_request`:
//!
//! - **Accept** must TOFU-pin the sender as a real `Contact` (`meridian contact list` shows it,
//!   `state: pinned`), with no petname (the inline prompt is TTY-gated — this harness pipes stdin,
//!   never a TTY, matching the same "deliberately unreachable from a subprocess test" precedent
//!   `contact_mgmt.rs` documents for `contact add`'s identical prompt).
//! - **Reject** must leave no trace at all: no `Contact` record for the rejected sender.
//!
//! Single, non-federated rendezvous server (unlike `two_orgs_walkthrough.rs`'s bidirectional-federation
//! harness — this property doesn't need federation, only the message-request gate + trust glue).

use std::time::Duration;

mod support;
use support::{base_config, spawn_c2s, wait_until, Client};

use meridian_rendezvous::{AppState, MemoryStore};

/// Boot a single local rendezvous server (no federation) and return its `ws://` c2s URL.
async fn boot_server() -> String {
    let state = AppState::new(
        base_config("localhost"),
        std::sync::Arc::new(MemoryStore::new()),
    );
    spawn_c2s(state).await
}

/// alice always ends up the X3DH initiator (lower identity key) so bob is deterministically the one
/// who sees the first-contact `message_request` gate on alice's opening envelope — mirrors
/// `two_orgs_walkthrough.rs`'s identical `loop { ... }` trick.
fn new_pair() -> (Client, String, Client, String) {
    let alice = Client::new();
    alice.new_account("alice.key", "localhost");
    let alice_id = alice.id();
    let alice_ik = *meridian_core::identity::parse_id(&alice_id)
        .unwrap()
        .pubkey();

    let bob = loop {
        let candidate = Client::new();
        candidate.new_account("bob.key", "localhost");
        let candidate_id = candidate.id();
        let candidate_ik = *meridian_core::identity::parse_id(&candidate_id)
            .unwrap()
            .pubkey();
        if alice_ik.as_slice() <= candidate_ik.as_slice() {
            break candidate;
        }
    };
    let bob_id = bob.id();
    (alice, alice_id, bob, bob_id)
}

#[test]
fn accepting_a_message_request_tofu_pins_a_contact_with_no_petname_over_piped_stdin() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(boot_server());
    let (alice, alice_id, bob, bob_id) = new_pair();

    // bob must be online before alice's opening message (deterministic gate ordering).
    let mut b = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(500));
    let mut a = alice.spawn_chat(&server, &bob_id);
    std::thread::sleep(Duration::from_millis(500));

    a.send("hello bob, this is alice");

    let gated = wait_until(Duration::from_secs(15), || {
        b.out().contains("\"event\":\"message_request\"")
    });
    assert!(
        gated,
        "bob never saw a message_request event.\nstdout: {}\nstderr: {}",
        b.out(),
        b.err()
    );

    // Before accepting: no `Contact` record exists yet for alice on bob's side (the pin the CLI
    // does at the top of `run()` is deferred for exactly this — an as-yet-undecided first
    // contact — task 4.7).
    let pre = bob.run(&["contact", "list", "--json"]);
    let pre_stdout = String::from_utf8_lossy(&pre.stdout);
    assert!(
        !pre_stdout.contains(&alice_id),
        "alice must not be pinned before bob accepts the request: {pre_stdout}"
    );

    // Accept — stdin here is piped (never a TTY), so the inline petname prompt (task 4.7) must be
    // skipped, never block the flow.
    b.send("y");
    let accepted = wait_until(Duration::from_secs(10), || {
        b.out().contains("\"event\":\"request_accepted\"")
    });
    assert!(
        accepted,
        "bob's accept did not register: {}\n{}",
        b.out(),
        b.err()
    );
    // The held intro still gets delivered exactly as before this task.
    let delivered = wait_until(Duration::from_secs(10), || {
        b.out().contains("hello bob, this is alice")
    });
    assert!(
        delivered,
        "bob never received alice's intro after accepting: {}\n{}",
        b.out(),
        b.err()
    );

    a.finish();
    b.finish();

    // After accepting: alice is now a real, pinned `Contact` on bob's side, with no petname (the
    // prompt was TTY-gated and skipped, never blocking, never guessing one from wire data).
    let post = bob.run(&["contact", "list", "--json"]);
    assert!(
        post.status.success(),
        "{}",
        String::from_utf8_lossy(&post.stderr)
    );
    let post_stdout = String::from_utf8_lossy(&post.stdout);
    assert!(
        post_stdout.contains(&alice_id) && post_stdout.contains("\"state\":\"pinned\""),
        "alice must be a pinned contact after bob accepted: {post_stdout}"
    );
    assert!(
        post_stdout.contains("\"petname\":null"),
        "no petname must be set when stdin was never a TTY: {post_stdout}"
    );
}

/// Regression for the bug this task's required review found and reproduced: restarting the
/// responder's `chat` process while a `MessageRequest` is still undecided must NOT TOFU-pin the
/// sender on the next invocation's startup. Before the fix, `run()`'s early
/// `trust.observe`/`save_trust` fired whenever `state.has_session(&peer_ik)` was true — but a
/// session already exists for a peer whose request hasn't been answered yet (`ChatState`'s
/// `open_inbound_gated` installs the ratchet session before deciding whether to gate the content
/// into `pending_requests`), so a restart-without-deciding silently pinned the sender exactly the
/// way `reject_request`'s "no trace" guarantee is supposed to prevent.
#[test]
fn restarting_without_deciding_a_pending_request_does_not_tofu_pin() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(boot_server());
    let (alice, alice_id, bob, bob_id) = new_pair();

    let b = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(500));
    let mut a = alice.spawn_chat(&server, &bob_id);
    std::thread::sleep(Duration::from_millis(500));

    a.send("hello bob, this is alice");

    let gated = wait_until(Duration::from_secs(15), || {
        b.out().contains("\"event\":\"message_request\"")
    });
    assert!(
        gated,
        "bob never saw a message_request event.\nstdout: {}\nstderr: {}",
        b.out(),
        b.err()
    );

    // bob exits WITHOUT ever answering the prompt (stdin EOF -> clean exit, same path a crash or
    // Ctrl-C would take) -- the request is still undecided in bob's sealed-at-rest ChatState.
    a.finish();
    b.finish();

    // No trace yet: the still-undecided request must not have pinned alice.
    let mid = bob.run(&["contact", "list", "--json"]);
    let mid_stdout = String::from_utf8_lossy(&mid.stdout);
    assert!(
        !mid_stdout.contains(&alice_id),
        "an undecided request must not pin the sender even before any restart: {mid_stdout}"
    );

    // Respawn bob's chat against the same peer -- the exact scenario the review reproduced. The
    // pending request reloads from disk; bob still doesn't answer, and exits again immediately.
    let b2 = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(500));
    b2.finish();

    // The critical assertion: a bare restart, with no accept ever having happened, must still
    // leave zero trace of a Contact for alice.
    let post = bob.run(&["contact", "list", "--json"]);
    assert!(
        post.status.success(),
        "{}",
        String::from_utf8_lossy(&post.stderr)
    );
    let post_stdout = String::from_utf8_lossy(&post.stdout);
    assert!(
        !post_stdout.contains(&alice_id),
        "restarting without deciding a pending request must never TOFU-pin the sender: {post_stdout}"
    );
}

#[test]
fn rejecting_a_message_request_leaves_no_trace_no_contact_record() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(boot_server());
    let (alice, alice_id, bob, bob_id) = new_pair();

    let mut b = bob.spawn_chat(&server, &alice_id);
    std::thread::sleep(Duration::from_millis(500));
    let mut a = alice.spawn_chat(&server, &bob_id);
    std::thread::sleep(Duration::from_millis(500));

    a.send("hello bob, this is alice");

    let gated = wait_until(Duration::from_secs(15), || {
        b.out().contains("\"event\":\"message_request\"")
    });
    assert!(
        gated,
        "bob never saw a message_request event.\nstdout: {}\nstderr: {}",
        b.out(),
        b.err()
    );

    // Reject.
    b.send("n");
    let rejected = wait_until(Duration::from_secs(10), || {
        b.out().contains("\"event\":\"request_rejected\"")
    });
    assert!(
        rejected,
        "bob's reject did not register: {}\n{}",
        b.out(),
        b.err()
    );
    assert!(
        !b.out().contains("\"event\":\"recv\""),
        "a rejected sender's intro must never be delivered: {}",
        b.out()
    );

    a.finish();
    b.finish();

    // No trace at all: no `Contact` record for alice on bob's side.
    let post = bob.run(&["contact", "list", "--json"]);
    assert!(
        post.status.success(),
        "{}",
        String::from_utf8_lossy(&post.stderr)
    );
    let post_stdout = String::from_utf8_lossy(&post.stdout);
    assert!(
        !post_stdout.contains(&alice_id),
        "rejecting must leave no Contact record for the sender: {post_stdout}"
    );
}
