//! `meridian contact add/list/rename/block` (task 4.6).
//!
//! The load-bearing property this file exists to prove: **petnames are never populated from a
//! QR payload, an `mrd1:` ID, or any other wire field** (system-design.md §3.1) — only from an
//! explicit `--petname` flag (or an interactive prompt, not exercised here since these tests run
//! with stdin closed, i.e. never a TTY). `alice_wonderland_hint_never_becomes_petname` constructs
//! exactly the attack this task's required security-reviewer pass will scrutinize: a peer id whose
//! wire-carried `@domain` hint contains a name-like string, added with no `--petname` at all.

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_meridian");

/// Create a fresh file-store account under `home`/`work`, with the given routing hint, and return
/// its full `mrd1:…@hint` ID.
fn new_account(home: &std::path::Path, work: &std::path::Path, hint: &str) -> String {
    let out = Command::new(BIN)
        .args([
            "id", "new", "--store", "file", "--out", "id.key", "--hint", hint,
        ])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian id new");
    assert!(
        out.status.success(),
        "id new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(BIN)
        .args(["id", "show"])
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run meridian id show");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Run `meridian contact <args...>` for the account rooted at `home`/`work`, with stdin closed
/// (never a TTY — `contact.rs`'s interactive-petname-prompt path is deliberately unreachable from
/// these tests, exactly like a scripted/CI invocation).
fn contact(
    home: &std::path::Path,
    work: &std::path::Path,
    args: &[&str],
) -> (bool, String, String) {
    let out = Command::new(BIN)
        .arg("contact")
        .args(args)
        .current_dir(work)
        .env("MERIDIAN_HOME", home)
        .env("MERIDIAN_PASSPHRASE", "demo-passphrase")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("run meridian contact {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The core security property: a contact's `mrd1:` ID carries a wire hint crafted to look exactly
/// like a petname a naive implementation might mistakenly promote (e.g. by splitting on `@` or
/// `.` and using the first label). Adding that contact with **no** `--petname` must never surface
/// that string as the petname — the field must stay unset.
#[test]
fn hint_containing_a_name_like_string_never_becomes_petname() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    // The hint IS the "QR/ID payload" name-like string: valid LDH labels, but exactly what a
    // careless implementation might mistake for a display name.
    let peer_id = new_account(
        peer_home.path(),
        peer_work.path(),
        "alice-wonderland.example",
    );
    assert!(peer_id.contains("alice-wonderland.example"));

    let (ok, stdout, stderr) = contact(home.path(), work.path(), &["add", &peer_id]);
    assert!(ok, "contact add failed: {stderr}");
    assert!(stdout.contains("added"));

    let (ok, stdout, stderr) = contact(home.path(), work.path(), &["list", "--json"]);
    assert!(ok, "contact list failed: {stderr}");
    assert!(
        stdout.contains("\"petname\":null"),
        "petname must stay unset when only the hint carries a name-like string: {stdout}"
    );
    assert!(
        !stdout.contains("\"petname\":\"alice-wonderland.example\""),
        "the hint must never leak into petname: {stdout}"
    );
    assert!(
        !stdout.contains("\"petname\":\"alice-wonderland\""),
        "no substring of the wire hint may leak into petname either: {stdout}"
    );
    // The hint itself is still recorded (as advisory routing metadata, not identity) and the
    // plain-text list should show the no-petname placeholder, never the hint standing in for one.
    assert!(stdout.contains("\"hint\":\"alice-wonderland.example\""));

    let (ok, stdout, stderr) = contact(home.path(), work.path(), &["list"]);
    assert!(ok, "contact list (table) failed: {stderr}");
    assert!(stdout.contains("(no petname)"), "table output: {stdout}");
}

/// The explicit-flag path: `--petname` (and only `--petname`) sets it, and it need not have any
/// relationship to the hint/ID at all.
#[test]
fn explicit_petname_flag_sets_it_independent_of_hint() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "bob-example.example");

    let (ok, _out, stderr) = contact(
        home.path(),
        work.path(),
        &["add", &peer_id, "--petname", "Bestie"],
    );
    assert!(ok, "contact add --petname failed: {stderr}");

    let (ok, stdout, stderr) = contact(home.path(), work.path(), &["list", "--json"]);
    assert!(ok, "contact list failed: {stderr}");
    assert!(
        stdout.contains("\"petname\":\"Bestie\""),
        "explicit --petname must be used verbatim: {stdout}"
    );
    assert!(
        !stdout.contains("\"petname\":\"bob-example"),
        "hint must not leak into the petname field: {stdout}"
    );
}

#[test]
fn rename_updates_petname_and_empty_string_clears_it() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "carol.example");

    let (ok, _, stderr) = contact(home.path(), work.path(), &["add", &peer_id]);
    assert!(ok, "{stderr}");

    let (ok, _, stderr) = contact(home.path(), work.path(), &["rename", &peer_id, "Carol"]);
    assert!(ok, "rename failed: {stderr}");
    let (ok, stdout, _) = contact(home.path(), work.path(), &["list", "--json"]);
    assert!(ok);
    assert!(stdout.contains("\"petname\":\"Carol\""), "{stdout}");

    let (ok, _, stderr) = contact(home.path(), work.path(), &["rename", &peer_id, ""]);
    assert!(ok, "clearing rename failed: {stderr}");
    let (ok, stdout, _) = contact(home.path(), work.path(), &["list", "--json"]);
    assert!(ok);
    assert!(
        stdout.contains("\"petname\":null"),
        "empty rename should clear it: {stdout}"
    );
}

#[test]
fn rename_unknown_contact_is_a_clean_error() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "dave.example");

    let (ok, _out, stderr) = contact(home.path(), work.path(), &["rename", &peer_id, "Dave"]);
    assert!(!ok, "renaming a never-added contact must fail");
    assert!(
        stderr.contains("contact add"),
        "error should point at `contact add`: {stderr}"
    );
}

#[test]
fn block_is_local_and_independent_of_trust_state() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    new_account(home.path(), work.path(), "localhost");

    let peer_home = tempfile::tempdir().unwrap();
    let peer_work = tempfile::tempdir().unwrap();
    let peer_id = new_account(peer_home.path(), peer_work.path(), "erin.example");

    let (ok, _, stderr) = contact(home.path(), work.path(), &["add", &peer_id]);
    assert!(ok, "{stderr}");

    let (ok, stdout, stderr) = contact(home.path(), work.path(), &["block", &peer_id]);
    assert!(ok, "block failed: {stderr}");
    assert!(stdout.contains("blocked"));

    let (ok, stdout, _) = contact(home.path(), work.path(), &["list", "--json"]);
    assert!(ok);
    assert!(stdout.contains("\"user_blocked\":true"), "{stdout}");
    // A user-initiated block must not be conflated with the key-change `Blocked` trust state —
    // the reported `state` stays `pinned`, only `user_blocked` flips.
    assert!(stdout.contains("\"state\":\"pinned\""), "{stdout}");

    let (ok, stdout, _) = contact(home.path(), work.path(), &["list"]);
    assert!(ok);
    assert!(stdout.contains("[blocked]"), "{stdout}");
}
