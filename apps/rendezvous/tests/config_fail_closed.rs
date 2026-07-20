//! F16 acceptance: the server never silently weakens its posture on a config error.
//!
//! - An explicitly supplied `--config <path>` that fails to load (missing file or bad TOML) must
//!   make the process exit non-zero *without* booting on defaults.
//! - No `--config` flag at all must still boot successfully on defaults (regression guard for the
//!   pre-existing "no config" path).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_meridian-rendezvous")
}

/// Poll `child` for up to `timeout`, returning `Some(status)` once it has exited.
fn wait_for_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if start.elapsed() > timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn explicit_bad_config_path_exits_nonzero() {
    // A path that simply doesn't exist.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.toml");

    let mut child = Command::new(bin())
        .arg("--config")
        .arg(&missing)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .current_dir(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn meridian-rendezvous");

    let status = wait_for_exit(&mut child, Duration::from_secs(10)).unwrap_or_else(|| {
        let _ = child.kill();
        panic!("process did not exit on missing --config path — fail-closed regressed")
    });
    assert!(
        !status.success(),
        "expected non-zero exit for a missing explicit --config path, got {status:?}"
    );
}

#[test]
fn explicit_unparseable_config_exits_nonzero() {
    // A path that exists but is not valid TOML.
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.toml");
    let mut f = std::fs::File::create(&bad).unwrap();
    writeln!(f, "this is [ not valid toml =").unwrap();
    drop(f);

    let mut child = Command::new(bin())
        .arg("--config")
        .arg(&bad)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .current_dir(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn meridian-rendezvous");

    let status = wait_for_exit(&mut child, Duration::from_secs(10)).unwrap_or_else(|| {
        let _ = child.kill();
        panic!("process did not exit on unparseable explicit --config — fail-closed regressed")
    });
    assert!(
        !status.success(),
        "expected non-zero exit for an unparseable explicit --config, got {status:?}"
    );
}

#[test]
fn no_config_flag_still_boots_on_defaults() {
    // Run in an empty directory (no stray `rendezvous.toml`) with no `--config` flag at all — this
    // must still boot successfully, exactly as before this fix.
    let dir = tempfile::tempdir().unwrap();

    let mut child = Command::new(bin())
        .arg("--bind")
        .arg("127.0.0.1:0")
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn meridian-rendezvous");

    // Give it a moment to either boot (and keep running) or fail fast.
    let exited_early = wait_for_exit(&mut child, Duration::from_millis(800));
    assert!(
        exited_early.is_none(),
        "server exited early when no --config was given: {exited_early:?}"
    );

    child.kill().expect("kill still-running server");
    let _ = child.wait();
}
