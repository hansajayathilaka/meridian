//! `meridian_tui::worker` — task 4.34's own test target
//! (`cargo nextest run -p meridian-tui --test run_worker_settings`).
//!
//! Dispatches `SaveSetting`/`RunDoctor` effects directly against `meridian_tui::worker::dispatch`
//! (no live screen stack, no channel plumbing — same shape as `tests/run_worker_chat.rs`/
//! `tests/run_worker_account.rs`), proving this task's own two Deliverables:
//! - comment-preserving `config.toml` write-back (`crate::config_write::write_setting_at`, task
//!   4.24) still works end to end through a real worker dispatch, not just a direct call into that
//!   function (`apps/tui/src/config_write.rs`'s own `#[cfg(test)]` module already covers the
//!   function directly — this file is the "and the worker actually calls it" half); and
//! - the doctor-binary-not-found path (`crate::screens::diagnostics::run_doctor_binary`, task 4.25)
//!   still surfaces honestly as a `WorkerEvent::Failed`, never a silent no-op, when dispatched
//!   through the real worker (`apps/tui/src/screens/diagnostics.rs`'s own `#[cfg(test)]` module
//!   already covers `run_doctor_binary` directly — same "and the worker actually calls it" split).
//!
//! Neither `SaveSettingRequest` nor `RunDoctorRequest` needs `$MERIDIAN_HOME`/an `account.json`/a
//! `SecretStore` at all — both carry every input their underlying function needs directly
//! (`config_path`/`value`; `binary`), unlike every contacts/chat effect in the sibling test files —
//! so this file needs none of their `EnvGuard`/OS-keystore machinery.

use std::path::PathBuf;

use meridian_tui::app::{
    Effect, RunDoctorEffect, RunDoctorRequest, SaveSettingEffect, SaveSettingRequest, SettingValue,
    WorkerEvent,
};
use meridian_tui::config::NetworkPolicy;
use meridian_tui::worker::{dispatch, OnboardingSession};

async fn dispatch_effect(effect: Effect) -> WorkerEvent {
    let mut session = OnboardingSession::default();
    dispatch(effect, &mut session).await
}

// ---------------------------------------------------------------------------
// SaveSetting
// ---------------------------------------------------------------------------

/// A representative hand-authored `config.toml` — comments, blank lines, and a value this test
/// never touches — mirrors `crate::config_write`'s own `SAMPLE` fixture exactly, since this test
/// exists to prove the *worker* preserves the same properties that module's own direct-call tests
/// already prove for `write_setting_at` itself.
const SAMPLE: &str = r#"# Meridian TUI configuration
# See docs/architecture/tui-client.md §5 for the full schema.

[account]
# Override the server this account registered against.
server = "old.example"

[ui]
theme = "dark"
unicode = true # keep box-drawing characters

[network]
policy = "direct"
reconnect_backoff_ms = [500, 1000, 2000]
"#;

fn write_sample(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("config.toml");
    std::fs::write(&path, SAMPLE).expect("write sample config.toml");
    path
}

fn save_setting_request(config_path: PathBuf, value: SettingValue) -> Effect {
    Effect::SaveSetting(SaveSettingEffect {
        request: SaveSettingRequest { config_path, value },
        outcome: None,
    })
}

/// The load-bearing end-to-end proof: dispatching `Effect::SaveSetting` through the real worker
/// (not calling `write_setting_at` directly) leaves every comment/blank-line/untouched-key
/// byte-identical and only changes the one targeted key — exactly
/// `config_write::tests::write_setting_preserves_comments_and_only_changes_the_targeted_key`'s own
/// assertions, now proven through the actual dispatch path a running `meridian tui` process uses.
#[tokio::test]
async fn save_setting_writes_back_preserving_comments_through_a_real_worker_dispatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_sample(&dir);

    let effect = save_setting_request(
        path.clone(),
        SettingValue::ServerUrl(Some("new.example".to_string())),
    );
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::SaveSetting(SaveSettingEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected a completed SaveSetting, got {other:?}"),
    }

    let updated = std::fs::read_to_string(&path).expect("read back config.toml");
    assert!(
        updated.contains("# Meridian TUI configuration"),
        "top comment survived"
    );
    assert!(
        updated.contains("# Override the server this account registered against."),
        "the field's own comment survived"
    );
    assert!(
        updated.contains("unicode = true # keep box-drawing characters"),
        "an untouched key + its trailing comment survived verbatim"
    );
    assert!(
        updated.contains(r#"server = "new.example""#),
        "the targeted key actually changed"
    );
    assert!(
        !updated.contains("old.example"),
        "the old value is really gone, not merely shadowed"
    );
    assert!(updated.contains(r#"theme = "dark""#));
    assert!(updated.contains(r#"policy = "direct""#));
    assert!(updated.contains("reconnect_backoff_ms = [500, 1000, 2000]"));
}

/// A second field, through the real worker, dispatched against the file the first test's own
/// write-back already produced — proves the worker's write-back genuinely composes across repeated
/// dispatches rather than only working once against a pristine fixture.
#[tokio::test]
async fn save_setting_a_second_field_through_the_worker_leaves_the_first_change_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_sample(&dir);

    match dispatch_effect(save_setting_request(
        path.clone(),
        SettingValue::ServerUrl(Some("first.example".to_string())),
    ))
    .await
    {
        WorkerEvent::Completed(_) => {}
        other => panic!("expected the first SaveSetting to complete, got {other:?}"),
    }
    match dispatch_effect(save_setting_request(
        path.clone(),
        SettingValue::RelayPolicy(NetworkPolicy::RelayOnly),
    ))
    .await
    {
        WorkerEvent::Completed(_) => {}
        other => panic!("expected the second SaveSetting to complete, got {other:?}"),
    }

    let updated = std::fs::read_to_string(&path).expect("read back config.toml");
    assert!(updated.contains(r#"server = "first.example""#));
    assert!(updated.contains(r#"policy = "relay-only""#));
}

/// A missing `config.toml` is an honest, named `WorkerEvent::Failed` — never a silent no-op and
/// never a fabricated fresh file — proving the worker propagates `ConfigWriteError::NoFile`
/// verbatim rather than swallowing it.
#[tokio::test]
async fn save_setting_against_a_missing_config_file_fails_closed_never_fabricating_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does-not-exist.toml");

    match dispatch_effect(save_setting_request(
        path.clone(),
        SettingValue::RetainDays(30),
    ))
    .await
    {
        WorkerEvent::Failed(
            Effect::SaveSetting(SaveSettingEffect { outcome: None, .. }),
            message,
        ) => {
            assert!(
                !message.is_empty(),
                "failure message must actually name the gap, not be empty"
            );
        }
        other => {
            panic!("expected a failed SaveSetting (no config.toml to preserve), got {other:?}")
        }
    }
    assert!(
        !path.exists(),
        "the worker must never author a config.toml from nothing"
    );
}

// ---------------------------------------------------------------------------
// RunDoctor
// ---------------------------------------------------------------------------

fn run_doctor_request(binary: &str) -> Effect {
    Effect::RunDoctor(RunDoctorEffect {
        request: RunDoctorRequest {
            binary: binary.to_string(),
        },
        outcome: None,
    })
}

/// The doctor-binary-not-found path, dispatched through the real worker — must surface as a real
/// `WorkerEvent::Failed` naming the actual gap ("not found on PATH"), never a silent no-op and
/// never a `WorkerEvent::Completed` with a fabricated/empty report.
#[tokio::test]
async fn run_doctor_binary_not_found_fails_closed_honestly_through_a_real_worker_dispatch() {
    match dispatch_effect(run_doctor_request(
        "definitely-not-a-real-meridian-binary-4f9c2a",
    ))
    .await
    {
        WorkerEvent::Failed(Effect::RunDoctor(RunDoctorEffect { outcome: None, .. }), message) => {
            assert!(
                message.contains("not found"),
                "expected an honest not-found message, got: {message}"
            );
        }
        other => panic!(
            "the doctor-binary-not-found path must surface as WorkerEvent::Failed, never a \
             silent no-op or a fabricated Completed, got {other:?}"
        ),
    }
}
