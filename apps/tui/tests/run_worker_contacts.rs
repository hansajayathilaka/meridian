//! `meridian_tui::worker` — task 4.31's own test target
//! (`cargo nextest run -p meridian-tui --test run_worker_contacts`).
//!
//! Dispatches `AddContact`/`ImportContactQr`/`SetPetname`/`SetUserBlocked`/`SetPolicyOverride`/
//! `DeleteContact` effects directly against `meridian_tui::worker::dispatch` (no live screen stack,
//! no channel plumbing — same shape as `tests/run_worker_account.rs`) and asserts the real
//! `trust.bin`/`contacts.json` side effects each one's own doc comment in `crate::app` requires.
//!
//! ## Why `OsSecretStore` + `install_mock_keystore`, not `StoreChoice::File`
//! Unlike `Effect::GenerateAccount`/`Effect::Register`/`Effect::Unlock`, none of this task's six
//! request types (`AddContactRequest`/`SetPetnameRequest`/…) carries a `StoreChoice` or passphrase
//! — `worker.rs::open_account_store` re-derives a `SecretStore`/`KeyHandle` fresh from the real,
//! already-onboarded `account.json` on every single dispatch (see that function's own doc comment),
//! and today that only actually resolves for an OS-keystore-backed account (a file-backed one fails
//! closed — see `add_contact_for_a_file_backed_account_fails_closed_with_an_actionable_message`
//! below). `meridian_store::install_mock_keystore` (re-exported straight through
//! `meridian_core::identity`) is exactly the sanctioned, headless-CI-safe way to exercise that real
//! `OsSecretStore` code path without a platform keychain/D-Bus — `apps/store/tests/keystore.rs`'s
//! own `os_store_leaves_no_plaintext_on_disk` test is the precedent this file follows.
//!
//! `install_mock_keystore` replaces a **process-global** default keyring store, so every test in
//! this file that touches it does so from inside [`EnvGuard`]'s own serialized critical section —
//! the same `ENV_LOCK` this crate's other test files already use to serialize `$MERIDIAN_HOME`
//! itself, extended here to also cover the keystore singleton (see [`EnvGuard::set`]).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::identity::{
    generate_account, install_mock_keystore, parse_id, FileSecretStore, KeyHandle, OsSecretStore,
};
use meridian_core::trust::{TrustState, TrustStore};

use meridian_tui::app::{
    AddContactEffect, AddContactRequest, DeleteContactEffect, DeleteContactRequest, Effect,
    ImportContactQrEffect, ImportContactQrRequest, SetPetnameEffect, SetPetnameRequest,
    SetPolicyOverrideEffect, SetPolicyOverrideRequest, SetUserBlockedEffect, SetUserBlockedRequest,
    WorkerEvent,
};
use meridian_tui::store::contacts::{self, PolicyOverride, TrustLabel};
use meridian_tui::worker::{dispatch, OnboardingSession};

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors
// `apps/tui/tests/run_worker_account.rs`'s own `EnvGuard` exactly, extended to also install a
// fresh mock keystore (see the module doc's "Why OsSecretStore" section for why that extension is
// needed here and not there).
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// `worker.rs::init_os_keystore` constructs a `keyring` v4 (v1-shim) `Entry` — and that crate's own
/// `Entry::new` only ever attempts *real* platform auto-detection on the very first call anywhere
/// in the process (an internal `AtomicBool`, set unconditionally win-or-lose, never reset — see
/// `keyring::v1::set_credential_store`). On this headless test runner that first attempt always
/// fails (no Secret Service/D-Bus session), so whichever test happened to run first would flakily
/// surface *that* failure instead of ever reaching the mock keystore this file installs below. This
/// burns that one-time attempt exactly once, before any test's own dispatch can reach it, so every
/// dispatch (in every test, in whatever order they run) instead falls through to
/// `keyring_core::Entry::new`, which consults [`install_mock_keystore`]'s current default store.
static KEYRING_WARMUP: std::sync::Once = std::sync::Once::new();

struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    prev_home: Option<String>,
}

impl EnvGuard {
    fn set(dir: &Path) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("MERIDIAN_HOME").ok();
        // SAFETY: serialized by ENV_LOCK, the only place in this test binary touching this var.
        unsafe {
            std::env::set_var("MERIDIAN_HOME", dir);
        }
        KEYRING_WARMUP.call_once(|| {
            let _ = keyring::Entry::new("meridian-tui-contacts-test-warmup", "warmup");
        });
        // Fresh, empty, in-process mock keystore for this test alone — installed inside the same
        // critical section as `$MERIDIAN_HOME` itself, since both are process-global state this
        // file's tests must never race on.
        install_mock_keystore();
        Self {
            _lock: lock,
            prev_home,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see `EnvGuard::set`.
        unsafe {
            match &self.prev_home {
                Some(v) => std::env::set_var("MERIDIAN_HOME", v),
                None => std::env::remove_var("MERIDIAN_HOME"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Account fixtures
// ---------------------------------------------------------------------------

const SERVICE: &str = "meridian-tui-contacts-test";

/// Mints a real OS-keystore-backed account (against the mock keystore [`EnvGuard::set`] already
/// installed) and saves its real `account.json` — the exact shape `worker.rs::open_account_store`
/// re-derives its `SecretStore`/`KeyHandle` from on every dispatch below.
fn setup_os_account() -> KeyHandle {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "self.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    account.handle().clone()
}

/// A second, unrelated peer identity — the contact these tests add/rename/block/delete.
fn peer_id() -> (String, [u8; 32], String) {
    let peer_store = meridian_core::identity::MemorySecretStore::new();
    let peer = generate_account(&peer_store, "peer.example").expect("peer generate_account");
    let id = peer.to_id_string();
    let parsed = parse_id(&id).expect("parse_id");
    (id, *parsed.pubkey(), parsed.hint().to_string())
}

/// Reads the real `trust.bin` back off disk through the same OS-keystore/mock-keyring path the
/// worker itself used to seal it.
fn read_trust() -> TrustStore {
    let os = OsSecretStore::new(SERVICE);
    let handle = KeyHandle::from_label(&AccountDescriptor::load().expect("account.json").label);
    let bytes = std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");
    TrustStore::open_at_rest(&os, &handle, &bytes).expect("open trust.bin")
}

/// Reads the real `contacts.json` back off disk the same way.
fn read_contacts() -> contacts::ContactsDocument {
    let os = OsSecretStore::new(SERVICE);
    let handle = KeyHandle::from_label(&AccountDescriptor::load().expect("account.json").label);
    contacts::load_or_default(&os, &handle).expect("load contacts.json")
}

async fn dispatch_effect(effect: Effect) -> WorkerEvent {
    let mut session = OnboardingSession::default();
    dispatch(effect, &mut session).await
}

// ---------------------------------------------------------------------------
// AddContact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_contact_pins_trust_and_writes_a_matching_contacts_json_row() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();

    let effect = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    });
    let added = match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected AddContact to complete, got {other:?}"),
    };
    assert_eq!(added.pubkey, pubkey);
    assert_eq!(added.id, id);
    assert_eq!(added.petname.as_deref(), Some("Alice"));
    assert_eq!(added.trust, TrustState::Pinned);
    assert!(!added.user_blocked);
    assert_eq!(added.pinned_key_history.len(), 1);

    let trust = read_trust();
    let contact = trust.contact(&pubkey).expect("pinned in trust.bin");
    assert_eq!(contact.state, TrustState::Pinned);
    assert_eq!(contact.petname.as_deref(), Some("Alice"));
    assert!(!contact.user_blocked);

    let doc = read_contacts();
    assert_eq!(doc.contacts.len(), 1);
    let record = &doc.contacts[0];
    assert_eq!(record.pubkey, hex::encode(pubkey));
    assert_eq!(record.id, id);
    assert_eq!(record.petname.as_deref(), Some("Alice"));
    assert_eq!(record.trust, TrustLabel::Pinned);
}

#[tokio::test]
async fn add_contact_with_no_petname_leaves_petname_unset_in_both_stores() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();

    let effect = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: None,
        },
        outcome: None,
    });
    let added = match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected AddContact to complete, got {other:?}"),
    };
    assert_eq!(added.petname, None);
    assert_eq!(read_trust().contact(&pubkey).unwrap().petname, None);
    assert_eq!(read_contacts().contacts[0].petname, None);
}

/// Security invariant: a petname is never derived from wire-observed content
/// (`AddContactRequest::petname` is the *only* source `run_add_contact` ever reads a petname value
/// from — see that request's own doc comment in `crate::app`). Simulates a hostile hint crafted to
/// look exactly like a petname, mirroring `apps/cli/src/contact.rs`'s own
/// `observe_alone_never_populates_petname` unit test, at this worker-integration level.
#[tokio::test]
async fn add_contact_never_derives_a_petname_from_the_hint_even_when_it_looks_like_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, _hint) = peer_id();
    let hostile_hint = "TotallyLegitAlice.example";

    let effect = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint: hostile_hint.to_string(),
            petname: None,
        },
        outcome: None,
    });
    let added = match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected AddContact to complete, got {other:?}"),
    };
    assert_eq!(
        added.hint, hostile_hint,
        "hint is still recorded as advisory metadata"
    );
    assert_eq!(
        added.petname, None,
        "a hint that looks like a name must never populate the petname"
    );
    assert_eq!(read_trust().contact(&pubkey).unwrap().petname, None);
}

/// The re-add edge case [`AddedContact`](meridian_tui::app::AddedContact)'s own doc comment calls
/// out explicitly: deleting a contact only removes its local `contacts.json` display row (never
/// `TrustStore`), so re-adding the same pubkey later — with the add form's petname field left
/// blank — must **not** regress the contact's real trust state or clobber its already-set petname.
/// `run_add_contact` only calls `TrustStore::set_petname` when the request's `petname` is `Some`
/// (mirroring `apps/cli/src/contact.rs::cmd_add` exactly), so a blank re-add leaves the existing
/// petname untouched; `AddedContact::petname` must then report that *real*, surviving value, not
/// `None`.
#[tokio::test]
async fn re_adding_a_deleted_contact_with_a_blank_petname_preserves_the_real_petname_and_trust_state(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();

    // 1. Add with a petname.
    let add = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    });
    match dispatch_effect(add).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(_), ..
        })) => {}
        other => panic!("expected first AddContact to complete, got {other:?}"),
    }

    // 2. Delete — only the local contacts.json row goes away; trust.bin's pin/petname survive
    // (see `DeleteContactRequest`'s own doc comment).
    let delete = Effect::DeleteContact(DeleteContactEffect {
        request: DeleteContactRequest { pubkey },
        outcome: None,
    });
    match dispatch_effect(delete).await {
        WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected DeleteContact to complete, got {other:?}"),
    }
    assert!(
        read_contacts().contacts.is_empty(),
        "delete must remove the contacts.json row"
    );
    let trust_after_delete = read_trust();
    let contact_after_delete = trust_after_delete
        .contact(&pubkey)
        .expect("trust.bin record must survive a contacts.json-only delete");
    assert_eq!(contact_after_delete.state, TrustState::Pinned);
    assert_eq!(contact_after_delete.petname.as_deref(), Some("Alice"));
    assert_eq!(contact_after_delete.pinned_key_history.len(), 1);

    // 3. Re-add the same pubkey with the petname field left blank.
    let re_add = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: None,
        },
        outcome: None,
    });
    let re_added = match dispatch_effect(re_add).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected re-add AddContact to complete, got {other:?}"),
    };

    // The core assertion this test exists for: the real, surviving petname is reported back, not
    // a naive echo of the blank request field.
    assert_eq!(
        re_added.petname.as_deref(),
        Some("Alice"),
        "a blank re-add must never clobber the existing petname"
    );
    assert_eq!(
        re_added.trust,
        TrustState::Pinned,
        "a repeat observation of the same key must never regress/reset trust state"
    );
    assert!(!re_added.user_blocked);
    // `observe` refreshes the existing history entry's `last_seen_unix` rather than appending a
    // second one for the very same key — still exactly one entry.
    assert_eq!(re_added.pinned_key_history.len(), 1);

    // And the contacts.json row is genuinely re-created (not left absent), carrying the same real
    // values forward.
    let doc = read_contacts();
    assert_eq!(doc.contacts.len(), 1);
    assert_eq!(doc.contacts[0].petname.as_deref(), Some("Alice"));
    assert_eq!(doc.contacts[0].trust, TrustLabel::Pinned);
}

/// Exercises the *other* branch of `worker.rs::upsert_contact_record` — the "row already exists in
/// `contacts.json`" update-in-place path — which the re-add test above never reaches (it goes
/// through `DeleteContact` first, so by the time it re-adds, the `contacts.json` row is genuinely
/// absent and only the insert branch runs). Here the same pubkey is re-added **with no
/// `DeleteContact` in between**, after a `SetPolicyOverride` has given it a non-default
/// `policy_override`, so the update branch's own contract — refresh the `TrustStore`-owned fields
/// (`petname`/`trust`/`pinned_key_history`) in place, bump `last_activity_at`, but leave the
/// purely-local fields (`added_at`, `policy_override`, `conv_handle`, `unread`) untouched — is
/// actually exercised, per `upsert_contact_record`'s own doc comment.
#[tokio::test]
async fn re_adding_a_still_present_contact_updates_trust_fields_in_place_and_preserves_local_fields(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();

    // 1. Add with a petname.
    let add = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    });
    match dispatch_effect(add).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(_), ..
        })) => {}
        other => panic!("expected first AddContact to complete, got {other:?}"),
    }

    // 2. Give it a non-default policy override — a purely-local field the update branch must never
    // clobber. The row is *not* deleted, so it's still present in `contacts.json` for step 4 below.
    let set_override = Effect::SetPolicyOverride(SetPolicyOverrideEffect {
        request: SetPolicyOverrideRequest {
            pubkey,
            policy_override: Some(PolicyOverride::RelayOnly),
        },
        outcome: None,
    });
    match dispatch_effect(set_override).await {
        WorkerEvent::Completed(Effect::SetPolicyOverride(SetPolicyOverrideEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected SetPolicyOverride to complete, got {other:?}"),
    }

    let before = read_contacts();
    assert_eq!(before.contacts.len(), 1, "row must still be present");
    let added_at_before = before.contacts[0].added_at;
    assert_eq!(
        before.contacts[0].policy_override,
        Some(PolicyOverride::RelayOnly)
    );

    // Force `now_unix()` to actually advance a whole second, so an `added_at`/`last_activity_at`
    // comparison below is a real signal rather than a same-second coincidence.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // 3. Re-add the same pubkey, with no `DeleteContact` in between — the `contacts.json` row is
    // still there, so this must take the update-in-place branch, not the insert branch. Petname is
    // left blank here too, re-confirming "don't clobber an existing petname" from the other
    // direction (the earlier re-add test only exercises that after a delete).
    let re_add = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: id.clone(),
            pubkey,
            hint: hint.clone(),
            petname: None,
        },
        outcome: None,
    });
    let re_added = match dispatch_effect(re_add).await {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected second AddContact to complete, got {other:?}"),
    };
    assert_eq!(
        re_added.petname.as_deref(),
        Some("Alice"),
        "a blank re-add must never clobber the existing petname"
    );
    assert_eq!(re_added.trust, TrustState::Pinned);

    // No duplicate row was created — this alone rules out the update branch having silently fallen
    // through to the insert branch.
    let after = read_contacts();
    assert_eq!(after.contacts.len(), 1, "must still be exactly one row");
    let record = &after.contacts[0];

    // `TrustStore`-owned fields reflect the fresh `observe` call.
    assert_eq!(record.petname.as_deref(), Some("Alice"));
    assert_eq!(record.trust, TrustLabel::Pinned);
    assert!(
        record.last_activity_at > added_at_before,
        "last_activity_at must be bumped by the re-add, proving the update branch actually ran"
    );

    // Purely-local fields survive untouched by the update branch.
    assert_eq!(
        record.added_at, added_at_before,
        "added_at must never change on a re-add of a still-present row"
    );
    assert_eq!(
        record.policy_override,
        Some(PolicyOverride::RelayOnly),
        "policy_override must never be clobbered by a mere re-observe"
    );
    // No effect in this task's scope sets `unread` directly (see `worker.rs::upsert_contact_record`'s
    // own doc comment) — insert always seeds it at 0, so this only confirms it stayed put, not that
    // a nonzero value would have survived.
    assert_eq!(record.unread, 0);
}

// ---------------------------------------------------------------------------
// ImportContactQr
// ---------------------------------------------------------------------------

#[tokio::test]
async fn import_contact_qr_decodes_the_id_string_and_touches_neither_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    // No account/keystore setup at all: `Effect::ImportContactQr`'s own doc comment says its
    // execution never touches `TrustStore`/`contacts.json`, so this proves it needs neither.

    let (id, _pubkey, _hint) = peer_id();
    let img = meridian_core::identity::render_luma(&id).expect("render_luma");
    let path = tmp.path().join("qr.png");
    img.save(&path).expect("write qr.png");

    let effect = Effect::ImportContactQr(ImportContactQrEffect {
        request: ImportContactQrRequest { path: path.clone() },
        outcome: None,
    });
    let decoded = match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::ImportContactQr(ImportContactQrEffect {
            outcome: Some(decoded),
            ..
        })) => decoded,
        other => panic!("expected ImportContactQr to complete, got {other:?}"),
    };
    assert_eq!(decoded, id);

    // Neither sealed store was ever created.
    assert!(!account::trust_path().unwrap().exists());
    assert!(!meridian_tui::store::contacts_path().unwrap().exists());
}

#[tokio::test]
async fn import_contact_qr_fails_closed_on_a_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());

    let effect = Effect::ImportContactQr(ImportContactQrEffect {
        request: ImportContactQrRequest {
            path: tmp.path().join("does-not-exist.png"),
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::ImportContactQr(_), message) => {
            assert!(!message.is_empty());
        }
        other => panic!("expected ImportContactQr to fail closed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// SetPetname
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_petname_renames_in_both_trust_bin_and_contacts_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();
    dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    }))
    .await;

    let effect = Effect::SetPetname(SetPetnameEffect {
        request: SetPetnameRequest {
            pubkey,
            petname: Some("Alicia".to_string()),
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::SetPetname(SetPetnameEffect {
            outcome: Some(()), ..
        })) => {}
        other => panic!("expected SetPetname to complete, got {other:?}"),
    }

    assert_eq!(
        read_trust().contact(&pubkey).unwrap().petname.as_deref(),
        Some("Alicia")
    );
    assert_eq!(
        read_contacts().contacts[0].petname.as_deref(),
        Some("Alicia")
    );
}

#[tokio::test]
async fn set_petname_with_none_clears_it_in_both_stores() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();
    dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    }))
    .await;

    let effect = Effect::SetPetname(SetPetnameEffect {
        request: SetPetnameRequest {
            pubkey,
            petname: None,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::SetPetname(SetPetnameEffect {
            outcome: Some(()), ..
        })) => {}
        other => panic!("expected SetPetname to complete, got {other:?}"),
    }

    assert_eq!(read_trust().contact(&pubkey).unwrap().petname, None);
    assert_eq!(read_contacts().contacts[0].petname, None);
}

#[tokio::test]
async fn set_petname_for_an_unknown_contact_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (_id, pubkey, _hint) = peer_id();

    let effect = Effect::SetPetname(SetPetnameEffect {
        request: SetPetnameRequest {
            pubkey,
            petname: Some("Nobody".to_string()),
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::SetPetname(_), message) => assert!(!message.is_empty()),
        other => panic!("expected SetPetname to fail closed for an unknown contact, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// SetUserBlocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_user_blocked_only_touches_trust_bin_never_contacts_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();
    dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    }))
    .await;
    let contacts_before = read_contacts();

    let effect = Effect::SetUserBlocked(SetUserBlockedEffect {
        request: SetUserBlockedRequest {
            pubkey,
            blocked: true,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected SetUserBlocked to complete, got {other:?}"),
    }

    assert!(read_trust().contact(&pubkey).unwrap().user_blocked);
    // `contacts.json`'s `ContactRecord` has no field for this at all — the document must be
    // byte-for-byte unaffected.
    assert_eq!(read_contacts(), contacts_before);

    // Unblocking is also wired (SetUserBlockedRequest::blocked accepts both directions).
    let unblock = Effect::SetUserBlocked(SetUserBlockedEffect {
        request: SetUserBlockedRequest {
            pubkey,
            blocked: false,
        },
        outcome: None,
    });
    match dispatch_effect(unblock).await {
        WorkerEvent::Completed(Effect::SetUserBlocked(SetUserBlockedEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected unblock to complete, got {other:?}"),
    }
    assert!(!read_trust().contact(&pubkey).unwrap().user_blocked);
}

#[tokio::test]
async fn set_user_blocked_for_an_unknown_contact_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (_id, pubkey, _hint) = peer_id();

    let effect = Effect::SetUserBlocked(SetUserBlockedEffect {
        request: SetUserBlockedRequest {
            pubkey,
            blocked: true,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::SetUserBlocked(_), message) => assert!(!message.is_empty()),
        other => {
            panic!("expected SetUserBlocked to fail closed for an unknown contact, got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// SetPolicyOverride
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_policy_override_only_touches_contacts_json_never_trust_bin() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();
    dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    }))
    .await;
    // Raw sealed bytes, not just a handful of hand-picked `Contact` fields — the same
    // full-document-equality strength as this test's sibling,
    // `set_user_blocked_only_touches_trust_bin_never_contacts_json`'s own `ContactsDocument`
    // comparison. `Contact`/`TrustStore` don't derive `PartialEq`, so the sealed on-disk bytes are
    // the direct equivalent here.
    let trust_bytes_before =
        std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");

    let effect = Effect::SetPolicyOverride(SetPolicyOverrideEffect {
        request: SetPolicyOverrideRequest {
            pubkey,
            policy_override: Some(PolicyOverride::RelayOnly),
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::SetPolicyOverride(SetPolicyOverrideEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected SetPolicyOverride to complete, got {other:?}"),
    }

    assert_eq!(
        read_contacts().contacts[0].policy_override,
        Some(PolicyOverride::RelayOnly)
    );
    // `TrustStore` has no concept of relay policy at all — `trust.bin` must be byte-for-byte
    // unaffected, exactly as `set_user_blocked_only_touches_trust_bin_never_contacts_json` asserts
    // full `ContactsDocument` equality for the opposite direction.
    let trust_bytes_after =
        std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");
    assert_eq!(trust_bytes_after, trust_bytes_before);
}

#[tokio::test]
async fn set_policy_override_for_an_unknown_contact_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (_id, pubkey, _hint) = peer_id();

    let effect = Effect::SetPolicyOverride(SetPolicyOverrideEffect {
        request: SetPolicyOverrideRequest {
            pubkey,
            policy_override: Some(PolicyOverride::Direct),
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::SetPolicyOverride(_), message) => {
            assert!(!message.is_empty())
        }
        other => panic!(
            "expected SetPolicyOverride to fail closed for an unknown contact, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// DeleteContact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_contact_removes_only_the_local_row_leaving_trust_bin_untouched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (id, pubkey, hint) = peer_id();
    dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: Some("Alice".to_string()),
        },
        outcome: None,
    }))
    .await;

    let effect = Effect::DeleteContact(DeleteContactEffect {
        request: DeleteContactRequest { pubkey },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected DeleteContact to complete, got {other:?}"),
    }

    assert!(read_contacts().contacts.is_empty());
    let trust = read_trust();
    let contact = trust
        .contact(&pubkey)
        .expect("TrustStore record must survive a DeleteContact");
    assert_eq!(contact.state, TrustState::Pinned);
    assert_eq!(contact.petname.as_deref(), Some("Alice"));
}

#[tokio::test]
async fn delete_contact_for_an_already_absent_row_is_an_idempotent_no_op() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    setup_os_account();
    let (_id, pubkey, _hint) = peer_id();

    let effect = Effect::DeleteContact(DeleteContactEffect {
        request: DeleteContactRequest { pubkey },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected a no-op delete to still complete, got {other:?}"),
    }
    assert!(read_contacts().contacts.is_empty());
}

// ---------------------------------------------------------------------------
// File-backed accounts: the documented, fail-closed known gap (see
// `worker.rs::open_account_store`'s own doc comment).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_contact_for_a_file_backed_account_fails_closed_with_an_actionable_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile: PathBuf = tmp.path().join("account.key");
    let fs = FileSecretStore::new(&keyfile, "correct horse battery staple");
    let account = generate_account(&fs, "self.example").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");
    let (id, pubkey, hint) = peer_id();

    let effect = Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id,
            pubkey,
            hint,
            petname: None,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::AddContact(_), message) => {
            assert!(
                message.contains("passphrase-protected"),
                "message should name the real gap, got: {message}"
            );
        }
        other => {
            panic!("expected AddContact to fail closed for a file-backed account, got {other:?}")
        }
    }
    // Never fell back to writing anything unsealed/unauthenticated.
    assert!(!account::trust_path().unwrap().exists());
}
