//! `meridian_tui::worker` — task 4.32's own test target
//! (`cargo nextest run -p meridian-tui --test run_worker_trust`).
//!
//! Dispatches `AcceptRequest`/`RejectRequest`/`MarkVerified`/`AcknowledgeKeyChange` effects directly
//! against `meridian_tui::worker::dispatch` (no live screen stack, no channel plumbing — same shape
//! as `tests/run_worker_contacts.rs`) and asserts the real `trust.bin`/`sessions.bin` side effects
//! each one's own doc comment in `crate::app` requires — in particular the two properties this
//! task's own file names explicitly:
//!
//! 1. **"reject leaves no trace"** ([`reject_leaves_the_queue_looking_exactly_like_the_sender_was_
//!    never_seen`]): a real before/after comparison — the pending-request/session/trust-store shape
//!    for a rejected sender must be indistinguishable from a sender who was never contacted at all,
//!    not merely "the call returned success".
//! 2. **The un-softenable key-change semantics stay intact through a real persist round trip**
//!    ([`mark_verified_persists_through_a_fresh_trust_store_reload`],
//!    [`acknowledge_key_change_persists_through_a_fresh_trust_store_reload`],
//!    [`acknowledge_key_change_on_a_contact_that_is_not_pinned_key_changed_fails_closed_and_never_
//!    mutates_trust_bin`]) — a fresh, independent [`TrustStore::open_at_rest`] reload (not just the
//!    in-memory value the dispatch call happened to return) sees the change, and a genuine
//!    [`TrustError::NotAcknowledgeable`] refusal is propagated as a real [`WorkerEvent::Failed`],
//!    never swallowed into a false completion.
//!
//! ## Why `OsSecretStore` + `install_mock_keystore`, not `StoreChoice::File`
//! Same reasoning as `tests/run_worker_contacts.rs`'s own module doc: none of this task's four
//! request types carries a `StoreChoice`/passphrase — `worker.rs::open_account_store` re-derives a
//! `SecretStore`/`KeyHandle` fresh from the real, already-onboarded `account.json` on every dispatch,
//! and today that only resolves for an OS-keystore-backed account.
//!
//! ## Building a genuine pending [`MessageRequest`]
//! `meridian_core::chat::ChatState::pending_requests`/`request_order` have no public seeding API
//! (by design — see that module's own doc), so [`receive_first_contact`] below drives the
//! real gate exactly like `apps/core/tests/message_request_gate.rs`'s own `Party` fixture does: a
//! genuine X3DH handshake (`generate_bundle` → `start_initiator_session` → `seal_outbound` →
//! `open_inbound`), just against the real OS-keystore-backed store this file's account under test
//! uses (`bob`), with an independent, unrelated `MemorySecretStore`-backed peer (`alice`) standing in
//! for the sender — never a hand-constructed `MessageRequest`/`Contact` in an assumed-correct state.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use meridian_core::account::{self, AccountDescriptor};
use meridian_core::chat::ChatState;
use meridian_core::envelope::ChatContent;
use meridian_core::identity::{
    generate_account, install_mock_keystore, AccountId, MemorySecretStore, OsSecretStore,
};
use meridian_core::signaling::generate_bundle;
use meridian_core::trust::{TrustError, TrustState, TrustStore};

use meridian_tui::app::{
    AcceptRequestEffect, AcceptRequestRequest, AcknowledgeKeyChangeEffect,
    AcknowledgeKeyChangeRequest, AddContactEffect, AddContactRequest, AddedContact,
    DeleteContactEffect, DeleteContactRequest, Effect, MarkVerifiedEffect, MarkVerifiedRequest,
    RejectRequestEffect, RejectRequestRequest, RepairAcceptedContactEffect,
    RepairAcceptedContactRequest, RepairableContact, ScanRepairableContactsEffect,
    ScanRepairableContactsRequest, WorkerEvent,
};
use meridian_tui::store::contacts::{self as contacts_store, ContactsDocument};
use meridian_tui::store::history::{self, Direction as HistDirection, MessageState};
use meridian_tui::worker::{dispatch, OnboardingSession};

const NOW: u64 = 1_760_000_000;

// ---------------------------------------------------------------------------
// `$MERIDIAN_HOME` + mock-keystore environment guard — mirrors
// `apps/tui/tests/run_worker_contacts.rs`'s own `EnvGuard` exactly.
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// See `run_worker_contacts.rs`'s own `KEYRING_WARMUP` doc comment for exactly why this exists —
/// same fix, needed independently in every test binary in this crate that reaches
/// `worker.rs::init_os_keystore`.
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
            let _ = keyring::Entry::new("meridian-tui-trust-test-warmup", "warmup");
        });
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

const SERVICE: &str = "meridian-tui-trust-test";

/// Mints a real OS-keystore-backed account (against the mock keystore [`EnvGuard::set`] already
/// installed) and saves its real `account.json` — the exact shape `worker.rs::open_account_store`
/// re-derives its `SecretStore`/`KeyHandle` from on every dispatch below.
fn setup_os_account() -> AccountId {
    let os = OsSecretStore::new(SERVICE);
    let account = generate_account(&os, "bob.example").expect("generate_account");
    AccountDescriptor::new_os(&account, SERVICE)
        .save()
        .expect("save account.json");
    account
}

fn read_trust(bob: &AccountId) -> TrustStore {
    let os = OsSecretStore::new(SERVICE);
    let bytes = std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");
    TrustStore::open_at_rest(&os, bob.handle(), &bytes).expect("open trust.bin")
}

fn read_chat(bob: &AccountId) -> ChatState {
    let os = OsSecretStore::new(SERVICE);
    let bytes = std::fs::read(account::sessions_path().unwrap()).expect("sessions.bin exists");
    ChatState::open_at_rest(&os, bob.handle(), &bytes).expect("open sessions.bin")
}

/// The real, sealed `contacts.json` as it stands on disk — read back through the same
/// `crate::store::contacts` loader the TUI itself uses (task 4.42: `run_accept_request` now writes
/// this file too, so every accept test below asserts the display row it produced, not only
/// `trust.bin`).
fn read_contacts(bob: &AccountId) -> ContactsDocument {
    let os = OsSecretStore::new(SERVICE);
    contacts_store::load_or_default(&os, bob.handle()).expect("load contacts.json")
}

/// The real, sealed `history/<sender>.jsonl` for `sender_ik`, as it stands on disk — read back
/// through the same `crate::store::history` loader the TUI itself uses (task 4.49:
/// `run_accept_request` now writes the accepted sender's intro here too).
fn read_history(bob: &AccountId, sender_ik: &[u8; 32]) -> Vec<history::HistoryEntry> {
    let os = OsSecretStore::new(SERVICE);
    history::load_or_default(&hex::encode(sender_ik), &os, bob.handle())
        .expect("load history.jsonl")
}

fn write_chat(bob: &AccountId, chat: &ChatState) {
    let os = OsSecretStore::new(SERVICE);
    let path = account::sessions_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sealed = chat
        .seal_at_rest(&os, bob.handle())
        .expect("seal sessions.bin");
    std::fs::write(&path, sealed).expect("write sessions.bin");
}

fn write_trust(bob: &AccountId, trust: &TrustStore) {
    let os = OsSecretStore::new(SERVICE);
    let path = account::trust_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sealed = trust
        .seal_at_rest(&os, bob.handle())
        .expect("seal trust.bin");
    std::fs::write(&path, sealed).expect("write trust.bin");
}

async fn dispatch_effect(effect: Effect) -> WorkerEvent {
    let mut session = OnboardingSession::default();
    dispatch(effect, &mut session).await
}

// ---------------------------------------------------------------------------
// An independent, `MemorySecretStore`-backed sender — never the account under test — used to drive
// a genuine X3DH handshake into `bob`'s real, OS-keystore-backed `ChatState`. Mirrors
// `apps/core/tests/message_request_gate.rs::Party` exactly, just against `meridian_core`'s
// re-exports instead of the internal crates directly.
// ---------------------------------------------------------------------------

struct Alice {
    store: MemorySecretStore,
    account: AccountId,
}

impl Alice {
    fn new() -> Self {
        let store = MemorySecretStore::new();
        let account = generate_account(&store, "alice.example").expect("generate_account");
        Self { store, account }
    }

    fn ik(&self) -> [u8; 32] {
        *self.account.public_key().as_bytes()
    }

    /// Establishes a real initiator session against `bob_ik`'s bundle and returns the opening
    /// prekey envelope, ready to hand to `bob`'s own `ChatState::open_inbound`.
    fn opening_envelope(&self, bob_ik: &[u8; 32], spk: &[u8; 32], opk: [u8; 32]) -> Vec<u8> {
        let ik = self.ik();
        let mut alice_chat = ChatState::default();
        alice_chat
            .start_initiator_session(
                &self.store,
                self.account.handle(),
                &ik,
                bob_ik,
                spk,
                Some(opk),
            )
            .expect("start_initiator_session");
        alice_chat
            .seal_outbound(
                &self.store,
                self.account.handle(),
                &ik,
                bob_ik,
                &ChatContent::Text {
                    id: [1u8; 16],
                    body: "hi bob, it's alice".into(),
                },
            )
            .expect("seal_outbound")
    }
}

/// Publishes `bob`'s bundle (through the real OS-keystore-backed store) and drives an independent
/// `alice` peer's opening envelope through `bob`'s own `ChatState::open_inbound`, landing a genuine
/// [`meridian_core::chat::MessageRequest`] in `bob_chat.pending_requests` — see the module doc's
/// "Building a genuine pending MessageRequest" section for why this, not a hand-built fixture.
fn receive_first_contact(bob: &AccountId, bob_chat: &mut ChatState) -> Alice {
    let os = OsSecretStore::new(SERVICE);
    let bob_ik = *bob.public_key().as_bytes();
    let gen = generate_bundle(&os, bob.handle(), bob_ik, 5).expect("generate_bundle");
    let otks: Vec<([u8; 32], [u8; 32])> = gen
        .bundle
        .otks
        .iter()
        .zip(gen.otk_secrets.iter())
        .map(|(p, s)| (*p, **s))
        .collect();
    bob_chat
        .vault
        .set_bundle(gen.bundle.spk, *gen.spk_secret, otks, NOW);

    let alice = Alice::new();
    let alice_ik = alice.ik();
    let blob = alice.opening_envelope(&bob_ik, &gen.bundle.spk, gen.bundle.otks[0]);

    let outcome = bob_chat.open_inbound(&os, bob.handle(), &bob_ik, &alice_ik, &blob);
    assert!(
        matches!(outcome, Err(meridian_core::chat::ChatError::MessageRequest)),
        "fixture setup sanity: a first-contact envelope must land in the request queue, got \
         {outcome:?}"
    );
    assert!(
        bob_chat.pending_request(&alice_ik).is_some(),
        "fixture setup sanity: the request must actually be queued"
    );
    assert!(
        bob_chat.has_session(&alice_ik),
        "fixture setup sanity: the crypto session is already established even though the request \
         is gated"
    );
    alice
}

// ---------------------------------------------------------------------------
// AcceptRequest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_request_delivers_the_session_and_tofu_pins_the_sender_with_an_empty_hint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&bob, &bob_chat);
    // No `trust.bin` at all yet — accept is the first thing that ever touches it for this sender.
    assert!(!account::trust_path().unwrap().exists());

    let effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    let added = match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected AcceptRequest to complete, got {other:?}"),
    };

    let chat_after = read_chat(&bob);
    assert!(
        chat_after.pending_request(&alice_ik).is_none(),
        "accept must remove the request from the queue"
    );
    assert!(
        chat_after.has_session(&alice_ik),
        "accept must keep the underlying session live — this is a delivery decision, not a \
         session teardown"
    );

    let trust_after = read_trust(&bob);
    let contact = trust_after
        .contact(&alice_ik)
        .expect("accept must TOFU-pin the sender");
    assert_eq!(contact.state, TrustState::Pinned);
    assert_eq!(
        contact.hint, "",
        "AcceptRequestRequest carries no hint (MessageRequest has none) — worker.rs must pass an \
         empty hint through, never fabricate one"
    );
    assert_eq!(contact.pinned_key_history.len(), 1);

    // --- Task 4.42 (Shape A): the display row this accept must also have written ---------------
    let doc = read_contacts(&bob);
    assert_eq!(
        doc.contacts.len(),
        1,
        "accept must synthesize exactly one contacts.json display row for the sender — without it \
         `screens::main::build_contact_entries`' contacts.json-driven join leaves the accepted \
         sender invisible in the live UI (task 4.41's Defect C)"
    );
    let record = &doc.contacts[0];
    assert_eq!(record.pubkey, hex::encode(alice_ik));
    assert_eq!(
        record.id, "",
        "no `mrd1:` id may be invented for a sender whose hint is empty — `Contact::id_string()` \
         genuinely fails there (ADR 0001's self-certifying-key + routing-hint identity), so the \
         row records the honest empty string"
    );
    assert_eq!(record.hint, "");
    assert_eq!(
        record.petname, None,
        "a wire-observed key never gets a petname"
    );
    assert_eq!(
        record.trust,
        meridian_tui::store::contacts::TrustLabel::Pinned
    );
    assert_eq!(
        record.conv_handle, None,
        "conv_handle stays None until a conversation is first opened"
    );
    assert_eq!(record.added_at, record.last_activity_at);
    assert_eq!(record.unread, 0);
    assert_eq!(doc.v, meridian_tui::store::contacts::CURRENT_VERSION);

    // --- and the AddedContact the effect carries back, for `App`'s in-memory replay -------------
    assert_eq!(
        added,
        AddedContact {
            pubkey: alice_ik,
            id: String::new(),
            hint: String::new(),
            petname: None,
            added_at: record.added_at,
            trust: TrustState::Pinned,
            user_blocked: false,
            pinned_key_history: contact.pinned_key_history.clone(),
        },
        "the outcome must be read back off the real post-observe Contact, never an assumed \
         fresh-TOFU shape (task 4.19 Finding 1's rule, applied to the accept path)"
    );

    // --- Task 4.49: the intro this accept must also have appended into history.jsonl ------------
    let history = read_history(&bob, &alice_ik);
    assert_eq!(
        history.len(),
        1,
        "accept must append exactly one history.jsonl entry for the sender's intro — without it \
         the very first message of every accepted conversation is silently, permanently absent \
         (task 4.48's fifth defect)"
    );
    let entry = &history[0];
    assert_eq!(entry.v, meridian_tui::store::history::CURRENT_VERSION);
    assert_eq!(
        entry.mid,
        hex::encode([1u8; 16]),
        "mid must come from the intro's own sender-minted id (Alice::opening_envelope's \
         ChatContent::Text {{ id: [1u8; 16], .. }}), the same field the ordinary inbound-Text \
         handler mints its own HistoryEntry.mid from"
    );
    assert_eq!(entry.dir, HistDirection::In);
    assert_eq!(entry.stream, "mrd.chat/1");
    assert_eq!(entry.body, "hi bob, it's alice");
    assert_eq!(entry.state, MessageState::Received);
}

/// End-state property 4's worker half (task 4.42, Deliverable 5): dispatching the **same**
/// `Effect::AcceptRequest` twice — what the UI does when a completion event is lost, or a stale
/// effect is replayed — must leave exactly the same on-disk state as one dispatch, and must report
/// the second one honestly as "nothing decided" (`outcome: None`) rather than fabricating a second
/// `AddedContact` that `App` would replay into the live screen a second time.
#[tokio::test]
async fn accept_request_is_idempotent_under_a_repeated_dispatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&bob, &bob_chat);

    let accept = || {
        Effect::AcceptRequest(AcceptRequestEffect {
            request: AcceptRequestRequest {
                sender_ik: alice_ik,
            },
            outcome: None,
        })
    };

    let first = match dispatch_effect(accept()).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(added),
            ..
        })) => added,
        other => panic!("expected the first accept to complete with a contact, got {other:?}"),
    };
    let doc_after_first = read_contacts(&bob);
    let trust_after_first = read_trust(&bob);
    let contact_after_first = trust_after_first
        .contact(&alice_ik)
        .cloned()
        .expect("pinned");

    match dispatch_effect(accept()).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: None,
            ..
        })) => {}
        other => {
            panic!("a repeated dispatch must still complete, but decide nothing — got {other:?}")
        }
    }

    let doc_after_second = read_contacts(&bob);
    assert_eq!(
        doc_after_second, doc_after_first,
        "a repeated accept must not duplicate, re-stamp or otherwise disturb the display row"
    );
    assert_eq!(doc_after_second.contacts.len(), 1);
    let contact_after_second = read_trust(&bob)
        .contact(&alice_ik)
        .cloned()
        .expect("still pinned");
    assert_eq!(
        contact_after_second.state, contact_after_first.state,
        "still a plain TOFU pin — a repeat accept never escalates trust"
    );
    assert_eq!(contact_after_second.state, TrustState::Pinned);
    assert_eq!(
        contact_after_second.pinned_key_history, contact_after_first.pinned_key_history,
        "no second history entry for the same key"
    );
    assert_eq!(first.added_at, doc_after_second.contacts[0].added_at);
}

#[tokio::test]
async fn accept_request_for_an_already_decided_sender_is_a_harmless_no_op() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    // Nobody has ever contacted bob — no pending request for this made-up sender key at all.
    let phantom_sender = [0x42u8; 32];
    write_chat(&bob, &ChatState::default());

    let effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: phantom_sender,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: None,
            ..
        })) => {}
        other => panic!(
            "expected a no-op accept to still complete, carrying no AddedContact (nothing was \
             decided, so there is nothing for App to replay), got {other:?}"
        ),
    }

    // Mirrors `answer_request`'s own `if let Some(req) = ...` guard: nothing was accepted, so
    // `TrustStore::observe` must never have run — no stray pin for a decision never actually made.
    assert!(
        !account::trust_path().unwrap().exists(),
        "a no-op accept must never create a trust.bin pin out of nowhere"
    );
    // Task 4.42: and no display row either — the synthesized `contacts.json` row rides on exactly
    // the same `accepted || pin_still_owed` guard, so a sender with no session never gets one.
    assert!(
        read_contacts(&bob).contacts.is_empty(),
        "a no-op accept must never create a contacts.json display row out of nowhere"
    );
}

/// Review fix: `run_accept_request` writes two separate sealed files (`sessions.bin`, then
/// `trust.bin`), not one atomic transaction. This reproduces the exact on-disk state left behind by
/// a `save_chat` that succeeded followed by a `save_trust` that failed (disk I/O error, permission
/// change, …) — by driving `ChatState::accept_request` + `save_chat` directly, the same way
/// `run_accept_request` itself does for its first step, and deliberately *not* calling
/// `TrustStore::observe`/`save_trust` at all, simulating the second step's failure — and then
/// dispatches a fresh `Effect::AcceptRequest` for the same `sender_ik`, exactly what the UI does on
/// retry (`crate::screens::requests`'s `Failed` arm leaves the entry in the list). Before the review
/// fix, `chat.accept_request` on this retry would return `None` (already removed from
/// `pending_requests` by the simulated first attempt), so the pin step was skipped entirely and the
/// retry reported success with no `TrustStore` record ever created for the sender. Asserts the real,
/// persisted `Contact` — from a fresh, independent `TrustStore::open_at_rest` reload, not the
/// in-memory return value — now exists after the retry.
#[tokio::test]
async fn accept_request_retry_after_a_partial_failure_still_completes_the_pin() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();

    // --- Simulate the first, partially-successful attempt --------------------------------------
    // Step 1 (chat side) succeeds, exactly like `run_accept_request`'s own first step.
    assert!(
        bob_chat.accept_request(&alice_ik).is_some(),
        "fixture setup sanity: a real pending request must actually be accepted here"
    );
    write_chat(&bob, &bob_chat);
    // Step 2 (trust side) is deliberately never run here — this is the failure being simulated.
    assert!(
        !account::trust_path().unwrap().exists(),
        "fixture setup sanity: the simulated partial failure leaves no trust.bin at all yet"
    );

    // --- Act: the UI's retry — a fresh AcceptRequest effect for the same sender ----------------
    let effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(_),
            ..
        })) => {}
        other => panic!("expected the retry to complete, got {other:?}"),
    }

    // --- Assert: the retry actually completed the pin this time --------------------------------
    let trust_after = read_trust(&bob);
    let contact = trust_after.contact(&alice_ik).expect(
        "the retry must complete the pin the first, partially-successful attempt left owed — a \
         live, delivering session must never be left with no TrustStore record at all",
    );
    assert_eq!(contact.state, TrustState::Pinned);
    assert_eq!(contact.hint, "");
    assert_eq!(contact.pinned_key_history.len(), 1);
    // Task 4.42: the display row rides on the same `pin_still_owed` disjunct, so the retry that
    // completes the owed pin also completes the owed row — the sender is never left pinned but
    // invisible in the UI.
    let doc = read_contacts(&bob);
    assert_eq!(doc.contacts.len(), 1);
    assert_eq!(doc.contacts[0].pubkey, hex::encode(alice_ik));
    assert_eq!(doc.contacts[0].id, "");
    // Task 4.49: the `pin_still_owed`-only retry branch has no `MessageRequest` to source an intro
    // from (`chat.accept_request` already returned `None` here, consumed by the simulated first
    // attempt above) — the retry must not fabricate a history entry it has no real content for.
    assert!(
        read_history(&bob, &alice_ik).is_empty(),
        "a pin_still_owed-only retry must not write a history.jsonl entry it has no \
         MessageRequest to source content from"
    );
}

// ---------------------------------------------------------------------------
// ScanRepairableContacts / RepairAcceptedContact (task 5.2)
//
// Extends the coverage above — never duplicates it: `accept_request_retry_after_a_partial_
// failure_still_completes_the_pin` (immediately above) already owns "a retry completes an owed
// pin/row"; these tests own the diagnostics-surfaced repair path for what a retry, by design, never
// re-attempts (a lost `contacts.json` row / a lost `history.jsonl` intro), and the repair-vs-
// tombstone distinction that path must never blur.
// ---------------------------------------------------------------------------

fn scan(effect: ScanRepairableContactsEffect) -> Effect {
    Effect::ScanRepairableContacts(effect)
}

async fn scan_repairable() -> Vec<RepairableContact> {
    match dispatch_effect(scan(ScanRepairableContactsEffect {
        request: ScanRepairableContactsRequest,
        outcome: None,
    }))
    .await
    {
        WorkerEvent::Completed(Effect::ScanRepairableContacts(ScanRepairableContactsEffect {
            outcome: Some(contacts),
            ..
        })) => contacts,
        other => panic!("expected the scan to complete with a contact list, got {other:?}"),
    }
}

async fn repair(pubkey: [u8; 32]) -> WorkerEvent {
    dispatch_effect(Effect::RepairAcceptedContact(RepairAcceptedContactEffect {
        request: RepairAcceptedContactRequest { pubkey },
        outcome: None,
    }))
    .await
}

/// Reproduces the genuine partial failure `run_accept_request`'s own doc comment names for its
/// `contacts.json` write: `trust.bin` succeeds, `contacts.json` never does — so `history.jsonl`
/// (sequenced strictly after it) never even gets attempted. Both are provably missing, and the scan/
/// repair must recover both from `trust.bin`'s own already-real `Contact`.
#[tokio::test]
async fn repair_rebuilds_both_the_contacts_row_and_the_history_intro_after_a_contacts_json_failure()
{
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();

    // --- Simulate: chat side + trust side both succeed, contacts.json/history.jsonl never do ----
    assert!(bob_chat.accept_request(&alice_ik).is_some());
    write_chat(&bob, &bob_chat);
    let mut trust = TrustStore::default();
    trust.observe(alice_ik, "", NOW);
    write_trust(&bob, &trust);
    assert!(read_contacts(&bob).contacts.is_empty(), "fixture sanity");
    assert!(read_history(&bob, &alice_ik).is_empty(), "fixture sanity");

    // --- The scan must list exactly this contact, both flags set -------------------------------
    let listed = scan_repairable().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].pubkey, alice_ik);
    assert!(listed[0].missing_contact_row);
    assert!(listed[0].missing_history_intro);

    // --- The repair must fix both, from trust.bin's own real Contact ---------------------------
    let outcome = match repair(alice_ik).await {
        WorkerEvent::Completed(Effect::RepairAcceptedContact(RepairAcceptedContactEffect {
            outcome: Some(outcome),
            ..
        })) => outcome,
        other => panic!("expected the repair to complete with a real outcome, got {other:?}"),
    };
    assert!(outcome.contact_row_repaired);
    assert!(outcome.history_repaired);

    let doc = read_contacts(&bob);
    assert_eq!(doc.contacts.len(), 1);
    assert_eq!(doc.contacts[0].pubkey, hex::encode(alice_ik));
    assert_eq!(doc.contacts[0].id, "");
    assert_eq!(
        doc.contacts[0].trust,
        meridian_tui::store::contacts::TrustLabel::Pinned
    );

    let history = read_history(&bob, &alice_ik);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].dir, HistDirection::In);
    assert_eq!(history[0].state, MessageState::Received);
    assert!(
        !history[0].body.is_empty(),
        "the repaired entry must carry an honest placeholder, never an empty body"
    );

    // --- A second scan/repair against the now-healthy contact is a genuine no-op ---------------
    assert!(
        scan_repairable().await.is_empty(),
        "a repaired contact must not still be listed as repairable"
    );
    match repair(alice_ik).await {
        WorkerEvent::Completed(Effect::RepairAcceptedContact(RepairAcceptedContactEffect {
            outcome: None,
            ..
        })) => {}
        other => {
            panic!("expected a no-op repair against an already-healthy contact, got {other:?}")
        }
    }
    assert_eq!(
        read_contacts(&bob),
        doc,
        "a no-op repair must not touch the row"
    );
    assert_eq!(
        read_history(&bob, &alice_ik),
        history,
        "a no-op repair must not touch the transcript"
    );
}

/// Reproduces the narrower, `history.jsonl`-only failure task 4.49's own doc comment names — driven
/// through the *real* `pin_still_owed` retry path (the same fixture shape as
/// `accept_request_retry_after_a_partial_failure_still_completes_the_pin` above), not a hand-rolled
/// one: the retry completes the pin and the row (task 4.42's own guard), but by design never
/// re-attempts the history write, since the retry's own `chat.accept_request` call returns `None`
/// (no `MessageRequest` to source content from). The repair must fix only the transcript, never
/// re-touch the already-healthy row.
#[tokio::test]
async fn repair_appends_a_placeholder_history_entry_after_the_narrower_history_only_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();

    // Step 1 only (mirrors the existing retry test's own fixture) — trust/contacts/history all
    // still owed.
    assert!(bob_chat.accept_request(&alice_ik).is_some());
    write_chat(&bob, &bob_chat);

    // The real retry completes the pin and the row, but — by design — no history entry.
    let retry_effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch_effect(retry_effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(_),
            ..
        })) => {}
        other => panic!("expected the retry to complete, got {other:?}"),
    }
    let doc_before = read_contacts(&bob);
    assert_eq!(doc_before.contacts.len(), 1, "fixture sanity");
    assert!(read_history(&bob, &alice_ik).is_empty(), "fixture sanity");

    // --- The scan must list exactly this contact, only the history flag set --------------------
    let listed = scan_repairable().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].pubkey, alice_ik);
    assert!(!listed[0].missing_contact_row);
    assert!(listed[0].missing_history_intro);

    // --- The repair must fix only the transcript ------------------------------------------------
    let outcome = match repair(alice_ik).await {
        WorkerEvent::Completed(Effect::RepairAcceptedContact(RepairAcceptedContactEffect {
            outcome: Some(outcome),
            ..
        })) => outcome,
        other => panic!("expected the repair to complete with a real outcome, got {other:?}"),
    };
    assert!(
        !outcome.contact_row_repaired,
        "the row was already healthy — repair must not report touching it"
    );
    assert!(outcome.history_repaired);

    assert_eq!(
        read_contacts(&bob),
        doc_before,
        "an already-healthy contacts.json row must be left byte-for-byte untouched"
    );
    let history = read_history(&bob, &alice_ik);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].dir, HistDirection::In);
    assert_eq!(history[0].state, MessageState::Received);
}

/// A fully-healthy contact (a genuine, uninterrupted accept) must never be listed as repairable, and
/// a repair forced against it anyway (defense in depth — the worker re-derives eligibility itself,
/// never trusting a stale scan) must be a real no-op that touches neither file.
#[tokio::test]
async fn repair_never_touches_an_already_healthy_contact() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&bob, &bob_chat);

    let accept_effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch_effect(accept_effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(_),
            ..
        })) => {}
        other => panic!("expected the genuine accept to complete, got {other:?}"),
    }
    let doc_before = read_contacts(&bob);
    let history_before = read_history(&bob, &alice_ik);
    assert_eq!(doc_before.contacts.len(), 1, "fixture sanity");
    assert_eq!(history_before.len(), 1, "fixture sanity");

    assert!(
        scan_repairable().await.is_empty(),
        "a fully-healthy accept must never be listed as repairable"
    );

    match repair(alice_ik).await {
        WorkerEvent::Completed(Effect::RepairAcceptedContact(RepairAcceptedContactEffect {
            outcome: None,
            ..
        })) => {}
        other => panic!(
            "a repair forced against an already-healthy contact must be a real no-op, got {other:?}"
        ),
    }
    assert_eq!(read_contacts(&bob), doc_before);
    assert_eq!(read_history(&bob, &alice_ik), history_before);
}

/// The exact case this whole task exists to stay distinct from: a genuine accept completes fully
/// (real `contacts.json` row, real history), the user then explicitly deletes the contact
/// ([`DeleteContactRequest`]'s own "removes only the local `contacts.json` row" contract), and the
/// repair path must never mistake that for a partial failure and resurrect the row.
#[tokio::test]
async fn repair_never_resurrects_a_contact_the_user_explicitly_deleted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&bob, &bob_chat);

    let accept_effect = Effect::AcceptRequest(AcceptRequestEffect {
        request: AcceptRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch_effect(accept_effect).await {
        WorkerEvent::Completed(Effect::AcceptRequest(AcceptRequestEffect {
            outcome: Some(_),
            ..
        })) => {}
        other => panic!("expected the genuine accept to complete, got {other:?}"),
    }
    let history_before_delete = read_history(&bob, &alice_ik);
    assert_eq!(history_before_delete.len(), 1, "fixture sanity");

    // --- The user explicitly deletes the contact ------------------------------------------------
    match dispatch_effect(Effect::DeleteContact(DeleteContactEffect {
        request: DeleteContactRequest { pubkey: alice_ik },
        outcome: None,
    }))
    .await
    {
        WorkerEvent::Completed(Effect::DeleteContact(DeleteContactEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected the delete to complete, got {other:?}"),
    }
    assert!(
        read_contacts(&bob).contacts.is_empty(),
        "fixture sanity: the row must actually be gone"
    );
    // trust.bin/history.jsonl survive untouched — DeleteContact's own contract.
    assert!(
        read_trust(&bob).contact(&alice_ik).is_some(),
        "fixture sanity"
    );
    assert_eq!(
        read_history(&bob, &alice_ik),
        history_before_delete,
        "fixture sanity: delete must not touch history.jsonl"
    );

    // --- The tombstoned contact must never be listed as repairable -----------------------------
    assert!(
        scan_repairable().await.is_empty(),
        "a tombstoned contact must never be surfaced as repairable"
    );

    // --- And a repair forced against it anyway must be refused, not silently resurrect it ------
    match repair(alice_ik).await {
        WorkerEvent::Failed(Effect::RepairAcceptedContact(_), message) => {
            assert!(
                message.to_lowercase().contains("delet")
                    || message.to_lowercase().contains("resurrect"),
                "expected an honest tombstone-refusal message, got: {message}"
            );
        }
        other => panic!("expected the repair to be refused, got {other:?}"),
    }
    assert!(
        read_contacts(&bob).contacts.is_empty(),
        "the refused repair must never resurrect the deleted row"
    );
    assert_eq!(
        read_history(&bob, &alice_ik),
        history_before_delete,
        "the refused repair must never touch the surviving transcript"
    );
}

/// A `pubkey` with no `trust.bin` record at all (never accepted, never added) is refused, not
/// silently treated as a no-op — the same "propagate faithfully" discipline every other guard in
/// this module already follows.
#[tokio::test]
async fn repair_refuses_a_pubkey_with_no_trust_record_at_all() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let _bob = setup_os_account();

    let phantom = [0x77u8; 32];
    match repair(phantom).await {
        WorkerEvent::Failed(Effect::RepairAcceptedContact(_), message) => {
            assert!(!message.is_empty());
        }
        other => panic!("expected a phantom pubkey's repair to be refused, got {other:?}"),
    }
}

/// A `trust.bin` contact created via [`Effect::AddContact`] (a real, non-empty hint) is not
/// accept-shaped and must never be treated as repairable, even if its `contacts.json` row happens to
/// be missing for an unrelated reason — the `hint == ""` eligibility gate this whole path relies on.
#[tokio::test]
async fn repair_refuses_a_contact_that_was_never_accept_shaped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let _bob = setup_os_account();

    let added_pubkey = [0x99u8; 32];
    match dispatch_effect(Effect::AddContact(AddContactEffect {
        request: AddContactRequest {
            id: format!("mrd1:{}@friend.example", hex::encode(added_pubkey)),
            pubkey: added_pubkey,
            hint: "friend.example".to_string(),
            petname: None,
        },
        outcome: None,
    }))
    .await
    {
        WorkerEvent::Completed(Effect::AddContact(AddContactEffect {
            outcome: Some(_), ..
        })) => {}
        other => panic!("expected the add to complete, got {other:?}"),
    }

    assert!(
        scan_repairable().await.is_empty(),
        "an AddContact-originated contact must never be listed as repairable"
    );
    match repair(added_pubkey).await {
        WorkerEvent::Failed(Effect::RepairAcceptedContact(_), message) => {
            assert!(!message.is_empty());
        }
        other => panic!(
            "expected a repair against a non-accept-shaped contact to be refused, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// RejectRequest — "leaves no trace"
// ---------------------------------------------------------------------------

/// The core property this task's own file names: a real, disk-round-tripped before/after
/// comparison, not just "the call returned success". Two independent accounts are set up
/// identically; one is contacted-then-rejected, the other is never contacted at all; the resulting
/// persisted state for the (would-be) sender is asserted equal on every observable axis — pending
/// request, live session, and trust-store record.
#[tokio::test]
async fn reject_leaves_the_queue_looking_exactly_like_the_sender_was_never_seen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();

    // --- Before: alice reaches bob's request queue -------------------------------------------
    let mut bob_chat = ChatState::default();
    let alice = receive_first_contact(&bob, &mut bob_chat);
    let alice_ik = alice.ik();
    write_chat(&bob, &bob_chat);

    let before = read_chat(&bob);
    assert_eq!(before.pending_requests().count(), 1);
    assert!(before.has_session(&alice_ik));

    // --- Act: reject ---------------------------------------------------------------------------
    let effect = Effect::RejectRequest(RejectRequestEffect {
        request: RejectRequestRequest {
            sender_ik: alice_ik,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::RejectRequest(RejectRequestEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected RejectRequest to complete, got {other:?}"),
    }

    // --- After: real disk reload, compared against "never contacted at all" ------------------
    let after = read_chat(&bob);
    assert_eq!(
        after.pending_requests().count(),
        0,
        "the queue must be empty again after a real reload"
    );
    assert!(
        after.pending_request(&alice_ik).is_none(),
        "no pending request may remain for the rejected sender"
    );
    assert!(
        !after.has_session(&alice_ik),
        "reject must discard the established session's key material, not just hide the request"
    );

    // `TrustStore` was never touched by either the accept-adjacent code path or reject itself —
    // exactly as if `alice` had never sent bob anything at all.
    assert!(
        !account::trust_path().unwrap().exists(),
        "reject must leave no trust.bin trace of the rejected sender"
    );

    // Direct comparison against a second, genuinely-never-contacted account: same observable shape.
    let stranger = setup_stranger_account();
    write_chat(&stranger, &ChatState::default());
    let never_contacted = read_chat(&stranger);
    assert_eq!(
        after.pending_requests().count(),
        never_contacted.pending_requests().count()
    );
    assert_eq!(
        after.has_session(&alice_ik),
        never_contacted.has_session(&alice_ik)
    );
}

fn setup_stranger_account() -> AccountId {
    let os = OsSecretStore::new(SERVICE);
    generate_account(&os, "stranger.example").expect("generate_account")
}

#[tokio::test]
async fn reject_request_for_a_never_seen_sender_is_a_harmless_no_op() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    write_chat(&bob, &ChatState::default());
    let phantom_sender = [0x77u8; 32];

    let effect = Effect::RejectRequest(RejectRequestEffect {
        request: RejectRequestRequest {
            sender_ik: phantom_sender,
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::RejectRequest(RejectRequestEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected a no-op reject to still complete, got {other:?}"),
    }
    assert!(!account::trust_path().unwrap().exists());
}

// ---------------------------------------------------------------------------
// MarkVerified
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_verified_persists_through_a_fresh_trust_store_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    let peer_ik = [0x11u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(peer_ik, "peer.example", NOW);
    write_trust(&bob, &trust);
    assert_eq!(
        read_trust(&bob).contact(&peer_ik).unwrap().state,
        TrustState::Pinned
    );

    let effect = Effect::MarkVerified(MarkVerifiedEffect {
        request: MarkVerifiedRequest { pubkey: peer_ik },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected MarkVerified to complete, got {other:?}"),
    }

    // The load-bearing assertion: a fresh, independent `TrustStore::open_at_rest` reload — not the
    // in-memory value the dispatch call happened to touch — sees `Verified`.
    let reloaded = read_trust(&bob);
    assert_eq!(
        reloaded.contact(&peer_ik).unwrap().state,
        TrustState::Verified
    );
}

#[tokio::test]
async fn mark_verified_clears_a_real_blocked_state_through_the_same_persist_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    let previous = [0x20u8; 32];
    let current = [0x21u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(previous, "peer.example", NOW);
    trust.mark_verified(&previous).expect("known contact");
    let resulting = trust
        .observe_key_change(&previous, current, "peer.example", NOW + 1)
        .expect("known contact, distinct new key");
    assert_eq!(
        resulting,
        TrustState::Blocked,
        "fixture setup sanity: a Verified contact's key change hard-blocks"
    );
    write_trust(&bob, &trust);

    let effect = Effect::MarkVerified(MarkVerifiedEffect {
        request: MarkVerifiedRequest { pubkey: current },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::MarkVerified(MarkVerifiedEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected MarkVerified to complete, got {other:?}"),
    }

    let reloaded = read_trust(&bob);
    assert_eq!(
        reloaded.contact(&current).unwrap().state,
        TrustState::Verified,
        "mark_verified is the only path that clears Blocked (task 4.4) — this must survive a real \
         reload, not just the in-memory transition"
    );
}

#[tokio::test]
async fn mark_verified_for_an_unknown_contact_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    write_trust(&bob, &TrustStore::default());

    let effect = Effect::MarkVerified(MarkVerifiedEffect {
        request: MarkVerifiedRequest {
            pubkey: [0x99u8; 32],
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::MarkVerified(_), message) => assert!(!message.is_empty()),
        other => {
            panic!("expected MarkVerified to fail closed for an unknown contact, got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// AcknowledgeKeyChange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acknowledge_key_change_persists_through_a_fresh_trust_store_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    let previous = [0x30u8; 32];
    let current = [0x31u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(previous, "peer.example", NOW);
    let resulting = trust
        .observe_key_change(&previous, current, "peer.example", NOW + 1)
        .expect("known contact, distinct new key");
    assert_eq!(
        resulting,
        TrustState::PinnedKeyChanged,
        "fixture setup sanity: a merely-Pinned contact's key change warns, not hard-blocks"
    );
    write_trust(&bob, &trust);

    let effect = Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
        request: AcknowledgeKeyChangeRequest { pubkey: current },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Completed(Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
            outcome: Some(()),
            ..
        })) => {}
        other => panic!("expected AcknowledgeKeyChange to complete, got {other:?}"),
    }

    let reloaded = read_trust(&bob);
    assert_eq!(
        reloaded.contact(&current).unwrap().state,
        TrustState::Pinned,
        "acknowledge re-pins — must be visible on a fresh, independent reload"
    );
}

/// The un-softenable half (tasks 4.4/4.23): a contact that is not currently `PinnedKeyChanged` —
/// here, already `Blocked` — must refuse the acknowledge with the real
/// `TrustError::NotAcknowledgeable`, propagated faithfully as `WorkerEvent::Failed`, and `trust.bin`
/// must be provably unchanged by the attempt (never silently downgraded to `Pinned`/`Verified`).
#[tokio::test]
async fn acknowledge_key_change_on_a_contact_that_is_not_pinned_key_changed_fails_closed_and_never_mutates_trust_bin(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    let previous = [0x40u8; 32];
    let current = [0x41u8; 32];

    let mut trust = TrustStore::default();
    trust.observe(previous, "peer.example", NOW);
    trust.mark_verified(&previous).expect("known contact");
    let resulting = trust
        .observe_key_change(&previous, current, "peer.example", NOW + 1)
        .expect("known contact, distinct new key");
    assert_eq!(resulting, TrustState::Blocked, "fixture setup sanity");
    write_trust(&bob, &trust);
    let trust_bytes_before =
        std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");

    let effect = Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
        request: AcknowledgeKeyChangeRequest { pubkey: current },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::AcknowledgeKeyChange(_), message) => {
            // The real, un-softened core error text — never swallowed into a generic message or,
            // worse, a false `Completed`.
            assert_eq!(message, TrustError::NotAcknowledgeable.to_string());
        }
        other => panic!(
            "expected AcknowledgeKeyChange to fail closed with NotAcknowledgeable, got {other:?}"
        ),
    }

    // `trust.bin` genuinely never changed — not sealed-and-rewritten-identically, but byte-for-byte
    // untouched (this arm reads, attempts the mutation, and only reseals/writes on `Ok`; a `Blocked`
    // contact's `acknowledge_key_change` call itself makes no mutation at all before returning `Err`
    // — see that method's own doc comment).
    let trust_bytes_after =
        std::fs::read(account::trust_path().unwrap()).expect("trust.bin exists");
    assert_eq!(trust_bytes_before, trust_bytes_after);
    assert_eq!(
        read_trust(&bob).contact(&current).unwrap().state,
        TrustState::Blocked,
        "the contact must remain hard-blocked — NotAcknowledgeable is never a bypass"
    );
}

/// The escalation-retroactivity edge (`TrustStore::acknowledge_key_change`'s own doc comment): a
/// contact that is already sitting in `PinnedKeyChanged` when `escalate_pinned_key_change` is turned
/// on is force-transitioned to `Blocked` by the *acknowledge attempt itself* — not by the key-change
/// observation — and that attempt still refuses with `NotAcknowledgeable`, proven here through the
/// same real persist round trip as every other test in this file, not just in-memory.
///
/// Review fix: this test used to turn escalation on *before* `observe_key_change`, which lands the
/// contact on `Blocked` via `observe_key_change`'s own `escalated_state` path — so the subsequent
/// `AcknowledgeKeyChange` dispatch only ever exercised the ordinary "not currently `PinnedKeyChanged`"
/// early return in `TrustStore::acknowledge_key_change`, never its escalate-and-mutate branch this
/// test's name claims to cover. Escalation is now turned on *after* the contact has already landed on
/// `PinnedKeyChanged` with escalation off, so the dispatched effect is the thing that actually walks
/// the escalate branch — and a fresh, independent `TrustStore::open_at_rest` reload (not the
/// short-lived in-memory value the dispatch call touched) is asserted to show the real, persisted
/// force-block, closing the `worker.rs::run_acknowledge_key_change` persistence gap this same review
/// pass fixed (the escalate branch mutates state and then returns `Err`, so it must persist that
/// mutation on the `Err` path too, not only on `Ok`).
#[tokio::test]
async fn acknowledge_key_change_under_escalation_force_blocks_and_still_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let bob = setup_os_account();
    let previous = [0x50u8; 32];
    let current = [0x51u8; 32];

    // Escalation is OFF for the key-change observation itself, so the contact lands on the
    // ordinary, un-escalated `PinnedKeyChanged` warning state (not `Blocked`).
    let mut trust = TrustStore::default();
    trust.observe(previous, "peer.example", NOW);
    let resulting = trust
        .observe_key_change(&previous, current, "peer.example", NOW + 1)
        .expect("known contact, distinct new key");
    assert_eq!(
        resulting,
        TrustState::PinnedKeyChanged,
        "fixture setup sanity: escalation is off for the observation itself, so this must still be \
         a plain warn, not a hard block"
    );

    // Escalation is turned on only now — *after* the contact is already sitting in
    // `PinnedKeyChanged` — so the upcoming `AcknowledgeKeyChange` dispatch is the first thing that
    // ever evaluates it against this contact, exercising `acknowledge_key_change`'s own
    // escalate-and-force-block branch rather than `observe_key_change`'s.
    trust.set_escalate_pinned_key_change(true);
    write_trust(&bob, &trust);
    assert_eq!(
        read_trust(&bob).contact(&current).unwrap().state,
        TrustState::PinnedKeyChanged,
        "fixture setup sanity: still just PinnedKeyChanged on disk before the acknowledge attempt"
    );

    let effect = Effect::AcknowledgeKeyChange(AcknowledgeKeyChangeEffect {
        request: AcknowledgeKeyChangeRequest { pubkey: current },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::AcknowledgeKeyChange(_), message) => {
            assert_eq!(message, TrustError::NotAcknowledgeable.to_string());
        }
        other => {
            panic!("expected AcknowledgeKeyChange to fail closed under escalation, got {other:?}")
        }
    }

    // The load-bearing assertion (the review fix): a fresh, independent `TrustStore::open_at_rest`
    // reload — not the in-memory value the dispatch call happened to touch — must show the real
    // force-block was actually persisted to `trust.bin`, not silently discarded on the `Err` path.
    assert_eq!(
        read_trust(&bob).contact(&current).unwrap().state,
        TrustState::Blocked,
        "the escalate-and-force-block mutation must be resealed into trust.bin even though the \
         call itself returns Err — otherwise a later plain acknowledge (escalation off again) would \
         still succeed and silently re-pin, exactly the bypass acknowledge_key_change's own doc \
         comment forbids"
    );
}

// ---------------------------------------------------------------------------
// File-backed accounts: the documented, fail-closed known gap
// (`worker.rs::open_account_store`'s own doc comment) — same shape as
// `run_worker_contacts.rs::add_contact_for_a_file_backed_account_fails_closed_with_an_actionable_message`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_verified_for_a_file_backed_account_fails_closed_with_an_actionable_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set(tmp.path());
    let keyfile = tmp.path().join("account.key");
    let fs =
        meridian_core::identity::FileSecretStore::new(&keyfile, "correct horse battery staple");
    let account = generate_account(&fs, "self.example").expect("generate_account");
    AccountDescriptor::new_file(&account, &keyfile)
        .save()
        .expect("save account.json");

    let effect = Effect::MarkVerified(MarkVerifiedEffect {
        request: MarkVerifiedRequest {
            pubkey: [0x60u8; 32],
        },
        outcome: None,
    });
    match dispatch_effect(effect).await {
        WorkerEvent::Failed(Effect::MarkVerified(_), message) => {
            assert!(
                message.contains("passphrase-protected"),
                "message should name the real gap, got: {message}"
            );
        }
        other => {
            panic!("expected MarkVerified to fail closed for a file-backed account, got {other:?}")
        }
    }
    assert!(!account::trust_path().unwrap().exists());
}
