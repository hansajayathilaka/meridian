//! IndexedDB record-sealing/schema module — ADR 0026 binding conditions 2–5 (task 12.12).
//!
//! One IndexedDB object store per ADR-0021-style bucket (`identity`, `sessions`, `contacts`,
//! `history`, `outbox` — [`Bucket`]), each record [`meridian_crypto::at_rest::seal`]/`open`-wrapped
//! **unmodified** (compiled to WASM through `meridian-core`'s re-export, `at_rest` below) under a
//! key from task 12.5's [`WebCryptoSecretStore::derive_key`] with a purpose-specific `info` string
//! per bucket ([`Bucket::key_info`]) — a key derived for `identity` can never open a `sessions`
//! record, and vice versa. Plus one unsealed object store, `state`, restricted to view geometry and
//! an opaque conversation handle (ADR 0026 binding condition 4 / ADR 0021 condition 2's `state.json`
//! analog — [`StateRecord`]).
//!
//! ## Why this lives in `apps/wasm`, not `apps/store`
//! `meridian-crypto` (needed here for `at_rest::seal`/`open`) already depends on `meridian-store`
//! (task 12.5's own crate, for DH/sign-through-the-keystore per `crypto-protocols` rule 6) — putting
//! this module in `apps/store` alongside `WebCryptoSecretStore` would make `meridian-store` depend on
//! `meridian-crypto` too, a cycle. `apps/wasm` already depends on `meridian-core` (which re-exports
//! both `meridian_store` as `store` and `meridian_crypto` as `crypto`), so it is the natural
//! cycle-free home — see `phase-12/README.md`'s architect consult and this task's own file for the
//! full reasoning.
//!
//! ## Schema versioning and fail-closed behavior (ADR 0021 conditions 5/5b, mirrored exactly)
//! Every record's plaintext content is a JSON [`Envelope`] carrying a top-level `"v"` field.
//! [`IndexedDbStore::get_sealed`]/[`IndexedDbStore::get_state`] refuse to open a record whose `v` is
//! newer than [`SCHEMA_VERSION`] — a hard [`IndexedDbError::UnsupportedVersion`], never a silent
//! downgrade or field-discarding "best effort" read. A record whose `v` is *older* than
//! [`SCHEMA_VERSION`] is forward-migrated in place via [`migrate_forward`] (currently a no-op ladder
//! — `SCHEMA_VERSION` has never bumped — but structured as the extension point a future bump uses,
//! one arm per version step, never skipping one).
//!
//! **The AEAD-failure-vs-`NotFound` distinction is the property that makes this module's fail-closed
//! story honest** (this task's own named risk — see [`IndexedDbStore::get_sealed`]'s doc comment for
//! the exact two branches). A record that was never written returns `Ok(None)` and legitimately
//! falls back to a fresh/default value. A record that *was* written but fails AEAD authentication on
//! open (wrong/rotated key, corruption, tampering) is [`IndexedDbError::SealedRecordCorrupt`] — a
//! hard error this module never catches and silently reinitializes from. This matters identically to
//! ADR 0021 condition 5b's own worked example: a browser-side `contacts` bucket's pinned-key history
//! defeats the same server key-substitution attack that reinitializing-on-any-error would erase.
//!
//! ## IndexedDB's callback API, bridged to `Future`s
//! Every meaningful `IDBRequest`/`IDBOpenDBRequest` operation is callback-based
//! (`onsuccess`/`onerror`/`onupgradeneeded`), not `Promise`-based — [`await_request`] bridges one
//! request's `onsuccess`/`onerror` pair onto a single `.await`able point via a one-shot channel, the
//! same technique `apps/wasm/src/transport.rs`'s `Signal` and `apps/store/src/webcrypto.rs`'s
//! `JsFuture`-wrapped `crypto.subtle` calls both use for their own callback/Promise seams.
//!
//! ## Concurrency (out of this task's scope)
//! No bespoke cross-tab/multi-window locking layer is added here — IndexedDB's own transaction model
//! (each `put`/`get` runs inside its own readwrite/readonly transaction) already serializes
//! same-origin access at the browser level, and this task's own testing found no gap beyond that.
//! Flagged explicitly, per this task's instruction, rather than preemptively built.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use futures_channel::oneshot;
use js_sys::Uint8Array;
use serde::{Deserialize, Serialize};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{IdbDatabase, IdbFactory, IdbRequest, IdbTransactionMode};

use meridian_core::crypto::at_rest;
use meridian_core::store::{KeyHandle, StoreError, WebCryptoSecretStore};

/// The record content schema version every bucket (sealed or not) writes and expects to read.
/// Bump this and extend [`migrate_forward`] — never the reverse — when any bucket's JSON payload
/// shape changes. Distinct from [`IDB_VERSION`] (the database's own object-store *structure*
/// version) even though both happen to be `1` today.
pub const SCHEMA_VERSION: u32 = 1;

/// The `IDBDatabase` version passed to `IDBFactory.open()` — bumped only when the *set of object
/// stores* changes (e.g. a future bucket is added), which is a different concern from
/// [`SCHEMA_VERSION`] (a given bucket's record *content* shape).
const IDB_VERSION: u32 = 1;

/// The unsealed `state`-equivalent object store name (ADR 0026 binding condition 4 / ADR 0021
/// condition 2's `state.json` analog).
const STATE_STORE: &str = "state";

/// One IndexedDB object store per ADR-0021-style bucket (ADR 0026's "Container" section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Identity,
    Sessions,
    Contacts,
    History,
    Outbox,
}

impl Bucket {
    /// Every bucket, for iterating (e.g. database setup).
    pub const ALL: [Bucket; 5] = [
        Bucket::Identity,
        Bucket::Sessions,
        Bucket::Contacts,
        Bucket::History,
        Bucket::Outbox,
    ];

    /// The IndexedDB object store name.
    pub fn store_name(self) -> &'static str {
        match self {
            Bucket::Identity => "identity",
            Bucket::Sessions => "sessions",
            Bucket::Contacts => "contacts",
            Bucket::History => "history",
            Bucket::Outbox => "outbox",
        }
    }

    /// The purpose-specific `derive_key` `info` string for this bucket — mirrors
    /// `meridian_crypto::at_rest::STORE_KEY_INFO`'s existing domain-separation pattern (ADR 0026
    /// binding condition 2). One distinct label per bucket, so a key derived for one bucket can
    /// never open a sealed record from another.
    fn key_info(self) -> &'static [u8] {
        match self {
            Bucket::Identity => b"Meridian/IndexedDB/identity/v1",
            Bucket::Sessions => b"Meridian/IndexedDB/sessions/v1",
            Bucket::Contacts => b"Meridian/IndexedDB/contacts/v1",
            Bucket::History => b"Meridian/IndexedDB/history/v1",
            Bucket::Outbox => b"Meridian/IndexedDB/outbox/v1",
        }
    }
}

/// The unsealed `state`-equivalent record (ADR 0026 binding condition 4 / ADR 0021 condition 2's
/// `state.json` analog). Restricted **by construction** to view geometry and an opaque,
/// locally-generated conversation handle — no petname, message body, key material, or
/// contact-identifying content (pubkey, `mrd1:` id, or any 1:1-correlating index) may ever be
/// written here. This structural restriction is the first line of defense; the at-rest-audit test
/// (`tests/indexeddb_audit.rs`, mirroring the 4.27/8.12 harness precedent) is the mechanical check
/// that no future bypass of this type (e.g. writing raw bytes directly) reintroduces a leak.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateRecord {
    /// View geometry only (e.g. pane split ratios, sidebar width) — a small numeric map, never a
    /// contact-identifying string.
    pub view: BTreeMap<String, f64>,
    /// The opaque, locally-generated, non-identifying handle for the last-open conversation, if
    /// any — never the peer's pubkey, `mrd1:` id, or petname (same restriction ADR 0021 condition 2
    /// draws for `state.json`'s own conversation reference).
    pub open_conversation_handle: Option<String>,
}

/// Failure modes this module can surface. Deliberately distinguishes
/// [`IndexedDbError::SealedRecordCorrupt`] (AEAD authentication failure on a record that *was*
/// found — fatal) from a genuine "no record yet" outcome, which is `Ok(None)`, never an `Err`
/// variant at all — see [`IndexedDbStore::get_sealed`]'s doc comment.
#[derive(Debug, thiserror::Error)]
pub enum IndexedDbError {
    /// An IndexedDB/browser-API failure not covered by the other variants (transaction aborted,
    /// quota exceeded, no `indexedDB` global present, …).
    #[error("IndexedDB backend error: {0}")]
    Backend(String),

    /// A sealed record was found but failed AEAD authentication on open — wrong/rotated key,
    /// corruption, or tampering. A hard, fail-closed error, **never** a reason to reinitialize the
    /// bucket to empty (ADR 0021 condition 5b, mirrored by ADR 0026 binding condition 3). Distinct
    /// from "the record does not exist" (`Ok(None)`, the only case that legitimately falls back to
    /// a fresh/default value).
    #[error(
        "sealed record failed AEAD authentication (corrupt, tampered, or wrong key) — refusing \
         to reinitialize; see ADR 0021 condition 5b"
    )]
    SealedRecordCorrupt,

    /// The record's `"v"` field is newer than this build understands. Fail closed — never silently
    /// discard unknown fields or downgrade.
    #[error(
        "record schema version {found} is newer than this build understands (supports up to \
         {supported})"
    )]
    UnsupportedVersion { found: u32, supported: u32 },

    /// The record's `"v"` field is older than [`SCHEMA_VERSION`] but no migration step exists to
    /// carry it forward (only possible once a future schema bump adds `migrate_forward` steps and
    /// this record predates all of them, or the stored `"v"` was corrupted/tampered with). Fail
    /// closed — never guess at the old shape or silently pass it through unmigrated.
    #[error("no migration path exists from schema version {found} to {supported}")]
    NoMigrationPath { found: u32, supported: u32 },

    /// The (already-decrypted, for sealed buckets) plaintext was not valid JSON in the expected
    /// envelope shape.
    #[error("record content was not valid JSON: {0}")]
    Malformed(String),

    /// [`WebCryptoSecretStore::derive_key`] failed (e.g. no key imported under this handle yet).
    #[error("key derivation failed: {0}")]
    KeyDerivation(#[from] StoreError),
}

type Result<T> = core::result::Result<T, IndexedDbError>;

/// Every record's on-the-wire (well, on-disk) plaintext shape: a top-level `"v"` field plus the
/// bucket-specific payload, matching ADR 0021 condition 5's "every JSON document carries a
/// top-level v field" discipline, applied per IndexedDB record instead of per file (ADR 0026
/// binding condition 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    v: u32,
    data: serde_json::Value,
}

/// Forward-migrates a record's JSON `data` from schema version `v` up to [`SCHEMA_VERSION`] — the
/// same "migrate forward in place, never discard, never downgrade" discipline ADR 0021 condition 5
/// establishes for the terminal client's own JSON documents. Only ever called after the
/// `v > SCHEMA_VERSION` fail-closed check has already passed (both call sites below check that
/// first), so `v <= SCHEMA_VERSION` always holds here.
fn migrate_forward(v: u32, data: serde_json::Value) -> Result<serde_json::Value> {
    debug_assert!(
        v <= SCHEMA_VERSION,
        "caller must reject v > SCHEMA_VERSION first"
    );
    if v == SCHEMA_VERSION {
        return Ok(data);
    }
    // No migrations exist yet — SCHEMA_VERSION has never bumped since this module's first
    // release, so any `v < SCHEMA_VERSION` reaching here is unexpected (there is no older shape on
    // record to migrate from). Fail closed rather than guessing at a shape or panicking — add a
    // real `if v == N { data = migrate_n_to_n_plus_1(data); v += 1; }` step (looping until
    // `v == SCHEMA_VERSION`, one step at a time, never skipping one) the day `SCHEMA_VERSION` first
    // increments past `1`.
    Err(IndexedDbError::NoMigrationPath {
        found: v,
        supported: SCHEMA_VERSION,
    })
}

/// The browser-side IndexedDB handle: one database, one object store per [`Bucket`] plus the
/// unsealed [`STATE_STORE`].
pub struct IndexedDbStore {
    db: IdbDatabase,
}

impl IndexedDbStore {
    /// Opens (creating on first use) the IndexedDB database named `db_name`. Safe to call
    /// repeatedly with the same name from the same origin — object stores are created exactly once,
    /// inside `onupgradeneeded`, the browser's own "does this database need a version bump" hook,
    /// which only fires when the database doesn't exist yet or its stored version is older than
    /// [`IDB_VERSION`].
    pub async fn open(db_name: &str) -> Result<Self> {
        let factory = indexed_db_factory()?;
        let open_req = factory
            .open_with_u32(db_name, IDB_VERSION)
            .map_err(js_err)?;

        let upgrade_req = open_req.clone();
        let on_upgrade = Closure::<dyn FnMut()>::new(move || {
            let Ok(result) = upgrade_req.result() else {
                return;
            };
            let db: IdbDatabase = result.unchecked_into();
            for bucket in Bucket::ALL {
                // Idempotent by construction: `onupgradeneeded` only fires once per version bump,
                // so `create_object_store` is only ever called when the store doesn't exist yet.
                // Ignoring the (impossible-in-practice) "already exists" error is deliberate — the
                // upgrade handler has no way to report a failure back to the async caller other
                // than aborting the whole open, which is worse than a defensive no-op here.
                let _ = db.create_object_store(bucket.store_name());
            }
            let _ = db.create_object_store(STATE_STORE);
        });
        open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));

        let result = await_request(&open_req).await.map_err(js_err)?;
        drop(on_upgrade);
        Ok(Self {
            db: result.unchecked_into(),
        })
    }

    /// Seals `payload` (wrapped in a versioned [`Envelope`]) under a `bucket`-specific key derived
    /// via [`WebCryptoSecretStore::derive_key`], and writes it to `bucket`'s object store under
    /// `key`. Uses `meridian_crypto::at_rest::seal` unmodified (ADR 0026 binding condition 2).
    pub async fn put_sealed(
        &self,
        secret_store: &WebCryptoSecretStore,
        handle: &KeyHandle,
        bucket: Bucket,
        key: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let envelope = Envelope {
            v: SCHEMA_VERSION,
            data: payload,
        };
        let plaintext =
            serde_json::to_vec(&envelope).map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        let seal_key = secret_store.derive_key(handle, bucket.key_info()).await?;
        let sealed = at_rest::seal(&seal_key, &plaintext)
            .map_err(|e| IndexedDbError::Backend(e.to_string()))?;
        put_bytes(&self.db, bucket.store_name(), key, &sealed).await
    }

    /// Reads and opens a sealed record from `bucket` under `key`.
    ///
    /// **The two failure branches below must never be conflated — this is the property that makes
    /// ADR 0026's whole fail-closed design honest (this task's own named risk):**
    /// - `Ok(None)`: no record exists yet under `key` — genuine `NotFound`. The **only** case that
    ///   legitimately falls back to a fresh/default value (ADR 0021 condition 5b).
    /// - `Err(IndexedDbError::SealedRecordCorrupt)`: a record *was* found but failed AEAD
    ///   authentication on `at_rest::open` (wrong/rotated key, corruption, tampering). A hard,
    ///   fail-closed error — never caught and silently treated as "reinitialize to empty".
    pub async fn get_sealed(
        &self,
        secret_store: &WebCryptoSecretStore,
        handle: &KeyHandle,
        bucket: Bucket,
        key: &str,
    ) -> Result<Option<serde_json::Value>> {
        // Branch 1: genuine NotFound. `IDBObjectStore.get()` resolves successfully with `undefined`
        // when no record exists — `get_bytes` surfaces that as `Ok(None)`, never an error.
        let Some(sealed) = get_bytes(&self.db, bucket.store_name(), key).await? else {
            return Ok(None);
        };

        let seal_key = secret_store.derive_key(handle, bucket.key_info()).await?;
        // Branch 2: a record was found but does not open — AEAD authentication failure. This is
        // fatal, distinct from branch 1 above, and deliberately discards `at_rest::open`'s specific
        // error (it only ever fails this way: bad length or AEAD tag mismatch) in favor of the one
        // named, hard-error variant every caller must handle as fatal.
        let plaintext =
            at_rest::open(&seal_key, &sealed).map_err(|_| IndexedDbError::SealedRecordCorrupt)?;

        let envelope: Envelope = serde_json::from_slice(&plaintext)
            .map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        if envelope.v > SCHEMA_VERSION {
            return Err(IndexedDbError::UnsupportedVersion {
                found: envelope.v,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(Some(migrate_forward(envelope.v, envelope.data)?))
    }

    /// Writes the unsealed `state`-equivalent record under `key`. `record`'s type ([`StateRecord`])
    /// structurally restricts content to view geometry and an opaque conversation handle (ADR 0026
    /// binding condition 4).
    pub async fn put_state(&self, key: &str, record: &StateRecord) -> Result<()> {
        let data =
            serde_json::to_value(record).map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        let envelope = Envelope {
            v: SCHEMA_VERSION,
            data,
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        put_bytes(&self.db, STATE_STORE, key, &bytes).await
    }

    /// Reads the unsealed `state`-equivalent record under `key`. `Ok(None)` if never written.
    pub async fn get_state(&self, key: &str) -> Result<Option<StateRecord>> {
        let Some(bytes) = get_bytes(&self.db, STATE_STORE, key).await? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        if envelope.v > SCHEMA_VERSION {
            return Err(IndexedDbError::UnsupportedVersion {
                found: envelope.v,
                supported: SCHEMA_VERSION,
            });
        }
        let data = migrate_forward(envelope.v, envelope.data)?;
        let record: StateRecord =
            serde_json::from_value(data).map_err(|e| IndexedDbError::Malformed(e.to_string()))?;
        Ok(Some(record))
    }

    /// The raw bytes actually stored under `state`'s `key` — bypasses [`StateRecord`]'s typed
    /// shape entirely. Exists for the at-rest-audit test (`tests/indexeddb_audit.rs`): the audit
    /// must scan what is genuinely persisted, not a value already round-tripped back through the
    /// restricted type, so it can catch a *future* bypass of that type (e.g. a stray extra field
    /// written some other way) — the same "scan the real bytes on disk" discipline the 4.27/8.12
    /// precedent uses.
    pub async fn get_state_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        get_bytes(&self.db, STATE_STORE, key).await
    }

    /// Writes raw, unvalidated bytes directly under `state`'s `key`, bypassing [`StateRecord`] and
    /// [`put_state`](Self::put_state) entirely. **Test/audit-harness support only** — proves the
    /// at-rest-audit scan primitive itself would catch an injected leak (the 4.27/8.12 harnesses'
    /// own "non-vacuity" check), never called from real application code, which only ever writes
    /// `state` records through [`put_state`](Self::put_state)'s typed, content-restricted API.
    pub async fn put_state_raw(&self, key: &str, bytes: &[u8]) -> Result<()> {
        put_bytes(&self.db, STATE_STORE, key, bytes).await
    }
}

// ---------------------------------------------------------------------------------------------
// Low-level IndexedDB byte KV helpers.
// ---------------------------------------------------------------------------------------------

async fn put_bytes(db: &IdbDatabase, store: &str, key: &str, bytes: &[u8]) -> Result<()> {
    let tx = db
        .transaction_with_str_and_mode(store, IdbTransactionMode::Readwrite)
        .map_err(js_err)?;
    let object_store = tx.object_store(store).map_err(js_err)?;
    let value: JsValue = Uint8Array::from(bytes).into();
    let req = object_store
        .put_with_key(&value, &JsValue::from_str(key))
        .map_err(js_err)?;
    await_request(&req).await.map_err(js_err)?;
    Ok(())
}

/// `Ok(None)` iff no record exists under `key` (IndexedDB's own `get()` resolves successfully with
/// `undefined` in that case — this is *not* a `Promise` rejection, hence not routed through
/// [`IndexedDbError::Backend`]). Any genuine backend failure (aborted transaction, …) is
/// [`IndexedDbError::Backend`].
async fn get_bytes(db: &IdbDatabase, store: &str, key: &str) -> Result<Option<Vec<u8>>> {
    let tx = db
        .transaction_with_str_and_mode(store, IdbTransactionMode::Readonly)
        .map_err(js_err)?;
    let object_store = tx.object_store(store).map_err(js_err)?;
    let req = object_store.get(&JsValue::from_str(key)).map_err(js_err)?;
    let value = await_request(&req).await.map_err(js_err)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let arr: Uint8Array = value.unchecked_into();
    Ok(Some(arr.to_vec()))
}

/// Bridges one `IDBRequest`'s `onsuccess`/`onerror` callback pair onto a single `.await`able point
/// via a one-shot channel — the same technique `transport.rs`'s `Signal` and `webcrypto.rs`'s
/// `JsFuture`-wrapped `crypto.subtle` calls both use for their own callback/Promise seams (see this
/// module's doc comment).
async fn await_request(req: &IdbRequest) -> core::result::Result<JsValue, JsValue> {
    let (tx, rx) = oneshot::channel::<core::result::Result<JsValue, JsValue>>();
    let tx = Rc::new(RefCell::new(Some(tx)));

    let tx_ok = tx.clone();
    let req_ok = req.clone();
    let on_success = Closure::<dyn FnMut()>::new(move || {
        if let Some(tx) = tx_ok.borrow_mut().take() {
            let result = req_ok.result().unwrap_or(JsValue::UNDEFINED);
            let _ = tx.send(Ok(result));
        }
    });
    req.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));

    let tx_err = tx.clone();
    let on_error = Closure::<dyn FnMut()>::new(move || {
        if let Some(tx) = tx_err.borrow_mut().take() {
            let _ = tx.send(Err(JsValue::from_str("IndexedDB request failed")));
        }
    });
    req.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    let outcome = rx.await.unwrap_or_else(|_| {
        Err(JsValue::from_str(
            "IndexedDB request dropped before completion",
        ))
    });
    // Both closures have already fired (or the request was dropped) by the time `rx.await`
    // resolves — safe to drop them now; see `ChanState`/`Session` in `transport.rs` for the same
    // "keep the Closure alive until its callback has definitely run" discipline.
    drop(on_success);
    drop(on_error);
    outcome
}

/// `js_sys::global().indexedDB` — works uniformly in a window, a worker, or a `wasm-bindgen-test`
/// harness (all expose `globalThis.indexedDB`), mirroring `webcrypto.rs`'s `subtle_crypto()`.
fn indexed_db_factory() -> Result<IdbFactory> {
    let global = js_sys::global();
    let idb = js_sys::Reflect::get(&global, &JsValue::from_str("indexedDB")).map_err(js_err)?;
    if idb.is_undefined() || idb.is_null() {
        return Err(IndexedDbError::Backend(
            "no `indexedDB` global in this JS context".into(),
        ));
    }
    Ok(idb.unchecked_into())
}

/// Coarse, non-leaking error mapping from a rejected `Promise`/thrown `JsValue` — mirrors
/// `transport.rs`'s `js_backend_err`/`webcrypto.rs`'s `js_err`.
fn js_err(e: JsValue) -> IndexedDbError {
    IndexedDbError::Backend(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const SEED: [u8; 32] = [11u8; 32];

    /// A fresh, uniquely-named database per test — `wasm-bindgen-test` runs every `#[wasm_bindgen_test]`
    /// in the same browser tab/origin, so a shared fixed name would let one test's writes leak into
    /// another's `get_sealed`/`get_state` reads.
    async fn fresh_db(tag: &str) -> IndexedDbStore {
        let mut name_bytes = [0u8; 8];
        getrandom::fill(&mut name_bytes).expect("getrandom");
        let name = format!("meridian-test-{tag}-{}", hex::encode(name_bytes));
        IndexedDbStore::open(&name).await.expect("open")
    }

    async fn fresh_secret_store() -> (WebCryptoSecretStore, KeyHandle) {
        let store = WebCryptoSecretStore::new();
        let handle = store.store("acct", &SEED).await.expect("store seed");
        (store, handle)
    }

    #[wasm_bindgen_test]
    async fn round_trips_every_bucket() {
        let db = fresh_db("round-trip").await;
        let (secret_store, handle) = fresh_secret_store().await;

        for bucket in Bucket::ALL {
            let payload = serde_json::json!({ "bucket": bucket.store_name(), "n": 42 });
            db.put_sealed(&secret_store, &handle, bucket, "k1", payload.clone())
                .await
                .expect("put_sealed");
            let got = db
                .get_sealed(&secret_store, &handle, bucket, "k1")
                .await
                .expect("get_sealed")
                .expect("record present");
            assert_eq!(
                got, payload,
                "round trip must be byte-identical for {bucket:?}"
            );
        }
    }

    #[wasm_bindgen_test]
    async fn missing_record_is_ok_none_not_an_error() {
        let db = fresh_db("missing").await;
        let (secret_store, handle) = fresh_secret_store().await;

        let got = db
            .get_sealed(&secret_store, &handle, Bucket::Contacts, "never-written")
            .await
            .expect("NotFound must not be an Err");
        assert!(got.is_none());
    }

    #[wasm_bindgen_test]
    async fn buckets_are_key_domain_separated() {
        // A key derived for Contacts must not open a record sealed for History, proving the
        // per-bucket `info` string (ADR 0026 binding condition 2) really domain-separates.
        let db = fresh_db("domain-sep").await;
        let (secret_store, handle) = fresh_secret_store().await;

        db.put_sealed(
            &secret_store,
            &handle,
            Bucket::Contacts,
            "k1",
            serde_json::json!({ "petname": "irrelevant" }),
        )
        .await
        .expect("put_sealed");

        // Manually seal-check: derive History's key and try to open the Contacts-sealed bytes with
        // it directly (bypassing `get_sealed`'s own bucket selection, which would derive the
        // correct Contacts key and always succeed).
        let sealed = get_bytes(&db.db, Bucket::Contacts.store_name(), "k1")
            .await
            .expect("get_bytes")
            .expect("present");
        let wrong_key = secret_store
            .derive_key(&handle, Bucket::History.key_info())
            .await
            .expect("derive_key");
        assert!(
            at_rest::open(&wrong_key, &sealed).is_err(),
            "History's key must not open a Contacts-sealed record"
        );
    }

    #[wasm_bindgen_test]
    async fn newer_than_understood_version_is_fail_closed() {
        let db = fresh_db("version-refusal").await;
        let (secret_store, handle) = fresh_secret_store().await;

        // Hand-seal an envelope claiming a version this build cannot possibly understand yet.
        let future_envelope = Envelope {
            v: SCHEMA_VERSION + 1,
            data: serde_json::json!({ "from": "the future" }),
        };
        let plaintext = serde_json::to_vec(&future_envelope).expect("serialize");
        let key = secret_store
            .derive_key(&handle, Bucket::Sessions.key_info())
            .await
            .expect("derive_key");
        let sealed = at_rest::seal(&key, &plaintext).expect("seal");
        put_bytes(&db.db, Bucket::Sessions.store_name(), "k1", &sealed)
            .await
            .expect("put_bytes");

        let err = db
            .get_sealed(&secret_store, &handle, Bucket::Sessions, "k1")
            .await
            .expect_err("a newer-than-understood version must be refused, not silently accepted");
        match err {
            IndexedDbError::UnsupportedVersion { found, supported } => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[wasm_bindgen_test]
    async fn corrupted_sealed_record_is_fatal_not_reinitialized() {
        let db = fresh_db("aead-failure").await;
        let (secret_store, handle) = fresh_secret_store().await;

        db.put_sealed(
            &secret_store,
            &handle,
            Bucket::Outbox,
            "k1",
            serde_json::json!({ "queued": true }),
        )
        .await
        .expect("put_sealed");

        // Flip one ciphertext byte (past the 24-byte nonce prefix) and write the corrupted bytes
        // straight back — simulates on-disk corruption/tampering, not a missing record.
        let mut sealed = get_bytes(&db.db, Bucket::Outbox.store_name(), "k1")
            .await
            .expect("get_bytes")
            .expect("present");
        assert!(
            sealed.len() > 24,
            "sealed blob must have nonce + ciphertext"
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        put_bytes(&db.db, Bucket::Outbox.store_name(), "k1", &sealed)
            .await
            .expect("put_bytes corrupted");

        let err = db
            .get_sealed(&secret_store, &handle, Bucket::Outbox, "k1")
            .await
            .expect_err(
                "a corrupted sealed record must surface a hard error, never silently \
                 reinitialize to empty",
            );
        assert!(
            matches!(err, IndexedDbError::SealedRecordCorrupt),
            "expected SealedRecordCorrupt (AEAD failure), got {err:?} — this must never be \
             conflated with NotFound"
        );
    }

    #[wasm_bindgen_test]
    async fn state_record_round_trips() {
        let db = fresh_db("state").await;
        let mut view = BTreeMap::new();
        view.insert("sidebar_width".to_string(), 24.0);
        let record = StateRecord {
            view,
            open_conversation_handle: Some("opaque-handle-abc123".to_string()),
        };
        db.put_state("ui", &record).await.expect("put_state");
        let got = db
            .get_state("ui")
            .await
            .expect("get_state")
            .expect("record present");
        assert_eq!(got, record);
    }
}
