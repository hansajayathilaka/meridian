//! Server-side storage: accounts + their published prekey bundles.
//!
//! What an admin with this store learns (threat A7) is bounded to the [data model](../../../docs/architecture/data-model.md):
//! which pubkeys registered and their PUBLIC prekeys. No contact graph, no content — bundles are
//! public key material by construction.
//!
//! Storage is a trait so the in-memory default (tests, MVP) and a persistent SQLite/sqlx backend
//! (the `sqlite` feature, stack.md §3) are interchangeable. Postgres is a later flag.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage backend error: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The persistence seam. All methods are keyed by the **full** account key — there is no
/// prefix/range lookup, by design (anti-enumeration §3.5).
#[async_trait]
pub trait Store: Send + Sync {
    /// Idempotently record an account (created on first auth). Updates `max_bundle_v`.
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()>;

    /// Store (replace) an account's prekey bundle.
    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()>;

    /// Fetch a bundle by exact account key, or `None` if absent.
    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>>;

    /// Total one-time prekeys currently held across all accounts (the `prekey_pool_depth` gauge).
    async fn total_otks(&self) -> StoreResult<u64>;
}

#[derive(Default)]
struct Account {
    #[allow(dead_code)]
    admission: String,
    #[allow(dead_code)]
    max_bundle_v: u16,
    bundle: Option<PrekeyBundle>,
}

/// In-memory store — the default for the MVP and all tests. Loses data on restart (clients
/// republish bundles on reconnect; ADR-8 "losing this DB costs reachability, never identity").
#[derive(Default)]
pub struct MemoryStore {
    accounts: Mutex<HashMap<[u8; 32], Account>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        let entry = accounts.entry(account_pub).or_default();
        entry.admission = admission.to_string();
        entry.max_bundle_v = max_bundle_v;
        Ok(())
    }

    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        let entry = accounts.entry(bundle.account_pub).or_default();
        entry.bundle = Some(bundle);
        Ok(())
    }

    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.get(target).and_then(|a| a.bundle.clone()))
    }

    async fn total_otks(&self) -> StoreResult<u64> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .filter_map(|a| a.bundle.as_ref())
            .map(|b| b.otks.len() as u64)
            .sum())
    }
}

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;
