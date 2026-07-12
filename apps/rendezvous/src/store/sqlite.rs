//! SQLite persistence via sqlx (enabled by the `sqlite` feature; stack.md §3).
//!
//! The runtime query API is used (no compile-time `query!` macros) so the crate builds without a
//! live `DATABASE_URL`. Bundles are stored as one CBOR blob keyed by account key — all public key
//! material; normalizing into the per-column data-model schema is a later refinement.
//! TODO: confirm normalized columns + Postgres backend in T06/T07.

use async_trait::async_trait;
use meridian_proto::PrekeyBundle;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use super::{Store, StoreError, StoreResult};

fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// A persistent store backed by SQLite. `url` is a sqlx SQLite URL, e.g. `sqlite://rdv.db` or
/// `sqlite::memory:`.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> StoreResult<Self> {
        let opts: SqliteConnectOptions = url.parse().map_err(backend)?;
        let opts = opts.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(backend)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS accounts (\
                account_pub BLOB PRIMARY KEY, admission TEXT NOT NULL, \
                max_bundle_v INTEGER NOT NULL, created_at INTEGER NOT NULL)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS bundles (\
                account_pub BLOB PRIMARY KEY, bundle BLOB NOT NULL, otk_count INTEGER NOT NULL)",
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn register_account(
        &self,
        account_pub: [u8; 32],
        admission: &str,
        max_bundle_v: u16,
    ) -> StoreResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        sqlx::query(
            "INSERT INTO accounts (account_pub, admission, max_bundle_v, created_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(account_pub) DO UPDATE SET admission = ?2, max_bundle_v = ?3",
        )
        .bind(account_pub.as_slice())
        .bind(admission)
        .bind(max_bundle_v as i64)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn put_bundle(&self, bundle: PrekeyBundle) -> StoreResult<()> {
        let blob = meridian_proto::encode(&bundle).map_err(backend)?;
        let otk_count = bundle.otks.len() as i64;
        sqlx::query(
            "INSERT INTO bundles (account_pub, bundle, otk_count) VALUES (?1, ?2, ?3) \
             ON CONFLICT(account_pub) DO UPDATE SET bundle = ?2, otk_count = ?3",
        )
        .bind(bundle.account_pub.as_slice())
        .bind(blob)
        .bind(otk_count)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get_bundle(&self, target: &[u8; 32]) -> StoreResult<Option<PrekeyBundle>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT bundle FROM bundles WHERE account_pub = ?1")
                .bind(target.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(backend)?;
        match row {
            Some((blob,)) => Ok(Some(meridian_proto::decode(&blob).map_err(backend)?)),
            None => Ok(None),
        }
    }

    async fn total_otks(&self) -> StoreResult<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COALESCE(SUM(otk_count), 0) FROM bundles")
            .fetch_one(&self.pool)
            .await
            .map_err(backend)?;
        Ok(row.0.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_proto::BUNDLE_VERSION;

    fn bundle(key: [u8; 32], otks: usize) -> PrekeyBundle {
        PrekeyBundle {
            v: BUNDLE_VERSION,
            account_pub: key,
            spk: [1u8; 32],
            spk_sig: [2u8; 64],
            otks: vec![[3u8; 32]; otks],
            otk_sigs: vec![[4u8; 64]; otks],
            device_record: None,
        }
    }

    #[tokio::test]
    async fn sqlite_store_roundtrips() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        let key = [9u8; 32];
        store.register_account(key, "open", 1).await.unwrap();
        store.put_bundle(bundle(key, 7)).await.unwrap();

        let got = store.get_bundle(&key).await.unwrap().unwrap();
        assert_eq!(got.account_pub, key);
        assert_eq!(got.otk_count(), 7);
        assert_eq!(store.total_otks().await.unwrap(), 7);

        // Exact-key only: a near-miss key is absent.
        let mut miss = key;
        miss[0] ^= 1;
        assert!(store.get_bundle(&miss).await.unwrap().is_none());

        // Republish replaces (and updates the pool depth).
        store.put_bundle(bundle(key, 3)).await.unwrap();
        assert_eq!(store.total_otks().await.unwrap(), 3);
    }
}
