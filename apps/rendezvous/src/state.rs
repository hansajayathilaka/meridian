//! Shared server state: config, storage, the live-connection registry, metrics, and rate limiters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::Message;
use tokio::sync::mpsc;

use crate::auth::AdmissionPolicy;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::store::Store;
use crate::turn::TurnConfig;

/// The live connections for one account key: `(conn_id, outbound sender)` per socket.
type ConnList = Vec<(u64, mpsc::Sender<Message>)>;

/// Registry of currently-connected clients, keyed by account key. A key may have several live
/// connections (multi-device); a routed envelope is pushed to all of them.
#[derive(Default)]
pub struct Registry {
    conns: Mutex<HashMap<[u8; 32], ConnList>>,
}

impl Registry {
    pub fn add(&self, key: [u8; 32], conn_id: u64, tx: mpsc::Sender<Message>) {
        self.conns
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .push((conn_id, tx));
    }

    pub fn remove(&self, key: &[u8; 32], conn_id: u64) {
        let mut map = self.conns.lock().unwrap();
        if let Some(list) = map.get_mut(key) {
            list.retain(|(id, _)| *id != conn_id);
            if list.is_empty() {
                map.remove(key);
            }
        }
    }

    /// Whether a key currently has any live connection.
    pub fn is_connected(&self, key: &[u8; 32]) -> bool {
        self.conns
            .lock()
            .unwrap()
            .get(key)
            .is_some_and(|l| !l.is_empty())
    }

    /// Push `msg` to every live connection for `key`. Returns true if at least one accepted it.
    pub fn send_to(&self, key: &[u8; 32], msg: Message) -> bool {
        let senders: Vec<mpsc::Sender<Message>> = {
            let map = self.conns.lock().unwrap();
            match map.get(key) {
                Some(list) => list.iter().map(|(_, tx)| tx.clone()).collect(),
                None => return false,
            }
        };
        let mut delivered = false;
        for tx in senders {
            if tx.try_send(msg.clone()).is_ok() {
                delivered = true;
            }
        }
        delivered
    }
}

/// Process-wide state shared by every connection handler (behind an `Arc`).
pub struct AppState {
    pub config: Config,
    pub store: Arc<dyn Store>,
    pub admission: Box<dyn AdmissionPolicy>,
    pub metrics: Arc<Metrics>,
    pub registry: Registry,
    pub auth_limiter: RateLimiter,
    pub fetch_limiter: RateLimiter,
    pub route_limiter: RateLimiter,
    pub turn_limiter: RateLimiter,
    /// Resolved TURN minting config (empty secret ⇒ minting disabled).
    pub turn: TurnConfig,
    conn_seq: AtomicU64,
}

impl AppState {
    pub fn new(config: Config, store: Arc<dyn Store>) -> Arc<Self> {
        let admission = crate::auth::admission_from(
            config.server.admission,
            config.server.invite_tokens.clone(),
        );
        let auth_limiter = RateLimiter::per_minute(config.limits.auth_per_ip_per_min);
        let fetch_limiter = RateLimiter::per_minute(config.limits.fetch_per_account_per_min);
        let route_limiter = RateLimiter::per_minute(config.limits.route_per_account_per_min);
        let turn_limiter = RateLimiter::per_minute(config.limits.turn_per_account_per_min);
        let turn = config.turn.to_turn_config();
        Arc::new(Self {
            config,
            store,
            admission,
            metrics: Arc::new(Metrics::new()),
            registry: Registry::default(),
            auth_limiter,
            fetch_limiter,
            route_limiter,
            turn_limiter,
            turn,
            conn_seq: AtomicU64::new(1),
        })
    }

    /// A fresh per-connection id (for precise registry removal on disconnect).
    pub fn next_conn_id(&self) -> u64 {
        self.conn_seq.fetch_add(1, Ordering::Relaxed)
    }
}
