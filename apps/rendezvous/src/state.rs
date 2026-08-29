//! Shared server state: config, storage, the live-connection registry, metrics, and rate limiters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::Message;
use rustls::ClientConfig;
use tokio::sync::mpsc;

use crate::auth::AdmissionPolicy;
use crate::config::{Config, DiscoveryMode};
use crate::federation;
use crate::metrics::Metrics;
use crate::ratelimit::RateLimiter;
use crate::store::{MailboxLocks, Store};
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
    /// Per-recipient locking for [`crate::store::mailbox_enqueue_with_quota`]'s check-then-write
    /// (task 9.1, review finding F1) — shared by BOTH the local route path
    /// (`ws::queue_to_mailbox`) and the federated route path (`federation::inbound::handle_fed_route`
    /// via its `FedRouteDeps`), so a local and a federated enqueue racing at the same recipient are
    /// serialized against each other too. See [`MailboxLocks`]'s own doc comment.
    pub mailbox_locks: MailboxLocks,
    /// TEST HOOK (task 1.32): byte-level buffers for the replay/reorder/drop/cross-delivery relay
    /// attacks. Compiled in only under the `test-tamper-hook` cargo feature — this field does not
    /// exist in a default/release build (F17).
    #[cfg(feature = "test-tamper-hook")]
    pub route_tamper: crate::route_tamper::RouteTamper,
    /// Federation runtime (task 2.7): resolved [`federation::Discovery`]/[`federation::FederationPolicy`]/
    /// [`federation::FederationLimits`] plus this server's own outbound TLS identity — what
    /// `federation::outbound::fetch_foreign_bundle` (server A's dial-out path) and
    /// `federation::inbound::serve_link` (server B's accept-loop dispatch) both read from. See
    /// [`FederationRuntime`]'s own doc comment for the disabled-by-default contract.
    pub federation: FederationRuntime,
    conn_seq: AtomicU64,
}

/// Owned (not borrowed) copy of the federation TLS material paths, so [`AppState`] can hold this
/// without a lifetime parameter. [`Self::as_paths`] builds the borrowed
/// `federation::FederationTlsPaths` that `federation::link::dial`/`FederationListener::bind`
/// actually take, on demand, at each call site.
#[derive(Clone, Debug, Default)]
pub struct FederationTlsOwned {
    pub cert_path: String,
    pub key_path: String,
    pub ca_bundle_path: String,
}

impl FederationTlsOwned {
    pub fn as_paths(&self) -> federation::FederationTlsPaths<'_> {
        federation::FederationTlsPaths {
            cert_path: &self.cert_path,
            key_path: &self.key_path,
            ca_bundle_path: &self.ca_bundle_path,
        }
    }
}

/// Federation runtime state, built once at startup from `config::Federation` (task 2.7 — tasks
/// 2.4/2.5/2.6 built the pieces this assembles, but left them unwired into any running server).
///
/// `discovery` is `None` whenever `config.federation.enabled` is `false` — the outbound fetch path
/// (`federation::outbound::fetch_foreign_bundle`) MUST check this and refuse (`fed_unreachable`)
/// BEFORE ever calling `Discovery::resolve`, matching `config::Federation`'s own fail-closed
/// contract that a disabled federation surface makes no DNS lookup and no dial, regardless of what
/// a client asks for.
pub struct FederationRuntime {
    pub own_domain: String,
    pub tls: FederationTlsOwned,
    /// Cached outbound mTLS `rustls::ClientConfig` (task 3.7, review finding F10). `link::dial`
    /// used to call `link::build_client_tls_config(paths)` itself, inline, on *every single*
    /// outbound dial — re-reading and re-parsing the CA bundle, cert chain, and private key from
    /// disk fresh each time, even though none of that material changes between calls in a running
    /// server. `rustls::ClientConfig` is designed to be built once and shared across many
    /// connections (hence the `Arc`), so this is built exactly once, here, at startup, and the same
    /// `Arc` is handed to every `dial` call for this server's lifetime.
    ///
    /// `None` under the identical condition as `discovery: None` (federation disabled) — built
    /// together, in the same `if config.federation.enabled` branch, in
    /// [`build_federation_runtime`]. Nothing dials out at all when federation is disabled, so there
    /// is nothing to cache.
    ///
    /// **Deliberate timing tradeoff (task 3.7's Risk note):** moving this load from "the first byte
    /// of every dial" to "server startup" changes *when* a rotated/absent/expired cert, key, or CA
    /// bundle on disk becomes visible as a failure. Before this change, a broken cert/key/CA-bundle
    /// only broke the very next dial attempt — each call independently re-read and re-failed, so
    /// the breakage stayed silent until (and unless) something actually tried to federate. After
    /// this change, it becomes a boot-time failure instead: `build_federation_runtime` panics
    /// (`unwrap_or_else`, mirroring `discovery`'s own construction just below this field and
    /// `main.rs`'s existing "an explicit misconfiguration is fatal at boot, never a silent
    /// downgrade" posture), loud and fail-closed, the moment the server starts. This is a
    /// deliberate side benefit, not an accidental regression: an operator who broke their
    /// federation cert on disk now finds out at server start, not silently on the first real
    /// cross-org message.
    pub client_tls: Option<Arc<ClientConfig>>,
    pub discovery: Option<Arc<dyn federation::Discovery>>,
    pub policy: federation::FederationPolicy,
    pub limits: federation::FederationLimits,
    /// Outbound dial/exchange timeout budget (task 3.3, review finding F3): read by
    /// `federation::outbound::dial_foreign`'s `link::dial` call and by `fetch_foreign_bundle`'s /
    /// `reachable_foreign`'s own per-exchange `send_frame`/`recv_frame` waits.
    pub timeouts: federation::FederationTimeouts,
}

/// Build the [`FederationRuntime`] this config describes. Fails closed and loudly (`panic!`,
/// mirroring `main.rs`'s existing "an explicit misconfiguration is fatal, never a silent
/// downgrade" posture — see `Config::load`'s doc comment) rather than silently degrading to
/// `discovery: None` when `enabled = true` but the discovery backend can't actually be built (a
/// missing/malformed `federation_map.toml`, or no usable system DNS resolver for SRV mode) — an
/// operator who turned federation on gets a clear boot-time error, not a server that silently
/// never federates. Same posture for `client_tls` (task 3.7): a rotated/absent/expired cert, key,
/// or CA bundle fails this call, not merely the first outbound dial — see
/// [`FederationRuntime::client_tls`]'s doc comment. When `enabled = false` this performs no I/O
/// and no DNS lookup at all.
fn build_federation_runtime(config: &Config) -> FederationRuntime {
    let tls = FederationTlsOwned {
        cert_path: config.federation.cert_path.clone(),
        key_path: config.federation.key_path.clone(),
        ca_bundle_path: config.federation.ca_bundle_path.clone(),
    };
    let (discovery, client_tls): (
        Option<Arc<dyn federation::Discovery>>,
        Option<Arc<ClientConfig>>,
    ) = if config.federation.enabled {
        let discovery = match config.federation.discovery {
            DiscoveryMode::Static => Arc::new(
                federation::StaticMap::load(&config.federation.map_path).unwrap_or_else(|e| {
                    panic!(
                        "federation: loading {:?}: {e} — refusing to boot with federation \
                         enabled but no usable discovery source",
                        config.federation.map_path
                    )
                }),
            ) as Arc<dyn federation::Discovery>,
            DiscoveryMode::Srv => Arc::new(federation::SrvDiscovery::new().unwrap_or_else(|e| {
                panic!(
                    "federation: constructing the SRV resolver: {e} — refusing to boot with \
                     federation enabled but no usable discovery source"
                )
            })) as Arc<dyn federation::Discovery>,
        };
        // Task 3.7 (F10): built once here, alongside `discovery` — same fail-closed-at-boot
        // posture, see `FederationRuntime::client_tls`'s doc comment for the timing tradeoff this
        // is a deliberate acceptance of.
        let client_tls =
            federation::link::build_client_tls_config(&tls.as_paths()).unwrap_or_else(|e| {
                panic!(
                    "federation: building the outbound TLS client config from cert_path={:?} \
                     key_path={:?} ca_bundle_path={:?}: {e} — refusing to boot with federation \
                     enabled but unusable TLS material",
                    tls.cert_path, tls.key_path, tls.ca_bundle_path
                )
            });
        (Some(discovery), Some(client_tls))
    } else {
        (None, None)
    };
    FederationRuntime {
        own_domain: config.server.domain.clone(),
        tls,
        client_tls,
        discovery,
        policy: config.federation.to_policy(),
        limits: config.federation.to_limits(),
        timeouts: config.federation.to_timeouts(),
    }
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
        let federation = build_federation_runtime(&config);
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
            mailbox_locks: MailboxLocks::default(),
            #[cfg(feature = "test-tamper-hook")]
            route_tamper: crate::route_tamper::RouteTamper::default(),
            federation,
            conn_seq: AtomicU64::new(1),
        })
    }

    /// A fresh per-connection id (for precise registry removal on disconnect).
    pub fn next_conn_id(&self) -> u64 {
        self.conn_seq.fetch_add(1, Ordering::Relaxed)
    }
}
