//! Shared test harness: PKI (test CA + leaf certs) + rendezvous server-boot helpers.
//!
//! Task 3.4 / review finding F18: this used to be ~40 lines of near-identical `make_ca`/
//! `make_leaf`/`mint_identity`/`write`/`base_config`/`spawn_c2s`/`spawn_federation`/
//! `write_federation_map`/`Acct` boilerplate, copy-pasted into `federation_mtls.rs`,
//! `federation_fetch.rs`, `federation_route.rs`, `federation_abuse.rs`,
//! `federation_outbound_policy.rs`, `federation_link_dos.rs`, and `federation_timeouts.rs`
//! independently (flagged as overdue debt by 2.7/2.8/2.9/2.12/2.15's own outcomes). One copy here
//! instead.
//!
//! **Must be `support/mod.rs`, not a bare `support.rs`**: Cargo treats a bare `tests/support.rs`
//! as its own top-level integration-test binary (it would have zero `#[test]`s and just be dead
//! weight); `tests/support/mod.rs`, brought in via `mod support;` from each real test file, is a
//! plain module instead.
//!
//! Dev-dependency only (`tempfile`, `rcgen`, `rustls`, `meridian-identity`, `meridian-signaling` —
//! all already this crate's own `[dev-dependencies]`) — nothing here is linked into the production
//! `meridian-rendezvous` binary. Not every test file in this crate uses every helper below: each
//! integration-test file compiles this module fresh as its own private `mod`, so per-file unused
//! warnings would otherwise fire for whichever helpers that particular file doesn't happen to call
//! — hence the blanket allow.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use meridian_identity::{generate_account, KeyHandle, MemorySecretStore};
use meridian_rendezvous::config::{
    Config, DiscoveryMode, Federation, FederationPolicyMode, Limits, Server, Turn,
};
use meridian_rendezvous::federation::inbound::{bind_federation, run_federation};
use meridian_rendezvous::federation::link::build_client_tls_config;
use meridian_rendezvous::federation::{Discovery, FederationTlsPaths};
use meridian_rendezvous::{serve, AppState, MemoryStore};
use meridian_signaling::{SignalError, SignalingClient};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ClientConfig;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// -- PKI test harness ---------------------------------------------------------------------------
// (mirrors the shape every federation_*.rs file in this crate used to redefine on its own)

/// A minted CA: its self-signed `rcgen::Certificate` (used as the `signed_by` issuer) and key.
pub struct TestCa {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

impl TestCa {
    /// Generate a new self-signed test CA with a generic common name.
    pub fn new() -> Self {
        Self::named("Meridian Test Federation CA")
    }

    /// Same as [`TestCa::new`], with an explicit common name — several tests mint more than one CA
    /// in the same process and want a readable name for each in failure output (e.g. "... (legit)"
    /// / "... (WebPKI-mode fixture)").
    pub fn named(common_name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().expect("generate CA key");
        let cert = params.self_signed(&key).expect("self-sign CA cert");
        TestCa { cert, key }
    }

    /// Mint a leaf cert for `domain` (used as both the SAN dNSName and the CN), signed by this CA,
    /// writing cert/key/CA-bundle PEMs under `dir`. `domain` also serves as the filename tag —
    /// every caller in this crate mints at most one identity per domain per directory, so this
    /// never collides.
    pub fn issue(&self, dir: &Path, domain: &str) -> Identity {
        self.issue_multi_san(dir, domain, &[domain])
    }

    /// Mint a leaf cert with MULTIPLE SAN `dNSName` entries (`domains`, in the given order —
    /// callers that care about SAN order, e.g. task 3.6's reordering fixtures, control it here),
    /// signed by this CA, writing cert/key/CA-bundle PEMs under `dir` tagged with `tag` (kept
    /// separate from `domains` since a multi-SAN cert has no one obvious domain to name files
    /// after, and two certs with the same SAN VALUES in a different order — task 3.6's
    /// SAN-reordering-across-renewal fixture — still need distinct filenames). The first entry in
    /// `domains` is also used as the subject CN, mirroring [`Self::issue`]. Task 3.6 (review
    /// finding F9): the shared multi-SAN fixture every test in this crate that needs one should
    /// use, rather than hand-rolling `rcgen::CertificateParams` locally.
    pub fn issue_multi_san(&self, dir: &Path, tag: &str, domains: &[&str]) -> Identity {
        assert!(
            !domains.is_empty(),
            "issue_multi_san requires at least one SAN"
        );
        let dns: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        let mut params = CertificateParams::new(dns).expect("SANs must be valid DNS names");
        params
            .distinguished_name
            .push(DnType::CommonName, domains[0]);
        let key = KeyPair::generate().expect("generate leaf key");
        let leaf_cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("sign leaf cert");
        Identity {
            cert_path: write(dir, &format!("{tag}.crt.pem"), &leaf_cert.pem()),
            key_path: write(dir, &format!("{tag}.key.pem"), &key.serialize_pem()),
            ca_bundle_path: write(dir, &format!("{tag}.ca.pem"), &self.cert.pem()),
        }
    }
}

pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// A minted identity's cert+key PEM files, written under some `dir`, plus the CA bundle PEM it was
/// signed under (also written under `dir`) — everything [`FederationTlsPaths`] needs.
pub struct Identity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_bundle_path: PathBuf,
}

impl Identity {
    pub fn cert_path_str(&self) -> &str {
        self.cert_path.to_str().unwrap()
    }
    pub fn key_path_str(&self) -> &str {
        self.key_path.to_str().unwrap()
    }
    pub fn ca_bundle_path_str(&self) -> &str {
        self.ca_bundle_path.to_str().unwrap()
    }

    pub fn paths(&self) -> FederationTlsPaths<'_> {
        FederationTlsPaths {
            cert_path: self.cert_path_str(),
            key_path: self.key_path_str(),
            ca_bundle_path: self.ca_bundle_path_str(),
        }
    }

    /// Same identity, but as a WebPKI-mode path set (empty `ca_bundle_path` — trust the OS/system
    /// store, which WebPKI-mode tests point at this identity's CA via `SSL_CERT_FILE`).
    pub fn webpki_paths(&self) -> FederationTlsPaths<'_> {
        FederationTlsPaths {
            cert_path: self.cert_path_str(),
            key_path: self.key_path_str(),
            ca_bundle_path: "",
        }
    }

    /// Build the outbound `rustls::ClientConfig` [`federation::link::dial`] now takes directly
    /// (task 3.7: `dial` no longer builds this itself from paths — see `FederationRuntime::client_tls`'s
    /// doc comment in production code). A thin convenience over `build_client_tls_config(&self.paths())`
    /// so per-test call sites don't each repeat that call.
    pub fn client_tls(&self) -> Arc<ClientConfig> {
        build_client_tls_config(&self.paths()).expect("valid test identity builds a client config")
    }

    /// Same as [`Self::client_tls`], but WebPKI-mode ([`Self::webpki_paths`]).
    pub fn webpki_client_tls(&self) -> Arc<ClientConfig> {
        build_client_tls_config(&self.webpki_paths())
            .expect("valid test identity builds a client config")
    }
}

// -- Server-boot harness -------------------------------------------------------------------------

/// A `Config` with `domain`, an ephemeral c2s bind address, and federation left at its fail-closed
/// default (disabled).
pub fn base_config(domain: &str) -> Config {
    config_with_federation(domain, Federation::default())
}

/// Same as [`base_config`], with an explicit `federation` block.
pub fn config_with_federation(domain: &str, federation: Federation) -> Config {
    Config {
        server: Server {
            domain: domain.to_string(),
            bind: "127.0.0.1:0".to_string(),
            ..Server::default()
        },
        limits: Limits::default(),
        turn: Turn::default(),
        federation,
    }
}

/// Spawn `state`'s c2s WS listener and return its `ws://` URL.
pub async fn spawn_c2s(state: Arc<AppState>) -> String {
    spawn_c2s_handle(state).await.0
}

/// Same as [`spawn_c2s`], also returning the listener task's [`JoinHandle`] — needed by tests that
/// must later kill the server outright (abort the task), not merely stop using it.
pub async fn spawn_c2s_handle(state: Arc<AppState>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = serve(state, listener).await;
    });
    (format!("ws://{addr}"), handle)
}

/// Bind `state`'s s2s federation listener and start serving it. Returns the bound address.
pub async fn spawn_federation(state: Arc<AppState>) -> SocketAddr {
    spawn_federation_handle(state).await.0
}

/// Same as [`spawn_federation`], also returning the listener task's [`JoinHandle`].
pub async fn spawn_federation_handle(state: Arc<AppState>) -> (SocketAddr, JoinHandle<()>) {
    let listener = bind_federation(&state).await.expect("bind s2s listener");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        run_federation(listener, state).await;
    });
    (addr, handle)
}

/// Build a `federation_map.toml` (private-CA mode, task 2.5's schema): one `[[partner]]` entry per
/// `(domain, endpoint, pinned_identity)` tuple.
pub fn write_federation_map(dir: &Path, entries: &[(&str, SocketAddr, &str)]) -> PathBuf {
    let mut toml = String::new();
    for (domain, addr, pin) in entries {
        toml.push_str(&format!(
            "[[partner]]\ndomain = \"{domain}\"\nendpoint = \"{addr}\"\npinned_identity = \"{pin}\"\n\n"
        ));
    }
    write(dir, "federation_map.toml", &toml)
}

/// Install `discovery` into a freshly-built (not yet cloned/spawned) [`AppState`], via
/// `Arc::get_mut` — the only way to reach `FederationRuntime::discovery` with a test-controlled
/// [`Discovery`] impl, since [`AppState::new`] always builds a config-driven one internally. Must
/// be called before the returned `Arc` is cloned anywhere (no live listener spawned on it yet).
/// Originally local to `federation_outbound_policy.rs` (task 3.1); moved here (task 3.7, review
/// follow-up) once `federation_route.rs`'s SRV-failover test needed the same seam to inject a
/// multi-`Endpoint`, call-observing `Discovery` stand-in — `federation_outbound_policy.rs` now
/// imports this copy instead of keeping its own.
pub fn install_discovery(state: &mut Arc<AppState>, discovery: Arc<dyn Discovery>) {
    Arc::get_mut(state)
        .expect("AppState must still be uniquely owned (not yet cloned/spawned)")
        .federation
        .discovery = Some(discovery);
}

// -- Signaling-client harness --------------------------------------------------------------------

pub struct Acct {
    pub store: MemorySecretStore,
    pub pubkey: [u8; 32],
    pub handle: KeyHandle,
}

pub fn new_acct(hint: &str) -> Acct {
    let store = MemorySecretStore::new();
    let account = generate_account(&store, hint).unwrap();
    Acct {
        pubkey: *account.public_key().as_bytes(),
        handle: account.handle().clone(),
        store,
    }
}

impl Acct {
    pub async fn connect(&self, url: &str) -> Result<SignalingClient, SignalError> {
        SignalingClient::connect(url, &self.store, &self.handle, self.pubkey, None, 1).await
    }
}

// -- Two-org federation harness ------------------------------------------------------------------
// The "org A dials out to org B" shape `federation_fetch.rs`/`federation_route.rs`/
// `federation_abuse.rs`/`federation_outbound_policy.rs` each used, independently, before this
// harness existed.

/// Options for [`boot_federated_pair`]. Defaults reproduce the shape those files used before this
/// harness existed: A's own outbound policy `open` (most of those files test B's behavior, not A's
/// own outbound admission — that's `federation_outbound_policy.rs`'s job), B's per-origin rate
/// limits at their `Federation::default()` values (fetch/route/account/reachability =
/// 300/600/30/600 per minute — reachability must stay `>=` route, task 3.5's throughput-coupling
/// correction), no allowlist on either side.
pub struct FederatedPairOpts {
    pub a_domain: String,
    pub b_domain: String,
    pub a_policy: FederationPolicyMode,
    pub b_policy: FederationPolicyMode,
    pub a_allowlist: Vec<String>,
    pub b_allowlist: Vec<String>,
    pub b_fed_fetch_per_origin_per_min: u32,
    pub b_fed_route_per_origin_per_min: u32,
    pub b_fed_per_origin_account_per_min: u32,
    /// Task 3.5 follow-up (review finding F4, blocking): `fed_reachability`'s own dedicated
    /// per-origin budget, independent of the three above.
    pub b_fed_reachability_per_origin_per_min: u32,
    pub b_allow_test_tamper: bool,
    /// Whether to also spawn B's c2s listener (and include its URL in the returned pair). Several
    /// tests only ever reach B through A's federation link and never need a direct client
    /// connection to B at all.
    pub spawn_b_c2s: bool,
}

impl Default for FederatedPairOpts {
    fn default() -> Self {
        Self {
            a_domain: "org-a.test".to_string(),
            b_domain: "org-b.test".to_string(),
            a_policy: FederationPolicyMode::Open,
            b_policy: FederationPolicyMode::Open,
            a_allowlist: Vec::new(),
            b_allowlist: Vec::new(),
            b_fed_fetch_per_origin_per_min: 300,
            b_fed_route_per_origin_per_min: 600,
            b_fed_per_origin_account_per_min: 30,
            // Task 3.5 correction: must stay >= b_fed_route_per_origin_per_min — route_foreign's
            // reachability pre-check spends one reachability unit per real routed message, so a
            // reachability budget below route's would silently cap real throughput below the
            // route budget (`Federation::validate`'s cross-field check enforces this in
            // production; this test-only struct bypasses `validate`, so it must match by hand).
            b_fed_reachability_per_origin_per_min: 600,
            b_allow_test_tamper: false,
            spawn_b_c2s: true,
        }
    }
}

/// Two real, in-process `meridian-rendezvous` servers connected over a real s2s mTLS link: org A
/// dials out to org B (tasks 2.4/2.5/2.7's harness shape). Owns the tempdir + CA (kept alive for
/// the caller's lifetime) so the cert/map files on disk stay valid for the whole test.
pub struct FederatedPair {
    pub dir: tempfile::TempDir,
    pub ca: TestCa,
    pub a_state: Arc<AppState>,
    pub b_state: Arc<AppState>,
    pub a_c2s_url: String,
    pub b_c2s_url: Option<String>,
    pub b_fed_addr: SocketAddr,
}

pub async fn boot_federated_pair(opts: FederatedPairOpts) -> FederatedPair {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();

    let b_id = ca.issue(dir.path(), &opts.b_domain);
    let b_empty_map = write(dir.path(), "b-federation_map.toml", "");
    let b_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: b_id.cert_path_str().to_string(),
        key_path: b_id.key_path_str().to_string(),
        ca_bundle_path: b_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: b_empty_map.to_str().unwrap().to_string(),
        policy: opts.b_policy,
        allowlist: opts.b_allowlist,
        fed_fetch_per_origin_per_min: opts.b_fed_fetch_per_origin_per_min,
        fed_route_per_origin_per_min: opts.b_fed_route_per_origin_per_min,
        fed_per_origin_account_per_min: opts.b_fed_per_origin_account_per_min,
        fed_reachability_per_origin_per_min: opts.b_fed_reachability_per_origin_per_min,
        ..Federation::default()
    };
    let mut b_config = base_config(&opts.b_domain);
    b_config.federation = b_federation;
    b_config.server.allow_test_tamper = opts.b_allow_test_tamper;
    let b_store = Arc::new(MemoryStore::new());
    let b_state = AppState::new(b_config, b_store);
    let b_fed_addr = spawn_federation(b_state.clone()).await;
    let b_c2s_url = if opts.spawn_b_c2s {
        Some(spawn_c2s(b_state.clone()).await)
    } else {
        None
    };

    let a_id = ca.issue(dir.path(), &opts.a_domain);
    let a_map = write_federation_map(dir.path(), &[(&opts.b_domain, b_fed_addr, &opts.b_domain)]);
    let a_federation = Federation {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        cert_path: a_id.cert_path_str().to_string(),
        key_path: a_id.key_path_str().to_string(),
        ca_bundle_path: a_id.ca_bundle_path_str().to_string(),
        discovery: DiscoveryMode::Static,
        map_path: a_map.to_str().unwrap().to_string(),
        policy: opts.a_policy,
        allowlist: opts.a_allowlist,
        ..Federation::default()
    };
    let mut a_config = base_config(&opts.a_domain);
    a_config.federation = a_federation;
    let a_store = Arc::new(MemoryStore::new());
    let a_state = AppState::new(a_config, a_store);
    let a_c2s_url = spawn_c2s(a_state.clone()).await;

    FederatedPair {
        dir,
        ca,
        a_state,
        b_state,
        a_c2s_url,
        b_c2s_url,
        b_fed_addr,
    }
}
