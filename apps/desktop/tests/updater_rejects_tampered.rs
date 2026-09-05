//! Task 12.16 / ADR 0027 acceptance test: proves `meridian-desktop`'s wired-up
//! `tauri-plugin-updater` rejects an update whose signature is tampered or missing, and (for
//! completeness) accepts one correctly signed with the matching public key.
//!
//! # Security note — this file uses a LOCAL, TEST-ONLY keypair, never a production key
//!
//! [`TEST_ONLY_PRIVATE_KEY_B64`]/[`TEST_ONLY_PUBLIC_KEY_B64`] below are an Ed25519/minisign-style
//! keypair generated once, locally, in a throwaway sandbox purely to drive this test
//! (`cargo tauri signer generate`). It is:
//! - **not** the real production `TAURI_SIGNING_PRIVATE_KEY` — that key exists only as a GitHub
//!   Actions repo secret (see `.github/workflows/release-desktop.yml`), was never generated in this
//!   change, and a human operator with real repo-admin access must generate and set it for real
//!   before this pipeline can sign an actual release (see `docs/operations/release-binaries.md`).
//! - **not** referenced anywhere outside this test file — `apps/desktop/tauri.conf.json`'s bundled
//!   `plugins.updater.pubkey` is a distinct placeholder (`TODO: confirm`), deliberately not this
//!   test key, so nobody mistakes one for the other.
//! - never printed/logged by anything this test exercises beyond the assertions below (this test
//!   process's own stdout on failure), matching the same "don't make key material look like it's
//!   being handled carelessly" discipline the real CI signing step follows.
//!
//! # What this drives
//!
//! This test registers the real `tauri_plugin_updater::Builder` plugin on a mock Tauri app
//! ([`tauri::test::mock_app`]'s machinery) configured with the test public key above, spins up a
//! local HTTP server (`axum`) serving a static-JSON update manifest (the same shape
//! `release-desktop.yml` publishes as `latest.json`) plus an artifact, and calls the *exact*
//! production code path — [`tauri_plugin_updater::UpdaterExt::updater`]'s `.check()` then
//! `Update::download()` — asserting:
//! 1. a correctly-signed artifact is accepted (positive control — proves the harness itself is
//!    wired correctly, not just that everything fails);
//! 2. a tampered signature is rejected;
//! 3. a missing/empty signature (standing in for a missing `.sig` sidecar — the manifest's
//!    `signature` field is where a `.sig` file's content ends up, per `tauri signer sign`'s own
//!    output) is rejected.

use base64::Engine;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Base64-encoded minisign public-key box, as produced by `cargo tauri signer generate`'s
/// `<name>.pub` output file. TEST-ONLY — see the module doc above.
const TEST_ONLY_PUBLIC_KEY_B64: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDc1NTQ3QjJBNkRFNzFFMTgKUldRWUh1ZHRLbnRVZFo3Mi92MGtZanRjYWlUZ2RLelhLQmhjSk9KVmdlZ053WVBJY2FxUmdtM3cK";

/// Base64-encoded, unencrypted (empty-password) minisign secret-key box, as produced by
/// `cargo tauri signer generate`'s `<name>.key` output file. TEST-ONLY — see the module doc above.
/// Generated with `--ci` (skips the interactive password prompt) purely so this test is
/// deterministic and self-contained; a real production key is never generated unencrypted, and
/// never lives in source at all (it is a CI-only secret).
const TEST_ONLY_PRIVATE_KEY_B64: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHJzaWduIGVuY3J5cHRlZCBzZWNyZXQga2V5ClJXUlRZMEl5Z0JkYncrc2U3MkhJSGtGc1lFcFdCTTNYOEJ4U0JUaXNXMWxpOTU1bkRYQUFBQkFBQUFBQUFBQUFBQUlBQUFBQU5wZ1AyR05HUW96Mm1lQXdmMStubkpaZ1BTTWxoU2g0ZUZhcEJoMG44ZnIwVU5ZdGN1SVZqTWNYU1FJcXpyZ09hdGVFejBqMGpRMjk1WGVZRUYrK1FqaDlkOGMyY2tubmJwelNVWDE5aHJ4NFRDcjNPeXUrZkNZa0ZQRWcxVmNGK01PUklmS1FQY2M9Cg==";

/// Decodes [`TEST_ONLY_PRIVATE_KEY_B64`] into a usable `minisign::SecretKey`, mirroring exactly
/// what `tauri-cli`'s own `secret_key()` helper does with `TAURI_SIGNING_PRIVATE_KEY` in the real
/// pipeline (base64-decode the file/env content, then parse the decoded minisign secret-key box).
fn load_test_secret_key() -> minisign::SecretKey {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(TEST_ONLY_PRIVATE_KEY_B64)
        .expect("test private key is valid base64");
    let decoded = String::from_utf8(decoded).expect("test private key decodes to utf8");
    let sk_box =
        minisign::SecretKeyBox::from_string(&decoded).expect("test private key box parses");
    sk_box
        .into_secret_key(Some(String::new()))
        .expect("test private key has no real password")
}

/// Signs `data`, returning the exact string a `.sig` sidecar file / a static-JSON manifest's
/// `signature` field holds (base64 of the minisign signature box) — the same encoding
/// `tauri-cli`'s `sign_file` produces and `tauri-plugin-updater`'s `verify_signature` expects.
fn sign(sk: &minisign::SecretKey, data: &[u8]) -> String {
    let sig_box = minisign::sign(
        None,
        sk,
        data,
        Some("test trusted comment — not a real release"),
        Some("test untrusted comment — not a real release"),
    )
    .expect("signing test fixture bytes never fails");
    base64::engine::general_purpose::STANDARD.encode(sig_box.to_string())
}

/// The `{os}-{arch}` key `tauri-plugin-updater`'s default target resolution looks up in a
/// static-JSON manifest's `platforms` map (see `Updater::get_urls` in the plugin's own source —
/// `format!("{os}-{arch}")`, where both come from `std::env::consts` on every platform this repo
/// builds for).
fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Spins up a local, loopback-only HTTP server serving `/latest.json` (the update manifest) and
/// `/artifact.bin` (the "artifact" bytes), returning its base URL. No TLS — the updater plugin
/// only requires `https://` endpoints in release builds; `cfg(debug_assertions)` (true for `cargo
/// test`) relaxes that to a warning, exactly like `apps/desktop`'s own dev-time `wss://`
/// relaxation elsewhere in this workspace.
async fn spawn_manifest_server(
    manifest: Arc<Mutex<serde_json::Value>>,
    artifact: Vec<u8>,
) -> std::net::SocketAddr {
    let manifest_for_route = manifest.clone();
    let router = axum::Router::new()
        .route(
            "/latest.json",
            axum::routing::get(move || {
                let manifest = manifest_for_route.clone();
                async move { axum::Json(manifest.lock().unwrap().clone()) }
            }),
        )
        .route(
            "/artifact.bin",
            axum::routing::get(move || {
                let artifact = artifact.clone();
                async move { artifact }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener has a local addr");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("mock update server");
    });
    addr
}

/// Builds a mock Tauri app with the real `tauri_plugin_updater` plugin registered and configured
/// with `pubkey`/`endpoint` — the same plugin registration `apps/desktop/src/main.rs` performs,
/// just against `tauri::test::MockRuntime` instead of a real window/WebView, and with the plugin's
/// config injected directly (`tauri::test::mock_context` ships an empty `plugins` map by default;
/// a real app gets this from `tauri.conf.json`'s `plugins.updater` section instead).
fn build_mock_app(pubkey: &str, endpoint: url::Url) -> tauri::App<tauri::test::MockRuntime> {
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().plugins.0.insert(
        "updater".to_string(),
        json!({
            "pubkey": pubkey,
            "endpoints": [endpoint.to_string()],
        }),
    );
    tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .expect("mock app with the updater plugin builds")
}

fn base_manifest(key: &str, signature: &str) -> serde_json::Value {
    json!({
        "version": "9.9.9",
        "notes": "test fixture — not a real release",
        "pub_date": "2020-01-01T00:00:00Z",
        "platforms": {
            key: { "signature": signature, "url": "placeholder — patched once the server is listening" }
        }
    })
}

/// Runs `Updater::check()` then `Update::download()` against a manifest whose `signature` field is
/// `signature`, returning the `download()` result — `Ok` means the update was accepted and applied,
/// `Err` means the updater rejected it (wrong/missing/tampered signature, or any other verification
/// failure) before ever handing artifact bytes back to a caller.
async fn check_and_download(
    signature: &str,
    pubkey: &str,
    artifact: &[u8],
) -> tauri_plugin_updater::Result<Vec<u8>> {
    use tauri_plugin_updater::UpdaterExt;

    let key = platform_key();
    let manifest = Arc::new(Mutex::new(base_manifest(&key, signature)));

    let addr = spawn_manifest_server(manifest.clone(), artifact.to_vec()).await;
    let base = format!("http://{addr}");
    {
        let mut m = manifest.lock().unwrap();
        m["platforms"][&key]["url"] = serde_json::Value::String(format!("{base}/artifact.bin"));
    }

    let endpoint: url::Url = format!("{base}/latest.json")
        .parse()
        .expect("mock server URL parses");
    let app = build_mock_app(pubkey, endpoint);

    let updater = app
        .handle()
        .updater()
        .expect("updater builds from mock config");
    let update = updater
        .check()
        .await
        .expect("check() itself succeeds — the manifest is well-formed JSON")
        .expect("a newer version is always found (9.9.9 > mock app's 0.1.0)");

    update.download(|_chunk_len, _total| {}, || {}).await
}

/// Positive control: a correctly-signed artifact, verified with the matching public key, is
/// accepted — proves the harness (mock app, plugin wiring, local server, manifest shape) is
/// actually exercising real verification, not vacuously passing because everything errors.
#[tokio::test]
async fn accepts_correctly_signed_update() {
    let sk = load_test_secret_key();
    let artifact = b"totally-fake-desktop-artifact-bytes-for-this-test".to_vec();
    let signature = sign(&sk, &artifact);

    let result = check_and_download(&signature, TEST_ONLY_PUBLIC_KEY_B64, &artifact).await;

    match result {
        Ok(bytes) => assert_eq!(
            bytes, artifact,
            "downloaded bytes must match the served artifact"
        ),
        Err(err) => panic!("a correctly-signed update must be accepted, got error: {err}"),
    }
}

/// The core acceptance assertion: a tampered signature (one byte flipped in the base64 blob) is
/// rejected by the updater's own verification — the app never treats the (in this case identical,
/// untampered) artifact bytes as trusted just because they were downloaded successfully.
#[tokio::test]
async fn rejects_tampered_signature() {
    let sk = load_test_secret_key();
    let artifact = b"totally-fake-desktop-artifact-bytes-for-this-test".to_vec();
    let mut signature = sign(&sk, &artifact);

    // Tamper: flip one base64 character well inside the encoded signature blob (not just
    // whitespace/padding, which some decoders tolerate) so the decoded minisign signature bytes
    // themselves differ from what was actually produced by the test secret key.
    let mid = signature.len() / 2;
    let bytes = unsafe { signature.as_bytes_mut() };
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };

    let result = check_and_download(&signature, TEST_ONLY_PUBLIC_KEY_B64, &artifact).await;

    assert!(
        result.is_err(),
        "a tampered signature must be rejected, but download() returned Ok"
    );
}

/// Completeness: a missing `.sig` sidecar shows up, in the static-JSON manifest format this
/// pipeline publishes, as an empty (or absent) `signature` field for that platform — also rejected.
#[tokio::test]
async fn rejects_missing_signature() {
    let artifact = b"totally-fake-desktop-artifact-bytes-for-this-test".to_vec();

    let result = check_and_download("", TEST_ONLY_PUBLIC_KEY_B64, &artifact).await;

    assert!(
        result.is_err(),
        "a missing/empty signature must be rejected, but download() returned Ok"
    );
}

/// Belt-and-suspenders on the public-key side too: even a *correctly formed* signature, verified
/// against the *wrong* public key (as if the app shipped with a stale/mismatched bundled key),
/// must be rejected — the updater's trust anchor is the app's own bundled key, not whatever key
/// happens to have produced a well-formed signature.
#[tokio::test]
async fn rejects_signature_from_unrelated_key() {
    let sk = load_test_secret_key();
    let artifact = b"totally-fake-desktop-artifact-bytes-for-this-test".to_vec();
    let signature = sign(&sk, &artifact);

    // A second, unrelated keypair — this app's bundled pubkey does not match the key that
    // actually signed the artifact above.
    let unrelated_pk = minisign::KeyPair::generate_unencrypted_keypair()
        .expect("generating an unrelated throwaway test keypair never fails");
    let unrelated_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(
        unrelated_pk
            .pk
            .to_box()
            .expect("public key boxes")
            .to_string(),
    );

    let result = check_and_download(&signature, &unrelated_pubkey_b64, &artifact).await;

    assert!(
        result.is_err(),
        "a signature from a key other than the app's bundled pubkey must be rejected"
    );
}
