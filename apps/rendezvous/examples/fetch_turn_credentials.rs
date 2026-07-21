//! Netns NAT-matrix rig helper (task 1.25): mint one real ephemeral TURN credential from a live
//! `meridian-rendezvous` instance, through the actual `TurnReq`/`TurnGrant` wire flow
//! (`meridian_signaling::SignalingClient::request_turn_credentials`) — never a hand-rolled
//! coturn-only HMAC script. `tools/netns-nat-matrix.sh` shells out to this so its TURN-reachability
//! smoke check (`turnutils_uclient`) exercises the same credential-minting path a real client uses.
//!
//! Usage: `cargo run -p meridian-rendezvous --example fetch_turn_credentials -- <ws-url>`
//!
//! Prints one `key=value` line per field to stdout (bash-parseable; deliberately not JSON, to avoid
//! adding a dependency this crate doesn't otherwise need):
//!   username=<...>
//!   credential=<...>
//!   realm=<...>
//!   ttl_secs=<...>
//!   url=<...>       (repeated, one per ICE-server URL in ladder order)

use meridian_identity::{generate_account, MemorySecretStore};
use meridian_signaling::SignalingClient;

#[tokio::main]
async fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: fetch_turn_credentials <ws-url>");
        std::process::exit(2);
    });

    let store = MemorySecretStore::new();
    let account = generate_account(&store, "localhost").unwrap_or_else(|e| {
        eprintln!("generate_account: {e}");
        std::process::exit(1);
    });

    let mut client = SignalingClient::connect(
        &url,
        &store,
        account.handle(),
        *account.public_key().as_bytes(),
        None,
        1,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("connect {url}: {e}");
        std::process::exit(1);
    });

    let grant = client.request_turn_credentials().await.unwrap_or_else(|e| {
        eprintln!("request_turn_credentials: {e}");
        std::process::exit(1);
    });

    println!("username={}", grant.username);
    println!("credential={}", grant.credential);
    println!("realm={}", grant.realm);
    println!("ttl_secs={}", grant.ttl_secs);
    for u in &grant.urls {
        println!("url={u}");
    }

    let _ = client.close().await;
}
