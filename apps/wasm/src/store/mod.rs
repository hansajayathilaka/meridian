//! Browser-side local store surface (ADR 0026, T11). `indexeddb` is the IndexedDB
//! record-sealing/schema module this crate owns directly (task 12.12) — see its own module doc for
//! why it lives here rather than in `apps/store` alongside task 12.5's `WebCryptoSecretStore`
//! (dependency-cycle avoidance: `meridian-crypto`, needed here for `at_rest::seal`/`open`, already
//! depends on `meridian-store`, so `apps/store` cannot also depend on `meridian-crypto`).
//!
//! `wasm32`-gated at the `pub mod store;` declaration in `lib.rs` — everything under here wraps
//! `web_sys::IdbFactory`/`IdbDatabase`, meaningless on any other target.

pub mod indexeddb;
