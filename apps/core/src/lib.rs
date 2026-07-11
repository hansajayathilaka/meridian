//! meridian-core — shared core facade (scaffold placeholder).
//!
//! Public API contract: ../../docs/api/core-api-contracts.md
//! Module architecture:  ../../docs/architecture/diagrams/core-modules.mermaid
//!
//! No functional code in this scaffold. Sub-crates (identity, crypto, trust,
//! session, transport, streams, signaling, store) are added per the roadmap
//! (../../docs/architecture/roadmap.md), starting with feature 01.

/// Placeholder so the crate compiles. Replace with the real public surface.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
