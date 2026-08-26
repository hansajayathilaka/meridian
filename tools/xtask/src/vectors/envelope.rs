//! `MessageEnvelope` wire-encoding conformance fixtures (`test-vectors/envelope-v1.json`).
//!
//! **(task 6.3, ADR 0016 C2/C3/C5) Deliberate no-op pending task 6.5.** Envelope v2 changed
//! `MessageEnvelope` in place — a leading mandatory `v: u16`, and the per-message `sig: [u8; 64]`
//! signature field is gone entirely (authentication moved to the ratchet AEAD). There is therefore
//! no way to construct a v1-shaped `MessageEnvelope` from current code any more: this is a hard
//! flag day (R5), not a version this crate can still emit. Regenerating a byte-pinned
//! `envelope-v2.json` (and updating `apps/crypto/tests/conformance.rs` to check it) is task 6.5's
//! explicit job, not this task's — see `docs/tasks/phase-6/6.3-envelope-v2-core-cutover.md`'s "Out"
//! scope and ADR 0016's Consequences section ("v1 files retained; vectors are canonical and never
//! hand-edited"). Until 6.5 lands, this function does nothing — in particular it does NOT touch
//! `test-vectors/envelope-v1.json`, which stays exactly as committed — so `cargo run -p xtask --
//! vectors` keeps building and running cleanly across the cutover.
pub fn generate_envelope() -> Result<(), String> {
    Ok(())
}
