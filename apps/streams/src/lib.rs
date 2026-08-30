//! meridian-streams — additive stream types (T03/T09/T15/T16: chat, file, location, sticker,
//! tunnel, fs). Home for content-shaped payload schemas that ride over a session's data channel
//! stream framing (`docs/api/wire-protocol.md` §6) once opened via `mrd.ctrl/1` (§5).
//!
//! This crate is where **additive stream types** live per the workspace convention (root
//! `CLAUDE.md`, `apps/CLAUDE.md`): a new stream type is added here, registered with the stream
//! registry (task 10.6's `StreamType` trait, later), and touches no core crate.
//!
//! Task 10.3 scope: the `mrd.file/1` manifest schema ([`manifest`]) and the BLAKE3 merkle
//! build/verify primitive ([`merkle`]) it depends on. Task 10.5 adds per-chunk AEAD ([`chunk`]).
//! The `StreamType` trait impl and the sender/receiver engines are later tasks in this phase
//! (10.6/10.7/10.8).

pub mod chunk;
pub mod manifest;
pub mod merkle;

pub use chunk::{open_chunk, seal_chunk, ChunkError};
pub use manifest::FileManifest;
pub use merkle::{verify, Hash, MerkleProof, MerkleTree, ProofStep, Side, CHUNK_SIZE};
