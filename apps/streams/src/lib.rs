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
//! Task 10.6 adds the `StreamType` implementation + registration ([`file`]). Task 10.7 adds the
//! sender engine ([`sender`]). The receiver engine is a later task in this phase (10.8).

pub mod chunk;
pub mod file;
pub mod manifest;
pub mod merkle;
pub mod sender;

pub use chunk::{open_chunk, seal_chunk, ChunkError, ChunkFrame};
pub use file::{
    decide_file_offer, FileMeta, FileOfferVerdict, FileStream, FileStreamError, TransferState,
    DEFAULT_AUTO_ACCEPT_IMAGE_MAX_BYTES,
};
pub use manifest::FileManifest;
pub use merkle::{verify, Hash, MerkleProof, MerkleTree, ProofStep, Side, CHUNK_SIZE};
pub use sender::{
    send_chunk_frame, send_file, send_files, FileSend, SendProgress, SenderConfig, SenderError,
};
