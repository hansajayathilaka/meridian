//! `mrd.ctrl/1` — channel 0 (system-design §5.3, wire-protocol.md §5). The always-first, reliable,
//! ordered data channel that carries capability advertisement, stream open/accept/reject/close
//! negotiation, and keep-alives. Every ctrl frame is CBOR and is **ratchet-sealed like any payload**
//! (wrapped in [`SignalContent::Ctrl`](crate::signal::SignalContent) before it rides the channel),
//! so a passive observer of the data channel sees only ciphertext.
//!
//! The version lives in the channel *name* (`mrd.ctrl/1`); a wire break is a new channel name, so
//! these structs carry a numeric `v` only inside [`Hello`] for the capability handshake.

use serde::{Deserialize, Serialize};

/// The `mrd.ctrl/1` protocol version advertised in [`Hello`].
pub const CTRL_VERSION: u16 = 1;

/// Direction a stream type is offered in (advertised in [`Hello`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// We can originate this stream (`OPEN` it).
    Outbound,
    /// We can accept this stream from the peer.
    Inbound,
    /// Both.
    Bidir,
}

/// One entry in a peer's advertised stream-type registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamAdvert {
    /// Registry name, e.g. `mrd.chat/1`.
    pub name: String,
    /// Type version.
    pub ver: u16,
    /// Which direction(s) we support it in.
    pub dir: Direction,
    /// If `true`, a peer that does not also support this type MUST reject the session at capability
    /// exchange (wire-protocol §2: "unknown *mandatory* capability names are rejected"). Optional
    /// (`false`) types are simply unavailable, never a session error.
    pub mandatory: bool,
}

/// Advisory flow-control / sizing limits carried in [`Hello`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Limits {
    /// Largest single ctrl/stream frame the sender will accept, in bytes. `0` ⇒ unspecified.
    pub max_frame: u32,
}

/// The wire form of a data channel's reliability/ordering config (mirrors
/// [`meridian_transport::ChannelCfg`] but stays in `-proto` so the server-independent wire shape is
/// canonical). `"rtp"` (media) is represented by `rtp = true`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChanCfgWire {
    pub reliable: bool,
    pub ordered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rtx: Option<u16>,
    /// A media (RTP transceiver) stream rather than a data channel.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rtp: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A `mrd.ctrl/1` frame. Serialized to deterministic CBOR, then sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlFrame {
    /// Capability advertisement, exchanged first on both sides once ctrl opens.
    Hello {
        v: u16,
        streams: Vec<StreamAdvert>,
        transports: Vec<String>,
        limits: Limits,
    },
    /// Request to open a stream. The peer's policy layer accepts/rejects.
    Open {
        sid: u64,
        #[serde(rename = "type")]
        ty: String,
        #[serde(with = "crate::bytes::bytes_vec")]
        params: Vec<u8>,
        chan: ChanCfgWire,
    },
    /// Accept a previously-received [`CtrlFrame::Open`].
    Accept { sid: u64 },
    /// Reject an [`CtrlFrame::Open`]. `code = "unsupported"` for an unknown type — never a session
    /// error (wire-protocol §5).
    Reject {
        sid: u64,
        code: String,
        reason: String,
    },
    /// Close a stream. `status` is a short reason ("done", "cancelled", "policy").
    Close { sid: u64, status: String },
    /// Liveness ping; also carries flow-control hints in a real deployment. `t` is a monotonic
    /// counter/timestamp the peer echoes semantics-free.
    Keepalive { t: u64 },
}

impl CtrlFrame {
    /// Deterministic-CBOR encode (the plaintext that gets ratchet-sealed).
    pub fn encode(&self) -> Result<Vec<u8>, crate::CodecError> {
        crate::encode(self)
    }

    /// Decode a decrypted ctrl frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::CodecError> {
        crate::decode(bytes)
    }
}
