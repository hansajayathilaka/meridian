//! Stream-type registry — the extension point that makes "ultimate sharing platform" an
//! *architectural* property (system-design §5.3, core-api-contracts §"Stream registry"). A new
//! feature (file transfer T09, calls T10, location T15, tunnels T16) is a registered
//! [`StreamType`] — a name, a channel config, a direction, and a policy hook — and **nothing in the
//! core changes**. Downstream code calls [`register_stream_type`] only; it never edits this crate.
//!
//! The full contract third parties code against is documented in
//! [`docs/api/stream-types-v1.md`](../../docs/api/stream-types-v1.md). Review changes here as if
//! third parties will implement against them, because eventually they will.

use std::collections::BTreeMap;
use std::sync::Arc;

use meridian_proto::ctrl::{Direction, Limits, StreamAdvert};
use meridian_proto::{CtrlFrame, CTRL_VERSION};
use meridian_transport::ChannelCfg;

/// A stream identifier assigned at OPEN time (the data channel label suffix / ctrl `sid`).
pub type StreamId = u64;

/// Context handed to a [`StreamType::on_open`] policy hook. Minimal by design in T04 (T08 grows the
/// trust surface); a hook decides accept/reject from the peer identity and whether this is a first
/// contact.
pub struct PolicyCtx {
    /// The peer's Ed25519 identity key.
    pub peer_ik: [u8; 32],
    /// Whether this is the first stream ever opened from this peer (message-request gate, §7.1).
    pub first_contact: bool,
}

/// A stream type's decision when the peer asks to OPEN it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenDecision {
    /// Accept — the substrate replies `Accept{sid}` and wires the data channel.
    Accept,
    /// Reject with a ctrl `code`/`reason` (e.g. `unsupported`, `policy`). Never a session error.
    Reject { code: String, reason: String },
}

/// The extension trait every stream type implements (core-api-contracts §"Stream registry"). Chat,
/// file, location, call, tunnel, and fs are all just implementations of this — added via the
/// registry with **zero** core-crate edits.
pub trait StreamType: Send + Sync {
    /// Registry name including the version, e.g. `"mrd.file/1"`.
    fn name(&self) -> &'static str;
    /// Numeric type version (matches the `/N` suffix in [`name`](StreamType::name)).
    fn version(&self) -> u16;
    /// The data-channel reliability/ordering (or RTP) this type rides on.
    fn channel_cfg(&self) -> ChannelCfg;
    /// Which direction(s) this side offers the type in.
    fn direction(&self) -> Direction;
    /// Whether a peer that lacks this type must reject the session (advertised as `mandatory`).
    /// Default optional — an unknown *optional* type is simply unavailable, never a session error.
    fn mandatory(&self) -> bool {
        false
    }
    /// Policy hook run when the peer asks to OPEN this stream. Default auto-accepts (chat behavior);
    /// screenshare/SSH/org-policy types override to prompt or consult a policy engine.
    fn on_open(&self, _sid: StreamId, _params: &[u8], _policy: &PolicyCtx) -> OpenDecision {
        OpenDecision::Accept
    }
    /// Called for each inbound stream frame once the stream is open. Default ignores (the substrate
    /// surfaces `mrd.chat/1` via its own callback); file/fs types buffer/assemble here.
    fn on_frame(&self, _sid: StreamId, _frame: &[u8]) {}
}

/// The per-session set of supported stream types. Built with [`with_builtins`](StreamRegistry::with_builtins)
/// (registers `mrd.chat/1`), then extended by downstream features via [`register_stream_type`].
#[derive(Clone, Default)]
pub struct StreamRegistry {
    types: BTreeMap<String, Arc<dyn StreamType>>,
}

/// Why capability exchange rejected the session (unknown mandatory type).
#[derive(Debug, thiserror::Error)]
#[error("peer requires unsupported mandatory stream type(s): {missing:?}")]
pub struct CapabilityError {
    /// The mandatory type names the peer advertised that we do not support.
    pub missing: Vec<String>,
}

impl StreamRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with the Tier-1 built-in `mrd.chat/1` registered. `mrd.ctrl/1` is not a stream
    /// type — it is channel 0 itself — so it is implicit and never registered here.
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Arc::new(ChatStream));
        r
    }

    /// Register a stream type. The only mutation point downstream features use.
    pub fn register(&mut self, ty: Arc<dyn StreamType>) {
        self.types.insert(ty.name().to_string(), ty);
    }

    /// Look up a registered type by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn StreamType>> {
        self.types.get(name).cloned()
    }

    /// Whether a type name is registered.
    pub fn supports(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// The registry advertisement carried in a `mrd.ctrl/1` [`CtrlFrame::Hello`].
    pub fn advertise(&self) -> Vec<StreamAdvert> {
        self.types
            .values()
            .map(|t| StreamAdvert {
                name: t.name().to_string(),
                ver: t.version(),
                dir: t.direction(),
                mandatory: t.mandatory(),
            })
            .collect()
    }

    /// Build our `Hello` capability frame.
    pub fn hello(&self) -> CtrlFrame {
        CtrlFrame::Hello {
            v: CTRL_VERSION,
            streams: self.advertise(),
            transports: vec!["webrtc".to_string()],
            limits: Limits { max_frame: 0 },
        }
    }

    /// Validate a peer's `Hello`: every stream type the peer marks `mandatory` must be one we also
    /// support, else the session is rejected **gracefully** at capability exchange (wire-protocol
    /// §2). An unknown *optional* type is fine — it is simply unavailable.
    pub fn check_peer(&self, peer_hello: &CtrlFrame) -> Result<(), CapabilityError> {
        let CtrlFrame::Hello { streams, .. } = peer_hello else {
            // A non-Hello where Hello was expected is a protocol error surfaced as "missing" caps.
            return Err(CapabilityError {
                missing: vec!["<expected Hello>".to_string()],
            });
        };
        let missing: Vec<String> = streams
            .iter()
            .filter(|s| s.mandatory && !self.supports(&s.name))
            .map(|s| s.name.clone())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(CapabilityError { missing })
        }
    }
}

/// Free-function form of [`StreamRegistry::register`] matching the core-api-contracts name so the
/// contract's `register_stream_type(t)` reads identically at call sites (`register_stream_type(&mut
/// reg, ty)`). Additive types use ONLY this — never a core edit.
pub fn register_stream_type(registry: &mut StreamRegistry, ty: Arc<dyn StreamType>) {
    registry.register(ty);
}

/// The Tier-1 built-in `mrd.chat/1` stream: reliable, ordered, auto-accepted (§5.3). The substrate
/// carries chat payloads itself (surfacing them via its callback), so `on_frame` is unused here.
pub struct ChatStream;

impl StreamType for ChatStream {
    fn name(&self) -> &'static str {
        "mrd.chat/1"
    }
    fn version(&self) -> u16 {
        1
    }
    fn channel_cfg(&self) -> ChannelCfg {
        ChannelCfg::reliable_ordered("mrd.chat/1")
    }
    fn direction(&self) -> Direction {
        Direction::Bidir
    }
    fn mandatory(&self) -> bool {
        // Chat is the Tier-1 baseline both peers must speak.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Exotic;
    impl StreamType for Exotic {
        fn name(&self) -> &'static str {
            "mrd.exotic/9"
        }
        fn version(&self) -> u16 {
            9
        }
        fn channel_cfg(&self) -> ChannelCfg {
            ChannelCfg::reliable_ordered("mrd.exotic/9")
        }
        fn direction(&self) -> Direction {
            Direction::Bidir
        }
        fn mandatory(&self) -> bool {
            true
        }
    }

    #[test]
    fn builtins_advertise_chat() {
        let r = StreamRegistry::with_builtins();
        assert!(r.supports("mrd.chat/1"));
        let adv = r.advertise();
        assert_eq!(adv.len(), 1);
        assert_eq!(adv[0].name, "mrd.chat/1");
        assert!(adv[0].mandatory);
    }

    #[test]
    fn unknown_mandatory_type_is_rejected_gracefully() {
        let ours = StreamRegistry::with_builtins();
        // A peer that also registered a mandatory exotic type we lack.
        let mut theirs = StreamRegistry::with_builtins();
        register_stream_type(&mut theirs, Arc::new(Exotic));
        let err = ours.check_peer(&theirs.hello()).unwrap_err();
        assert_eq!(err.missing, vec!["mrd.exotic/9".to_string()]);
    }

    #[test]
    fn matching_capabilities_accept() {
        let ours = StreamRegistry::with_builtins();
        let theirs = StreamRegistry::with_builtins();
        assert!(ours.check_peer(&theirs.hello()).is_ok());
    }

    #[test]
    fn unknown_optional_type_is_fine() {
        struct OptionalExotic;
        impl StreamType for OptionalExotic {
            fn name(&self) -> &'static str {
                "mrd.optional/1"
            }
            fn version(&self) -> u16 {
                1
            }
            fn channel_cfg(&self) -> ChannelCfg {
                ChannelCfg::reliable_ordered("mrd.optional/1")
            }
            fn direction(&self) -> Direction {
                Direction::Bidir
            }
            // mandatory() defaults to false.
        }
        let ours = StreamRegistry::with_builtins();
        let mut theirs = StreamRegistry::with_builtins();
        register_stream_type(&mut theirs, Arc::new(OptionalExotic));
        assert!(ours.check_peer(&theirs.hello()).is_ok());
    }
}
