//! `LoopbackTransport` — a deterministic, in-process [`Transport`](crate::Transport) used by the
//! substrate's tests and the `meridian session` demo. Two [`LoopbackTransport`]s that share a
//! [`LoopbackFabric`] behave as two peers on the same LAN: SDP carries a routing token, data
//! channels are wired by label, and a "DTLS handshake" simply exposes each side's fingerprint to the
//! other.
//!
//! It is **not** a security boundary and does no crypto — that is exactly the point of the
//! `Transport` seam: identity binding is the substrate's post-handshake fingerprint cross-check
//! (§4.6), which this transport lets us exercise honestly, including a MITM mode
//! ([`LoopbackTransport::new_mitm`]) that reports a *different* negotiated fingerprint than the peer
//! asserted, so the forced-mismatch teardown test has something real to catch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use crate::types::{
    ChannelCfg, ChannelId, Fingerprint, IceCandidate, IceConfig, IcePolicy, MediaKind, Path, Sdp,
    SessionHandle, TrackId,
};
use crate::{Result, Transport, TransportError};

type Inbox = mpsc::UnboundedReceiver<(ChannelId, Vec<u8>)>;

/// Shared switchboard connecting the sessions of every [`LoopbackTransport`] built from it. Cheap to
/// clone (an `Arc`); clone it once per peer.
#[derive(Clone, Default)]
pub struct LoopbackFabric {
    inner: Arc<Mutex<FabricInner>>,
    inboxes: Arc<Mutex<HashMap<u64, Arc<AsyncMutex<Inbox>>>>>,
}

#[derive(Default)]
struct FabricInner {
    next_id: u64,
    next_channel: u64,
    sessions: HashMap<u64, Sess>,
}

struct Sess {
    token: u64,
    local_fp: Fingerprint,
    /// The negotiated *remote* fingerprint learned when the peer's SDP was applied. A MITM session
    /// records a corrupted value here so the substrate's §4.6 check trips.
    remote_fp: Option<Fingerprint>,
    peer: Option<u64>,
    channels: Vec<(String, ChannelId)>,
    local_candidates: Vec<IceCandidate>,
    ice_generation: u32,
    policy: IcePolicy,
    mitm: bool,
    tx: mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
}

impl LoopbackFabric {
    pub fn new() -> Self {
        Self::default()
    }
}

/// One peer's view onto a shared [`LoopbackFabric`].
#[derive(Clone)]
pub struct LoopbackTransport {
    fabric: LoopbackFabric,
    mitm: bool,
}

impl LoopbackTransport {
    /// An honest peer on `fabric`.
    pub fn new(fabric: LoopbackFabric) -> Self {
        Self {
            fabric,
            mitm: false,
        }
    }

    /// A malicious peer that terminated DTLS in the middle: it reports a *negotiated* fingerprint
    /// that differs from the one the honest peer asserted in its encrypted envelope. Used only to
    /// prove the substrate tears the session down 100% of the time (T04 deliverable 2).
    pub fn new_mitm(fabric: LoopbackFabric) -> Self {
        Self { fabric, mitm: true }
    }

    fn with_inner<R>(&self, f: impl FnOnce(&mut FabricInner) -> R) -> R {
        let mut g = self.fabric.inner.lock().unwrap();
        f(&mut g)
    }
}

/// Deterministic per-session fingerprint (a stand-in for the DTLS cert fingerprint). Distinct per
/// token so an honest peer's asserted value and the negotiated value agree.
fn fingerprint_for(token: u64) -> Fingerprint {
    Fingerprint(format!("sha-256 LOOPBACK:{token:016x}"))
}

/// Encode a session description that carries the routing token and the local fingerprint, so the
/// peer can both find us on the fabric and (honestly) learn our fingerprint.
fn encode_sdp(token: u64, fp: &Fingerprint, generation: u32) -> Sdp {
    Sdp(format!("v=loopback\ntoken={token}\nfp={}\ngen={generation}\n", fp.0).into_bytes())
}

fn parse_sdp(sdp: &Sdp) -> Result<(u64, Fingerprint)> {
    let text = std::str::from_utf8(&sdp.0).map_err(|_| TransportError::BadRemoteDescription)?;
    let mut token = None;
    let mut fp = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("token=") {
            token = v.parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("fp=") {
            fp = Some(Fingerprint(v.to_string()));
        }
    }
    match (token, fp) {
        (Some(t), Some(f)) => Ok((t, f)),
        _ => Err(TransportError::BadRemoteDescription),
    }
}

#[async_trait::async_trait]
impl Transport for LoopbackTransport {
    async fn new_session(&self, cfg: IceConfig) -> Result<SessionHandle> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.with_inner(|inner| {
            inner.next_id += 1;
            let id = inner.next_id;
            let local_fp = fingerprint_for(id);
            // relay-only strips host/srflx candidates *before* gathering (invariant 3): none are
            // synthesized here. Relay (TURN) candidates are T05, so a relay-only loopback session
            // gathers nothing and would need T05 to connect — which is the honest behavior.
            let local_candidates = match cfg.policy {
                IcePolicy::RelayOnly => Vec::new(),
                _ => vec![
                    IceCandidate(format!("candidate:host {id} 127.0.0.1")),
                    IceCandidate(format!("candidate:srflx {id} 203.0.113.{}", id % 251)),
                ],
            };
            inner.sessions.insert(
                id,
                Sess {
                    token: id,
                    local_fp,
                    remote_fp: None,
                    peer: None,
                    channels: Vec::new(),
                    local_candidates,
                    ice_generation: 0,
                    policy: cfg.policy,
                    mitm: self.mitm,
                    tx,
                },
            );
            id
        });
        self.fabric
            .inboxes
            .lock()
            .unwrap()
            .insert(id, Arc::new(AsyncMutex::new(rx)));
        Ok(SessionHandle(id))
    }

    async fn add_data_channel(&self, s: &SessionHandle, cfg: ChannelCfg) -> Result<ChannelId> {
        self.with_inner(|inner| {
            inner.next_channel += 1;
            let cid = ChannelId(inner.next_channel);
            let sess = inner
                .sessions
                .get_mut(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            sess.channels.push((cfg.label, cid));
            Ok(cid)
        })
    }

    async fn add_transceiver(&self, s: &SessionHandle, _kind: MediaKind) -> Result<TrackId> {
        // Media is ADR 0014 / libwebrtc, out of scope for the loopback data plane. Return a stub id
        // so the trait is total; the substrate never calls this on a data-only session.
        self.with_inner(|inner| {
            inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            Ok(TrackId(s.0))
        })
    }

    fn local_description(&self, s: &SessionHandle) -> Result<Sdp> {
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            Ok(encode_sdp(sess.token, &sess.local_fp, sess.ice_generation))
        })
    }

    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()> {
        // The token *is* the peer's session id (tokens are allocated as ids), so no live-session
        // lookup is needed — the peer may already have torn down (e.g. a MITM that failed its own
        // fingerprint check). Data sent later to a gone peer is simply dropped.
        let (peer_id, asserted_fp) = parse_sdp(&sdp)?;
        self.with_inner(|inner| {
            let mitm = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?
                .mitm;
            // A MITM records a *corrupted* negotiated fingerprint — different from what the peer
            // asserted — modelling a DTLS termination the signaling path could never authenticate.
            let negotiated = if mitm {
                Fingerprint(format!("sha-256 MITM:{peer_id:016x}"))
            } else {
                asserted_fp
            };
            let sess = inner
                .sessions
                .get_mut(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            sess.peer = Some(peer_id);
            sess.remote_fp = Some(negotiated);
            Ok(())
        })
    }

    async fn add_ice_candidate(&self, s: &SessionHandle, _c: IceCandidate) -> Result<()> {
        // Candidates only refine the path in a real backend; on the loopback the link is already up
        // once descriptions are exchanged. Just validate the handle.
        self.with_inner(|inner| {
            inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            Ok(())
        })
    }

    async fn local_candidates(&self, s: &SessionHandle) -> Result<Vec<IceCandidate>> {
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            Ok(sess.local_candidates.clone())
        })
    }

    fn local_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint> {
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            Ok(sess.local_fp.clone())
        })
    }

    fn dtls_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint> {
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            sess.remote_fp.clone().ok_or(TransportError::NoPath)
        })
    }

    async fn ice_restart(&self, s: &SessionHandle) -> Result<()> {
        // Keep the peer link and the negotiated fingerprint; just bump the generation and re-gather
        // candidates. The substrate's ratchet state is untouched (invariant 5).
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get_mut(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            sess.ice_generation += 1;
            let id = sess.token;
            if sess.policy != IcePolicy::RelayOnly {
                sess.local_candidates = vec![
                    IceCandidate(format!(
                        "candidate:host {id} 127.0.0.1 gen={}",
                        sess.ice_generation
                    )),
                    IceCandidate(format!(
                        "candidate:srflx {id} 198.51.100.{} gen={}",
                        id % 251,
                        sess.ice_generation
                    )),
                ];
            }
            Ok(())
        })
    }

    async fn send(&self, s: &SessionHandle, ch: &ChannelId, data: &[u8]) -> Result<()> {
        // Resolve the sending channel's label and the peer, then deliver to the peer's channel that
        // carries the same label (creating it if the peer opened channels in a different order).
        let (label, peer_id) = self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            let label = sess
                .channels
                .iter()
                .find(|(_, cid)| cid == ch)
                .map(|(l, _)| l.clone())
                .ok_or(TransportError::UnknownChannel)?;
            let peer_id = sess.peer.ok_or(TransportError::NoPath)?;
            Ok::<_, TransportError>((label, peer_id))
        })?;

        let (peer_cid, peer_tx) = self.with_inner(|inner| {
            let next_channel = &mut inner.next_channel;
            let peer = inner
                .sessions
                .get_mut(&peer_id)
                .ok_or(TransportError::Closed)?;
            let cid = match peer.channels.iter().find(|(l, _)| *l == label) {
                Some((_, cid)) => *cid,
                None => {
                    *next_channel += 1;
                    let cid = ChannelId(*next_channel);
                    peer.channels.push((label.clone(), cid));
                    cid
                }
            };
            Ok::<_, TransportError>((cid, peer.tx.clone()))
        })?;

        // A closed peer just drops the frame (a lost packet), never an error that would tear down
        // the sender — the substrate decides teardown, not the pipe.
        let _ = peer_tx.send((peer_cid, data.to_vec()));
        Ok(())
    }

    async fn recv(&self, s: &SessionHandle) -> Result<Option<(ChannelId, Vec<u8>)>> {
        let inbox = self
            .fabric
            .inboxes
            .lock()
            .unwrap()
            .get(&s.0)
            .cloned()
            .ok_or(TransportError::UnknownSession)?;
        let mut rx = inbox.lock().await;
        Ok(rx.recv().await)
    }

    async fn selected_path(&self, s: &SessionHandle) -> Result<Path> {
        self.with_inner(|inner| {
            let sess = inner
                .sessions
                .get(&s.0)
                .ok_or(TransportError::UnknownSession)?;
            if sess.peer.is_none() {
                return Err(TransportError::NoPath);
            }
            Ok(match sess.policy {
                IcePolicy::RelayOnly => Path::Relay,
                _ => Path::Direct,
            })
        })
    }

    async fn close(&self, s: &SessionHandle) -> Result<()> {
        self.with_inner(|inner| {
            inner.sessions.remove(&s.0);
        });
        self.fabric.inboxes.lock().unwrap().remove(&s.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_peers_exchange_bytes_and_fingerprints_agree() {
        let fabric = LoopbackFabric::new();
        let a = LoopbackTransport::new(fabric.clone());
        let b = LoopbackTransport::new(fabric.clone());

        let sa = a.new_session(IceConfig::default()).await.unwrap();
        let sb = b.new_session(IceConfig::default()).await.unwrap();

        let ca = a
            .add_data_channel(&sa, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
            .await
            .unwrap();
        b.add_data_channel(&sb, ChannelCfg::reliable_ordered("mrd.ctrl/1"))
            .await
            .unwrap();

        // Exchange descriptions (as the substrate would, via encrypted envelopes).
        let offer = a.local_description(&sa).unwrap();
        let answer = b.local_description(&sb).unwrap();
        b.set_remote_description(&sb, offer).await.unwrap();
        a.set_remote_description(&sa, answer).await.unwrap();

        // Honest peers: each side's negotiated remote fp equals the other's asserted local fp.
        assert_eq!(a.dtls_fingerprint(&sa).unwrap(), fingerprint_for(sb.0));
        assert_eq!(b.dtls_fingerprint(&sb).unwrap(), fingerprint_for(sa.0));

        // Data flows peer-to-peer with no server involved.
        a.send(&sa, &ca, b"hello").await.unwrap();
        let (_cid, data) = b.recv(&sb).await.unwrap().unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(a.selected_path(&sa).await.unwrap(), Path::Direct);
    }

    #[tokio::test]
    async fn mitm_reports_a_different_negotiated_fingerprint() {
        let fabric = LoopbackFabric::new();
        let honest = LoopbackTransport::new(fabric.clone());
        let mitm = LoopbackTransport::new_mitm(fabric.clone());

        let sh = honest.new_session(IceConfig::default()).await.unwrap();
        let sm = mitm.new_session(IceConfig::default()).await.unwrap();

        let honest_offer = honest.local_description(&sh).unwrap();
        mitm.set_remote_description(&sm, honest_offer)
            .await
            .unwrap();

        // The MITM's negotiated fp does NOT equal the honest peer's real fingerprint — the exact
        // condition the substrate's §4.6 check rejects.
        assert_ne!(mitm.dtls_fingerprint(&sm).unwrap(), fingerprint_for(sh.0));
    }
}
