//! `SignalRelay`-over-`SignalingClient` adapter (1.24): closes the gap that today only
//! [`MemRelay`](crate::session::MemRelay) (an in-process channel pair) implements
//! [`SignalRelay`](crate::session::SignalRelay). Wrapping the real rendezvous
//! [`SignalingClient`](meridian_signaling::SignalingClient) here lets `dial_with_config`/
//! `answer_with_config` establish a P2P session across two real OS processes, not just within one
//! process's memory.
//!
//! ## Why this lives in `apps/core`, not `apps/signaling`
//! `meridian-core` already depends on `meridian-signaling`; `meridian-signaling` does not depend
//! back on `meridian-core`. `SignalRelay` is defined in [`crate::session`], so implementing it
//! inside `meridian-signaling` would require the reverse dependency and create a cycle.
//!
//! ## Peer filtering
//! [`recv`](RendezvousRelay::recv) forwards whatever [`SignalingClient::next_deliver`] returns
//! verbatim — it does **not** filter by peer itself. The caller
//! (`session::recv_sdp`) already discards any `(from, blob)` pair that doesn't match the expected
//! peer `ik`, so a second filter here would be redundant.
//!
//! ## `route()` is a hard error when not delivered
//! Unlike chat's tolerant offline-delivery (`route_tolerant` in `apps/cli/src/chat.rs`, which
//! treats a momentarily-offline peer as "not delivered" rather than fatal), P2P session
//! establishment has no mailbox/async-queuing story for the offer/answer exchange itself (that's
//! T07, and even then only chat envelopes get it) — if the peer is not live on the rendezvous right
//! now, dial/answer cannot proceed, so [`send`](RendezvousRelay::send) turns
//! `route() == Ok(false)` into a hard [`SessionError::Relay`].

use meridian_signaling::{SignalError, SignalingClient};

use crate::session::{SessionError, SignalRelay};

/// A [`SignalRelay`] backed by a real rendezvous [`SignalingClient`] connection. Borrows the
/// client (rather than owning it) so the caller can still use it afterward — in particular to
/// `close()` it once the P2P session is up, restoring T04's "servers out of the data path"
/// property over a real socket.
pub struct RendezvousRelay<'a> {
    client: &'a mut SignalingClient,
}

impl<'a> RendezvousRelay<'a> {
    /// Wrap an already-connected, already-authenticated `SignalingClient`.
    pub fn new(client: &'a mut SignalingClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl SignalRelay for RendezvousRelay<'_> {
    async fn send(&mut self, to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError> {
        map_route_result(self.client.route(*to, blob).await)
    }

    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError> {
        map_deliver_result(self.client.next_deliver().await)
    }
}

/// The `route()` outcome → `send()` mapping, extracted so it is unit-testable without a live
/// WebSocket. A [`SignalError`] propagates as [`SessionError::Relay`]; `Ok(false)` (the peer was
/// not connected, so the server could not deliver) is *also* a hard error — see the module docs.
fn map_route_result(result: Result<bool, SignalError>) -> Result<(), SessionError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(SessionError::Relay(
            "peer is not currently connected to the rendezvous".to_string(),
        )),
        Err(e) => Err(SessionError::Relay(e.to_string())),
    }
}

/// The `next_deliver()` outcome → `recv()` mapping, extracted for the same reason.
fn map_deliver_result(
    result: Result<meridian_proto::Deliver, SignalError>,
) -> Result<([u8; 32], Vec<u8>), SessionError> {
    let deliver = result.map_err(|e| SessionError::Relay(e.to_string()))?;
    Ok((deliver.from, deliver.blob.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_delivered_is_ok() {
        assert!(map_route_result(Ok(true)).is_ok());
    }

    #[test]
    fn route_not_delivered_is_a_hard_error() {
        // Design decision (task 1.24): unlike chat's tolerant offline-delivery, there is no mailbox
        // for the offer/answer exchange — an offline peer must abort dial/answer, not silently
        // continue.
        let err = map_route_result(Ok(false)).unwrap_err();
        match err {
            SessionError::Relay(msg) => {
                assert!(msg.contains("not currently connected"), "got: {msg}")
            }
            other => panic!("expected SessionError::Relay, got {other:?}"),
        }
    }

    #[test]
    fn route_signal_error_maps_to_relay_error() {
        let err = map_route_result(Err(SignalError::ClosedEarly("frame"))).unwrap_err();
        assert!(matches!(err, SessionError::Relay(_)));
    }

    #[test]
    fn deliver_signal_error_maps_to_relay_error() {
        let err = map_deliver_result(Err(SignalError::ClosedEarly("frame"))).unwrap_err();
        assert!(matches!(err, SessionError::Relay(_)));
    }

    #[test]
    fn deliver_ok_extracts_from_and_bytes() {
        let deliver = meridian_proto::Deliver {
            from: [7u8; 32],
            blob: meridian_proto::OpaqueBlob::new(vec![1, 2, 3]),
        };
        let (from, blob) = map_deliver_result(Ok(deliver)).unwrap();
        assert_eq!(from, [7u8; 32]);
        assert_eq!(blob, vec![1, 2, 3]);
    }
}
