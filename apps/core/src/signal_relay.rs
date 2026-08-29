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
    /// (2.15) The peer's `@domain` routing hint — the same wire-level hint already threaded into
    /// `fetch_bundle` (task 2.7/2.9), now also carried on every `send()`. `None` for a same-server
    /// peer, `Some(domain)` when this relay's one fixed peer is believed to live at a foreign
    /// org's server. One `RendezvousRelay` always wraps one client for one fixed peer relationship
    /// (see the module docs), so a single hint fixed at construction is sufficient — there is no
    /// per-call hint to thread separately.
    hint: Option<String>,
}

impl<'a> RendezvousRelay<'a> {
    /// Wrap an already-connected, already-authenticated `SignalingClient`. `hint` is the peer's
    /// `@domain` routing hint (task 2.7/2.8's wire-level hint), passed on every `send()` so
    /// cross-org routing — not just the initial bundle fetch — reaches the federation path
    /// (task 2.15, system-design.md §3.3 step 2's "subsequent signaling envelopes" requirement).
    pub fn new(client: &'a mut SignalingClient, hint: Option<String>) -> Self {
        Self { client, hint }
    }
}

#[async_trait::async_trait]
impl SignalRelay for RendezvousRelay<'_> {
    async fn send(&mut self, to: &[u8; 32], blob: Vec<u8>) -> Result<(), SessionError> {
        map_route_result(
            self.client
                .route_with_hint(*to, self.hint.clone(), blob)
                .await,
        )
    }

    async fn recv(&mut self) -> Result<([u8; 32], Vec<u8>), SessionError> {
        map_deliver_result(self.client.next_deliver().await)
    }
}

/// (2.9) Reclassify a [`SignalError`] into a [`SessionError`], preserving the three
/// federation-specific outcomes (`FedDenied`/`FedUnreachable`/`NotFoundAtHint`) as their own
/// structurally distinct `SessionError` variants rather than folding them into the generic
/// [`SessionError::Relay`] string — mirrors [`meridian_signaling`]'s own taxonomy so the
/// reachability-vs-policy-vs-security distinction survives crossing from the signaling crate into
/// the session substrate. Any other error still degrades to `Relay(e.to_string())`, unchanged.
fn map_signal_error(e: SignalError) -> SessionError {
    match e {
        SignalError::FedDenied { hint, detail } => SessionError::FedDenied { hint, detail },
        SignalError::FedUnreachable { hint, detail } => {
            SessionError::FedUnreachable { hint, detail }
        }
        SignalError::NotFoundAtHint { hint, detail } => {
            SessionError::NotFoundAtHint { hint, detail }
        }
        other => SessionError::Relay(other.to_string()),
    }
}

/// The `route()` outcome → `send()` mapping, extracted so it is unit-testable without a live
/// WebSocket. A [`SignalError`] propagates via [`map_signal_error`]; `Ok(false)` (the peer was
/// not connected, so the server could not deliver) is *also* a hard error — see the module docs.
fn map_route_result(result: Result<bool, SignalError>) -> Result<(), SessionError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(SessionError::Relay(
            "peer is not currently connected to the rendezvous".to_string(),
        )),
        Err(e) => Err(map_signal_error(e)),
    }
}

/// The `next_deliver()` outcome → `recv()` mapping, extracted for the same reason.
fn map_deliver_result(
    result: Result<meridian_proto::Deliver, SignalError>,
) -> Result<([u8; 32], Vec<u8>), SessionError> {
    let deliver = result.map_err(map_signal_error)?;
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
            mailbox_id: None,
        };
        let (from, blob) = map_deliver_result(Ok(deliver)).unwrap();
        assert_eq!(from, [7u8; 32]);
        assert_eq!(blob, vec![1, 2, 3]);
    }

    // -- 2.9: federation outcomes survive the SignalError -> SessionError crossing distinctly ----

    #[test]
    fn route_fed_denied_maps_to_its_own_session_variant_not_relay() {
        let err = map_route_result(Err(SignalError::FedDenied {
            hint: "org-b.test".to_string(),
            detail: "closed".to_string(),
        }))
        .unwrap_err();
        match err {
            SessionError::FedDenied { hint, detail } => {
                assert_eq!(hint, "org-b.test");
                assert_eq!(detail, "closed");
            }
            other => panic!("expected SessionError::FedDenied, got {other:?}"),
        }
    }

    #[test]
    fn route_fed_unreachable_maps_to_its_own_session_variant() {
        let err = map_route_result(Err(SignalError::FedUnreachable {
            hint: "org-b.test".to_string(),
            detail: "dial failed".to_string(),
        }))
        .unwrap_err();
        assert!(matches!(err, SessionError::FedUnreachable { .. }));
    }

    #[test]
    fn deliver_not_found_at_hint_maps_to_its_own_session_variant_never_a_security_error() {
        let err = map_deliver_result(Err(SignalError::NotFoundAtHint {
            hint: "org-b.test".to_string(),
            detail: "no such account".to_string(),
        }))
        .unwrap_err();
        match err {
            SessionError::NotFoundAtHint { hint, .. } => assert_eq!(hint, "org-b.test"),
            other => panic!("expected SessionError::NotFoundAtHint, got {other:?}"),
        }
        // Structurally distinct from the fingerprint/envelope security checks — never
        // `FingerprintMismatch`/`Chat`, and the reachability outcome above must never be
        // constructible from this mapping as one of those.
    }

    #[test]
    fn other_signal_errors_still_fall_back_to_the_generic_relay_variant() {
        // Unaffected by the 2.9 additions: anything that isn't one of the three federation
        // outcomes keeps degrading to the pre-existing generic string, exactly as before.
        let err = map_route_result(Err(SignalError::ClosedEarly("frame"))).unwrap_err();
        assert!(matches!(err, SessionError::Relay(_)));
        let err = map_deliver_result(Err(SignalError::ClosedEarly("frame"))).unwrap_err();
        assert!(matches!(err, SessionError::Relay(_)));
    }
}
