<!-- Source: p2p-comms-design.md §8 ADR-6. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

> **Update:** the open media-stack question referenced here is now resolved in **[ADR 0014](./0014-media-stack.md)** (libwebrtc for real-time media, webrtc-rs for data).

# ADR 0006: Terminal/non-browser transport — native WebRTC (webrtc-rs / libdatachannel), QUIC deferred

**Status:** Proposed · **Options:** (A) headless Chromium; (B) **native WebRTC library — webrtc-rs (Rust) or libdatachannel (C++) (chosen)**; (C) QUIC/WebTransport between non-browser peers with WebRTC only when a browser participates; (D) plain TLS-TCP with manual traversal.

**Trade-offs:** A is a ~300 MB dependency and an embarrassment on a headless server. D forfeits NAT traversal — non-viable. C is the technically superior long-term transport for bulk data (proper congestion control, streams without SCTP quirks) but bifurcates the wire protocol day one and still requires the WebRTC path anyway (browsers exist). B gives one wire protocol across all five platforms now; webrtc-rs keeps the build pure-Rust (favored), libdatachannel is the fallback if webrtc-rs media maturity disappoints (data channels in webrtc-rs are solid; full media stacks on desktop may still borrow libwebrtc, per §6). **Decision: B**, with the `Transport` trait explicitly sized so C can slot in as a negotiated capability (`transport=quic` in the capability exchange) in Phase 4 for CLI↔CLI bulk transfer. **Consequences:** SCTP throughput ceilings accepted near-term; one protocol to debug everywhere.

