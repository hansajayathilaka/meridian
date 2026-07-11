<!-- Source: resolves the open media question in ADR-0006 / system-design §12; handoff decision D2. -->
> **Nav:** [ADR index](./README.md) · [ADR 0006 (terminal transport)](./0006-terminal-transport.md) · [webrtc-nat-traversal skill](../../.claude/skills/webrtc-nat-traversal/SKILL.md)

# ADR 0014: Real-time media stack — libwebrtc for media, webrtc-rs for data (hybrid)

**Status:** **Accepted** (resolves the open "libwebrtc vs pure-Rust media" question flagged in
[ADR 0006](./0006-terminal-transport.md) and system design §12).

## Context
webrtc-rs gives us pure-Rust data channels, ICE, SCTP, DTLS, and SRTP — production-usable — but does
**not** implement the audio 3A pipeline (echo cancellation, noise suppression, AGC), NetEQ, or
hardware codec integration. Voice/video quality on real devices depends on exactly those pieces.

## Options
- **A. Pure webrtc-rs for everything**, build/port audio 3A ourselves.
- **B. libwebrtc for everything** (a `-sys` binding), drop webrtc-rs.
- **C. Hybrid (chosen):** webrtc-rs for all **data-channel** paths and the CLI; **libwebrtc** (via a
  `-sys` crate) for **real-time media** on desktop and mobile — both behind the `Transport` trait.

## Decision
**C — hybrid, split at the media boundary, hidden behind the `Transport` trait.**

### Pros
- **Ships a good call experience without a research project.** libwebrtc brings AEC/AGC/NS, NetEQ,
  hardware codecs, and platform capture — porting those into Rust (option A) is a multi-quarter effort
  that would gate features 10/12 indefinitely.
- **Keeps the data plane pure-Rust and identical everywhere.** Chat, files, location, tunnels, and the
  CLI stay on webrtc-rs — one wire behavior across all five targets, no C++ in the headless/server path.
- **The `Transport` trait already isolates this.** Consumers of `meridian-core` never see which stack
  is under a given session; swapping later touches only the shim ([core-api-contracts](../api/core-api-contracts.md)).
- **Matches the platform reality.** Mobile already needs libwebrtc for CallKit/ConnectionService and
  hardware codecs (features 10/12), so we pay that cost once and reuse it on desktop.

### Cons (accepted, with mitigations)
- **libwebrtc is a heavy, Google-driven C++ dependency** with a painful build. *Mitigation:* confine it
  to a single `meridian-media-sys` crate consumed only by desktop/mobile shims; **vendor a pinned
  prebuilt** (documented build pipeline is a deliverable, per feature 12) rather than building from
  Chromium depot_tools per-CI.
- **Two transport implementations to reason about.** *Mitigation:* they meet only at the `Transport`
  trait; data vs media is a clean seam, not a fork of the whole stack.
- **CLI video is out of scope** (terminals can't render it). *Mitigation:* already the design's position
  (§6) — CLI does data + optional Opus voice via `cpal`, and can save received tracks.

## Consequences
- New crate `meridian-media-sys` (desktop/mobile only); CLI and server never link it.
- webrtc-rs remains the default `Transport` for data; media sessions attach libwebrtc transceivers.
- A Phase-0/1 spike (`/spike libwebrtc-packaging`) decides vendor-prebuilt vs maintained `-sys` crate;
  until then, data-plane features (03/04/09/16) proceed unblocked on webrtc-rs.
