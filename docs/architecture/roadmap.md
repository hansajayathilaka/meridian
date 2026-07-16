# Phased Roadmap & Feature Index

<!-- Source: p2p-comms-design.md §11 + tasks/T00-INDEX. -->
> **Nav:** [docs index](../INDEX.md) · [system design](./system-design.md) · [features](./features/) · [test strategy](../testing/strategy.md)

Every feature ships as a runnable increment — each spec under [features/](./features/) ends in a
demo you can execute at sign-off. Trust-critical substrate comes first; convenience later.

## Feature specs (priority order)

| # | Feature | Working output at sign-off | Depends on |
|---|---------|----------------------------|------------|
| [01](./features/01-identity-keystore-core.md) | Identity & Keystore Core | CLI mints/parses/verifies `mrd1:` IDs + QR | — |
| [02](./features/02-rendezvous-mvp.md) | Rendezvous Server MVP | Two CLIs register & fetch verified prekey bundles | 01 |
| [03](./features/03-e2ee-messaging-relayed.md) | E2EE Messaging (relayed) | Two CLIs chat; server sees only opaque blobs | 02 |
| [04](./features/04-p2p-session-substrate.md) | P2P Session Substrate | Chat goes P2P; survives server shutdown | 03 |
| [05](./features/05-nat-traversal-relay-policy.md) | NAT Traversal & Relay Policy | Session across symmetric NATs; `relay-only` hides IPs | 04 |
| [06](./features/06-cross-org-federation.md) | Cross-Org Federation | Full cross-org walkthrough on two stacks | 04 |
| [07](./features/07-offline-mailbox.md) | Offline Ciphertext Mailbox | Offline peer gets message on reconnect; DB ciphertext-only | 03, 06 |
| [08](./features/08-verification-trust.md) | Verification & Contact Trust | Simulated MITM fails closed; safety-number QR | 03 |
| [09](./features/09-file-transfer.md) | File Transfer Stream | 1 GiB transfer, killed mid-way, resumes + verifies | 04 |
| [10](./features/10-av-calls-screenshare.md) | Voice / Video / Screenshare | Cross-org video call, live relay fallback | 05, 06 |
| [11](./features/11-browser-desktop-clients.md) | Browser & Desktop Clients | Browser tab ↔ CLI chat + file transfer | 04–09 |
| [12](./features/12-mobile-clients.md) | Mobile Clients | Android/iOS chat + call, push-wake delivery | 10, 11 |
| [13](./features/13-multi-device.md) | Multi-Device | 2nd device by QR; ghost-device insertion detected | 08, 11 |
| [14](./features/14-selfhosting-ops-kit.md) | Self-Hosting Ops Kit | One-command stack; dashboard; air-gapped install | 06, 07 |
| [15](./features/15-location-stickers.md) | Location & Stickers | Live location on map; signed sticker pack P2P | 09, 11 |
| [16](./features/16-tier2-tunnels.md) | Tier-2 Tunnels (SSH / fs) | `ssh` into a NAT'd headless box via `meridian tunnel` | 09 |

## Phasing (from the design)

The canonical **design** phase narrative (Phase 0–4) lives in
[system-design.md §11](./system-design.md#11-phased-roadmap). In full:

**Phase 0 — Substrate (the risk burn-down):** meridian-core (identity, X3DH+Double Ratchet via audited lib, ctrl channel, `mrd.chat/1`), single-org rendezvous, CLI + one desktop client, direct+TURN ICE. Exit criterion: two CLIs on hostile NATs exchange verified, ratcheted messages via one org's stack.
**Phase 1 — Federation & Tier-1 core:** s2s mTLS federation (SRV + static map), ciphertext mailbox, `mrd.file/1`, voice/video/screenshare on 1:1 DTLS-SRTP with fingerprint-in-envelope binding, safety-number UX, browser + mobile clients. Exit: the §7.1 cross-org walkthrough works end-to-end on all five platforms.
**Phase 2 — Identity depth:** multi-device (device records, provisioning, fan-out), pairwise small groups (hard cap ~15), location + stickers, PQXDH bundle bump, message-request/anti-spam surface, ops hardening (Helm, dashboards, `doctor`).
**Phase 3 — Scale & privacy:** MLS groups on OpenMLS with rendezvous-as-DS commit log, mailbox padding/batching, multi-hint IDs, relay-only polish, sealed-sender-style envelope wrapping.
**Phase 4 — Reach:** `mrd.tunnel.tcp/1` + `mrd.fs/1` (SSH/FTP tier), QUIC transport negotiation for non-browser pairs, optional PKARR/DHT hint-resolution for server-less consumer mode, group calls (SFU + SFrame over MLS keys).

Sequencing rationale: everything trust-critical (identity, federation, verification) ships before anything convenient; Tier-2 waits because the stream abstraction (Phase 0) already guarantees it's additive.

> **Execution vs design phases:** day-to-day delivery is driven by the numbered *execution* phases in
> the [task tracker](../tasks/README.md) (Phase 0 done, Phase 1 review, Phase 2 = T06, …), which
> alternate build and review. Those are a delivery cadence, not the design grouping above.


## Parallel tracks for a small team
Track A (protocol): 01→03→08→13 · Track B (transport): 04→05→09→10→16 ·
Track C (infra): 02→06→07→14 · Track D (clients): 11→12→15.
Features 01–04 are the critical path everyone converges on first.
