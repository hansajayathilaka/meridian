<!-- Source: p2p-comms-design.md (master design). Threat model (§1) and ADRs (§8) are
     extracted into docs/security/ and docs/adr/ respectively and linked below to avoid
     duplication. This remains the canonical architectural narrative. -->
> **Nav:** [docs index](../INDEX.md) · [stack](./stack.md) · [data model](./data-model.md) · [roadmap](./roadmap.md) · [diagrams](./diagrams/README.md) · [threat model](../security/threat-model.md) · [ADRs](../adr/README.md)

# Meridian: A Decentralized, End-to-End-Encrypted, Cross-Platform Communication Platform

**System Design & Architecture — v1.0 draft**
**Author:** Principal architect review draft · **Status:** Proposed

---
## 0. Design stance and core assumptions

Before the threat model, three assumptions that shape everything downstream. They are stated here so they can be challenged early.

**Assumption 1 — Identity must be self-certifying.** The single most important decision in this design is that a user's shareable ID *is* (a hash of) their public key, not a name resolved by a server. Once identity is key-derived, the signaling server is demoted from a trust anchor to a dumb message router: it can deny service, but it can never impersonate a user without producing a detectable key mismatch. Every other security property in this document leans on this.

**Assumption 2 — "Serverless" means content-blind, not server-free.** Pure infrastructure-free P2P (DHT-only discovery, no rendezvous point) fails the enterprise and air-gapped requirements, fails offline delivery, and fails mobile battery/NAT realities. We interpret the requirement precisely as written: servers exist for *rendezvous* and *relay*, hold no plaintext, and hold as little metadata as we can engineer away. Where a server must hold *ciphertext* transiently (offline message delivery), we call that out explicitly rather than pretending it isn't a server-side store (see ADR-7).

**Assumption 3 — Metadata privacy is a spectrum, and WebRTC sits at an awkward point on it.** Direct P2P connections reveal peer IP addresses to each other and connection timing to the signaling operator. Perfect metadata hiding (Tor-grade unlinkability) is incompatible with low-latency A/V calling over WebRTC. We do not paper over this: we define a per-contact/per-org privacy policy knob (direct ↔ relay-only) and state plainly what each setting leaks and to whom (§1.3, §10).

Other assumptions: a small self-hosting team (2–5 engineers) operates the infra; orgs federating with each other have mutual network reachability between their signaling servers (or an explicit bridge); clients can be updated on a reasonable cadence; we may use well-audited open-source crypto libraries (libsodium, ring, OpenMLS, libsignal) — we never author primitives.

---


## 1. Threat model & security goals

> Extracted to a dedicated, canonical file: **[docs/security/threat-model.md](../security/threat-model.md)**.
> In one line: *servers are trusted for availability only; peers are trusted for content you
> deliberately send them; nobody is trusted for keys.* See also the
> [threat → mitigation matrix](../security/threat-mitigation-matrix.md) and
> [privacy & retention model](../security/anonymity-and-retention.md).

## 2. High-level architecture

### 2.1 Components

**Client core ("meridian-core")** — a single Rust library containing: identity & keystore, X3DH/Double-Ratchet (and later MLS) session management, the stream-type registry and framing, file-transfer engine, signaling protocol client, and federation-aware addressing. Compiled natively for desktop/mobile/terminal and to WASM for browsers. Platform shims provide transport (WebRTC), UI, and OS keystore access (§6).

**Signaling server ("meridian-rendezvous")** — the only always-on service an org must run. Responsibilities, exhaustively: (1) accept client WebSocket connections and authenticate them by identity-key challenge; (2) store users' *public* prekey bundles and signed device lists; (3) route opaque, client-signed signaling envelopes (SDP offers/answers, ICE candidates) between connected clients; (4) hold a bounded, TTL'd *ciphertext* mailbox for offline delivery (ADR-7); (5) speak the server-to-server federation protocol to peer orgs' rendezvous servers. It stores no plaintext, no message content, no contact graphs beyond transient routing state, and cannot forge any envelope (all envelopes are signed by sender identity keys and verified by recipients).

**Relay server (TURN)** — stock coturn (or eturnal), org-operated, granting time-limited allocations via HMAC credentials minted by the rendezvous server. Sees only DTLS/SRTP ciphertext. Optional but strongly recommended; ~15–20% of real-world pairs need it.

**STUN** — usually the same coturn instance; air-gapped deployments point clients only at internal STUN/TURN.

There is deliberately **no** application server, no user database beyond `pubkey → (prekeys, device list, mailbox, routing hint)`, and no server-side contact list.

### 2.2 Topology

```
        ┌──────────────────────── Org A ────────────────────────┐      ┌──────────── Org B ────────────┐
        │                                                       │      │                               │
        │   ┌──────────────┐  s2s federation (mTLS, signed      │      │        ┌──────────────┐       │
        │   │ Rendezvous A │◄────── envelopes) ─────────────────┼──────┼───────►│ Rendezvous B │       │
        │   └──────┬───────┘                                    │      │        └──────┬───────┘       │
        │          │ WSS (client signaling,                     │      │               │ WSS           │
        │          │ prekey fetch, mailbox)                     │      │               │               │
        │   ┌──────┴──────┐        ┌──────────┐                 │      │        ┌──────┴──────┐        │
        │   │  Alice's    │        │ TURN A   │                 │      │        │   Bob's     │        │
        │   │  clients    │───────►│ (coturn) │                 │      │        │   clients   │        │
        │   └──────┬──────┘  alloc └────┬─────┘                 │      │        └──────┬──────┘        │
        │          │                    │                       │      │               │               │
        └──────────┼────────────────────┼───────────────────────┘      └───────────────┼───────────────┘
                   │                    │                                              │
                   │            ══════════════════ E2E-encrypted media/data ═══════════│
                   └────────────════ (direct P2P when possible; via TURN A and/or ═════┘
                                ══════════════════ TURN B when NATs force it) ══════════
```

Control plane (thin lines): client↔rendezvous over WSS; rendezvous↔rendezvous over mTLS. Data plane (double lines): peer↔peer WebRTC — DTLS-SRTP media plus SCTP data channels — which never transits a rendezvous server and transits TURN only as an opaque ciphertext relay.

### 2.3 Responsibility boundaries (the "cannot" list)

| Component | Can | Cannot (by construction) |
|---|---|---|
| Rendezvous | route envelopes, store prekeys/ciphertext mailbox, deny service, observe who-signals-whom & timing | read/forge content; substitute keys undetectably; enumerate users w/o full IDs; see media/data traffic at all |
| TURN | relay packets, observe flow metadata (IPs, volume, timing) of relayed sessions | read content (sees DTLS/SRTP ciphertext); correlate flows to identities without rendezvous collusion |
| Client core | everything cryptographic | trust any server assertion about keys |

---

## 3. Identity, discovery & federation — the crux

### 3.1 What the shareable ID actually is

A user's canonical identity is an **Ed25519 identity public key** (the *account key*). The shareable ID is a compact, self-certifying string that binds that key to a *routing hint*:

```
mrd1:<base32(multicodec ‖ account-pubkey ‖ 4-byte checksum)>@<home-domain>

e.g.  mrd1:kq3f7…x9dm@chat.org-a.example
```

Two parts, deliberately separable:

- **The key part is the identity.** It is globally unique, unforgeable, and independent of any server. Two IDs with the same key part are the same principal even if the domain differs. All authentication, verification, and safety numbers derive from the key alone.
- **The `@home-domain` part is a hint, not a name.** It answers exactly one question — "which rendezvous server currently agrees to route envelopes and store prekeys for this key?" — and it is *advisory*. A stale hint degrades reachability, never security. Users can migrate home servers by re-registering the same key elsewhere and handing out an updated ID; old sessions keep working because sessions are bound to keys, not domains.

This is essentially the `did:key` + service-endpoint pattern, flattened into one copy-pasteable string. QR codes carry the same payload plus an optional display name (which is *never* authoritative — names are local petnames assigned by the receiving user; see §3.5 on impersonation).

Rejected shapes, briefly: **server-assigned usernames** (`alice@org-a`) put the server back in the trust anchor position — the server could remap the name to its own key, which is exactly the MITM we must survive; **pure key with no hint** forces a global lookup system (DHT) into the critical path, which fails air-gapped enterprises. The hybrid keeps the security of the former's absence and the routability of the latter's presence. ADR-1 formalizes this.

### 3.2 Registration and prekey publication

On first run, a client generates the account key inside the OS keystore where possible, then registers with its (org-configured or user-chosen) rendezvous server by signing a challenge. It uploads: a **signed prekey bundle** (X25519 signed prekey + a batch of one-time prekeys, all signed by the account key — X3DH-style) and a **signed device record** (per-device subkeys; §4.5). The server stores these against the account pubkey. Note what registration does *not* involve: no email, no phone number, no server-chosen identifier. An org MAY gate registration behind its IdP (OIDC) purely as an *admission* control — "may this key register here" — without that IdP identity entering the protocol (§9.2).

### 3.3 Cross-server rendezvous with no central directory

The flow when Alice (`…@chat.org-a`) contacts Bob (`…@chat.org-b`):

1. Alice's client parses Bob's ID → key `K_B`, hint `chat.org-b`.
2. Alice's client asks *her own* rendezvous server (A) to federate a **prekey fetch** and subsequent **signaling envelopes** to `chat.org-b` for `K_B`. (Clients never talk to foreign servers directly — this keeps the client trust surface to one server, simplifies air-gapped egress rules, and lets Org A apply outbound policy.)
3. Server A dials `chat.org-b` — discovered via DNS SRV `_meridian-fed._tcp.chat.org-b` (or a static federation map in air-gapped mode) — over **mTLS**, and forwards Alice's request. Server-to-server authentication uses TLS certs (WebPKI or a federation-private CA); this authenticates *servers to each other* for routing/anti-abuse purposes only. It contributes nothing to end-to-end security, which is carried entirely by the fact that Alice will verify everything she receives against `K_B`, and Bob verifies Alice's envelopes against `K_A` embedded in them.
4. Server B returns Bob's prekey bundle; Alice's client verifies the bundle's signature under `K_B` **before** using it. A malicious server (A or B) that substitutes keys produces a bundle that fails this check → hard failure, not downgrade. The only remaining MITM shape is "server B replaces Bob entirely, prekeys and all, under a *different* key" — which fails because Alice addressed `K_B` specifically, and the fetch protocol requires the bundle be signed by the exact requested key.
5. X3DH runs, an initial signaling envelope (containing Alice's identity key, ephemeral, and an encrypted SDP offer) flows A→B→Bob, and the WebRTC dance proceeds (§7.1).

**Why federated signaling rather than a DHT** for the primary mechanism: a Kademlia-style DHT gives true directory-less lookup but imports Sybil/eclipse attacks against *availability*, node churn on mobile, hostile fit with air-gapped enterprises (a two-org private DHT is just a complicated static map), and it broadcasts lookup metadata to strangers. Federated signaling matches the deployment reality (orgs already run the servers), keeps metadata within the two involved orgs, and is operable by a small team. However — and this matters — the ID format is *transport-agnostic*: because identity is the key and the domain is only a hint, a **DHT/PKARR-based resolver can be added later as an alternate hint-resolution and envelope-transport mechanism** for the consumer/no-home-server case, without changing IDs, crypto, or clients' verification logic. That optionality is the payoff of ADR-1, and it is scheduled as Phase 4, not hand-waved into v1. ADR-2 compares the options in full.

### 3.4 Presence and reachability

Rendezvous servers exchange *per-request* reachability ("is a device for K_B connected right now?") rather than subscription-based presence feeds across the federation boundary — presence fan-out is a notorious metadata amplifier. Within an org, presence is available to authorized contacts only, computed at the server edge from live WebSocket state, never persisted.

### 3.5 Impersonation, enumeration, spam

**Impersonation.** Nothing a server does can make a client accept the wrong key: sessions are addressed *to keys*, bundles are verified *against keys*, and envelopes are signed *by keys*. The residual risk is human-layer: an attacker hands you an ID and claims to be "Dana from finance." Mitigations: safety-number verification (§4.4) with QR flow for in-person/video verification; TOFU pinning with loud, blocking alerts on key change; org-level **directory attestations** — an enterprise MAY run an internal signed directory mapping HR identities → account keys, which clients treat as a *petname source with provenance*, not as a key authority (a wrong directory entry is detectable by the victim, whose client knows its own key).

**Enumeration.** Account identifiers are 256-bit keys — unguessable, so there is no namespace to walk. The federation API only answers queries for *exact, full* IDs (no prefix/search across orgs), rate-limits per requesting server and per requesting account, and can require the requester to present a **contact token** — a short-lived object signed by the target (or by the target's org for intra-federation openness) proving the requester was *given* the ID rather than mining it. One-time prekey depletion (a classic quiet enumeration/DoS channel) is bounded per-source and falls back to the signed prekey, which weakens only the vestigial deniability of the first message, not confidentiality.

**Spam / unsolicited contact.** Possession of a full ID is itself a capability (you can't spam who you can't name). Beyond that: first-contact envelopes are delivered to a segregated "message request" state — the recipient sees the sender's key/safety-number and a short encrypted intro before any further envelopes are accepted; per-account and per-origin-server rate limits at the federation edge; org policy hooks (allowlist federation partners, require contact tokens from unknown origins, optional proof-of-work stamp on first-contact envelopes for open deployments). Tension acknowledged: the more anti-spam friction, the less "hand your ID to anyone and they can reach you" — we resolve it by making the *default* permissive-with-request-queue and every restriction an org/user policy, never a protocol requirement.

---

## 4. Cryptographic architecture

Principle: no bespoke constructions. Everything below is Signal-protocol-family or IETF-standardized, via audited implementations (libsignal, or ring/libsodium + OpenMLS).

### 4.1 Key hierarchy

```
Account identity key (Ed25519, long-lived, in OS keystore/secure enclave where available)
 ├─ signs → Device subkeys (per device: Ed25519 sig key + X25519 DH key), in a signed,
 │           versioned device record published to the home rendezvous
 ├─ signs → Signed prekey (X25519, rotated ~weekly) + batches of one-time prekeys
 └─ derives → Safety number (with peer's account key)
Per-session: X3DH → root key → Double Ratchet chains (per peer-device pair)
Per-stream:  keys exported/derived from the session (media via DTLS-SRTP; app-layer AEAD for
             data channels; per-file keys for transfers)
```

### 4.2 Session establishment — X3DH (with a PQ note)

Initial key agreement is **X3DH** against the fetched, verified prekey bundle: DH(IK_A, SPK_B) ‖ DH(EK_A, IK_B) ‖ DH(EK_A, SPK_B) [‖ DH(EK_A, OPK_B)] → HKDF → root key. It provides mutual (deferred) authentication, forward secrecy from message one, and works asynchronously — Bob can be offline when Alice initiates, which the ciphertext mailbox (ADR-7) exploits.

*Post-quantum:* the design allocates a slot for **PQXDH-style hybrid** (adding an ML-KEM/Kyber encapsulation against a signed KEM prekey, KDF'd together with the classical DHs) as a bundle-format version bump. It is not in v1 scope — the operational story (bundle sizes, library maturity in our FFI matrix) needs its own evaluation — but the bundle format is versioned from day one specifically so this lands without a migration event. Harvest-now-decrypt-later is the realistic PQ threat here, so this is scheduled early in Phase 2, and stated as a known limitation until then (§10).

### 4.3 Message protection — Double Ratchet, applied *inside* the transport

All data-channel payloads (chat, file chunks' content keys, location, control messages, Tier-2 stream setup) are encrypted with **Double Ratchet** (X25519 DH ratchet + KDF chains, AEAD = XChaCha20-Poly1305 or AES-256-GCM) **at the application layer, in addition to the DTLS transport encryption underneath**. This double encryption is deliberate, not redundant paranoia:

1. DTLS protects the *pipe*; the ratchet protects the *messages* — giving FS/PCS at message granularity, which DTLS's session-scoped keys do not.
2. It makes the security of content independent of the transport path — the same ciphertext can traverse a data channel, the offline mailbox, or a future non-WebRTC transport, unchanged. This is what lets the mailbox exist without violating requirement 1.
3. It authenticates *the peer's account/device keys*, not just a DTLS certificate, and preserves deniability (MACs, not signatures, on message contents).

Header encryption (Double Ratchet's encrypted headers variant) is enabled so even ratchet public keys/counters are hidden from anything that ever stores an envelope.

### 4.4 Verification — safety numbers

The safety number is a 60-digit (or QR) fingerprint derived from `SHA-512(version ‖ sorted(IK_A, IK_B) ‖ …)` iterated per Signal's construction — identical semantics: compare out-of-band, mark verified, and *block-by-default* on key change for verified contacts (org-configurable to warn-only for unverified). This is the human-verifiable backstop that makes even a fully malicious dual-server MITM (A2×2) detectable, and it is the reason we can honestly claim goal #2 in §1.2.

### 4.5 Multi-device

Chosen model (ADR-5): **account key signs device subkeys; sessions are per device-pair** (Sesame-style). The device record — an append-only, versioned, account-signed list of device pubkeys with add/revoke entries — lives on the home rendezvous; peers fetch and verify it under the account key, so the server cannot invisibly add a "ghost device" (any device addition changes the record hash, and clients surface device-list changes on verified contacts exactly like key changes). Sending a message means encrypting to each of the peer's active devices (and one's own other devices) under their pairwise ratchets. Linking a new device uses a QR-mediated provisioning handshake where the *existing* device transfers a signed delegation and (optionally, encrypted) history — the account private key never transits the server. Cost accepted: N×M ratchet fan-out for 1:1 chats; this is Signal's production-proven trade and is cheap at 1:1 scale. Group scale changes the calculus, which is precisely why groups get MLS (ADR-4).

### 4.6 Media encryption — DTLS-SRTP, with the group caveat named

For **1:1** calls, screenshare, and P2P data channels, WebRTC's mandatory **DTLS-SRTP** *is* end-to-end — there is no middlebox to terminate it; TURN relays see only ciphertext. The known weakness is that DTLS authenticates *certificate fingerprints carried in SDP*, and SDP transits the signaling path — so a malicious rendezvous could try to substitute fingerprints. We close this by carrying the SDP **inside ratchet-encrypted, identity-authenticated envelopes** (the server routes opaque blobs; it never sees or edits SDP) and additionally cross-checking the negotiated DTLS fingerprint against the one asserted in the encrypted envelope after the handshake (a mismatch tears the call down). Thus media inherits identity-bound authentication rather than trusting the signaling path.

For **future group calls via an SFU**, DTLS-SRTP alone is *not* E2E (the SFU terminates it). The design pre-commits to **SFrame/insertable-streams-style sender keys** layered inside SRTP payloads for that phase, with keys distributed over the MLS group. Named now so nobody "temporarily" ships a trusted SFU later.

### 4.7 At-rest

Local stores (ratchet state, history) are encrypted with a key held in the OS keystore (Keychain/StrongBox/TPM-DPAPI); headless/terminal clients use an age/scrypt-wrapped keyfile or PKCS#11 token. History sync between own devices rides the same E2E channels. There is **no server-side backup** in v1; escrow-free recovery is fundamentally at odds with "no server holds user data," and we say so rather than smuggling in a recovery service (§10, §12).

---

## 5. Transport & session substrate

### 5.1 Why WebRTC (and what it costs)

WebRTC is the only transport that simultaneously: runs unmodified in browsers, carries congestion-controlled real-time A/V, provides reliable+unreliable datagram channels (SCTP), and has mature ICE/STUN/TURN NAT traversal. The costs, stated: ICE leaks IPs to the peer (mitigated by relay-only policy at a latency cost); the browser dictates the stack (no custom transports there); SCTP over DTLS underperforms QUIC for bulk transfer. ADR-6 evaluates the alternative (QUIC/WebTransport for non-browser paths) and keeps it as a Phase-4 optimization behind the same abstraction, so we are not architecturally married to WebRTC — only pragmatically.

### 5.2 Session model

A **Session** is the unit of connectivity between two *devices*: one WebRTC peer connection, established via the signaling flow of §7.1, authenticated by the ratchet-encrypted envelope exchange, carrying (a) zero or more media transceivers and (b) an SCTP association multiplexing data channels. Sessions are lazy (dialed on demand), resumable (ICE restarts on network change), and independent of message-layer state — ratchets outlive sessions, which is what makes offline delivery and transport swaps possible.

### 5.3 The stream-type abstraction (the "ultimate sharing platform" property)

Every feature above the session is a **Stream Type** — a named, versioned protocol bound to a channel. Concretely:

- **Channel 0 — `mrd.ctrl/1`:** always opened first; reliable/ordered. Carries capability advertisement (each side sends its supported stream-type registry: `{name, version, direction, requirements}`), stream open/accept/reject/close negotiation, keep-alives, and per-stream flow-control hints. All ctrl frames are ratchet-encrypted CBOR.
- **Stream open:** `OPEN{stream_id, type:"mrd.file/1", params, channel_config}` → peer's policy layer accepts/rejects (auto-accept for chat, prompt for screenshare/SSH, org policy hooks). On accept, the initiator opens a new SCTP data channel labeled with the stream id, configured per type: reliable/ordered for chat & control; reliable/unordered for file chunks; unreliable/unordered (maxRetransmits=0) for live location and game-like streams; media stream types attach RTP transceivers instead of data channels.
- **Framing:** length-prefixed CBOR envelopes; payloads sealed by the session ratchet (or, for high-rate media-adjacent streams, by per-stream keys exported from the ratchet via HKDF with the stream id as info — one ratchet step per stream setup, then fast symmetric AEAD with per-stream nonce sequences, preserving FS at stream granularity without ratcheting per packet).

Tier-1 features expressed as stream types — none of them special-cased:

| Stream type | Channel semantics | Notes |
|---|---|---|
| `mrd.chat/1` | reliable, ordered | text, receipts, typing, reactions; also the offline-mailbox payload format |
| `mrd.file/1` | reliable, unordered | manifest (name, size, BLAKE3 merkle root, per-file key) sent on ctrl; chunks (64 KiB) sent unordered with offsets; resume = re-request missing ranges against the merkle tree; backpressure via `bufferedAmount` low-watermark |
| `mrd.call.audio/1`, `.video/1` | RTP transceivers | Opus / VP9-or-AV1; DTLS-SRTP per §4.6 |
| `mrd.screen/1` | RTP video transceiver | content-hint "detail"; per-monitor/window params in OPEN |
| `mrd.location/1` | unreliable stream (live) or chat message (static) | live mode sends deltas at ≤1 Hz, auto-expiring grant |
| `mrd.sticker/1` | chat message referencing pack | packs are content-addressed bundles (BLAKE3 root = pack id) signed by the pack author's key; fetched P2P from the sender via `mrd.file/1`, cached locally; org "sticker registries" are just ordinary accounts publishing signed pack manifests — pluggability without a server-side media store |

Tier-2 rides identically: `mrd.tunnel.tcp/1` maps one TCP connection ↔ one reliable-ordered data channel with a tiny connect header (`host:port` against a recipient-side policy allowlist); **SSH-over-P2P** is `ssh` pointed at a local socket the client bridges into such a stream (double encryption accepted — SSH's own crypto is retained deliberately so the tunnel adds reach, not trust); **FTP-over-P2P** is better served by a native `mrd.fs/1` stream (list/stat/get/put verbs over CBOR reusing `mrd.file/1` chunking) than by literally proxying FTP's two-connection legacy — we provide the TCP tunnel for compatibility and `mrd.fs/1` as the recommended path. A third-party feature is: a registered type name, a schema, a channel config, and a policy descriptor — nothing else in the stack changes. That is the architectural property requested.

### 5.4 NAT traversal

Full ICE: host + server-reflexive (STUN) + relay (TURN/UDP, TURN/TCP, TURN/TLS-443 as the last resort for hostile egress). TURN credentials are ephemeral HMAC tokens minted by the rendezvous per session — no static TURN secrets in clients. **Policy knob (per user/contact/org): `direct | prefer-relay | relay-only`** — the explicit resolution of the P2P-latency vs. IP-privacy tension: `relay-only` strips host/srflx candidates so peers never learn each other's addresses, at the price of relay latency and concentrating flow metadata on the org TURN (which, in an enterprise, is often the *desired* audit point — one adversary's leak is another's compliance feature; we surface it as a labeled choice rather than deciding for the org). In federated calls each side may use its own org's TURN (TURN-to-TURN paths work; expect double-relay latency).

---

## 6. Per-platform client strategy

**One Rust core, thin native shells.** `meridian-core` (identity, keystore abstraction, ratchets, sessions, stream registry, file engine, signaling client, local encrypted store) compiles to: native cdylib/staticlib with UniFFI bindings (Kotlin/Swift/C#), and WASM for the browser. The core defines two traits that shims implement: `Transport` (create peer connection, channels, tracks) and `SecretStore`.

- **Browser:** core as WASM; `Transport` backed by the browser's native WebRTC via wasm-bindgen (browser policy forbids any other stack — this is why `Transport` is a trait); IndexedDB (encrypted blobs) for storage; WebCrypto/CryptoKey where non-extractable keys help. Honest caveat: a web app is only as trustworthy as its served JS — enterprises should prefer the desktop build or serve the web client from their own audited origin; we do not claim web-served code matches signed-release guarantees.
- **Windows desktop (and macOS/Linux):** Tauri shell (webview UI, Rust backend = the core in-process) — chosen over Electron for footprint and because the core is already Rust; `Transport` = **libdatachannel** (or webrtc-rs; ADR-6) for data + libwebrtc via bindings where full media stacks are needed; DPAPI/TPM-backed `SecretStore`.
- **iOS/Android:** native UI (SwiftUI/Compose) over UniFFI bindings; media via the platform's WebRTC (Google's libwebrtc builds — the pragmatic choice for hardware codec/CallKit/ConnectionService integration); Keychain-SecureEnclave / Keystore-StrongBox. Push: a **content-free wake ping** ("connect to your rendezvous") via APNs/FCM — the notification never carries even ciphertext; air-gapped Android deployments can substitute a persistent WebSocket foreground service since APNs/FCM are unreachable there anyway (named limitation for air-gapped iOS: no APNs means no push wake — polling/foreground only).
- **Terminal/headless — the interesting one:** the same Rust core in a `meridian-cli` binary. WebRTC *without a browser* is well-trodden: **webrtc-rs** (pure Rust, data channels + ICE, fits the core natively) or **libdatachannel** (C++, lighter, excellent SCTP/ICE, prebuilt everywhere) — either gives the terminal client *identical* wire behavior to browsers, because WebRTC is a protocol suite, not a browser feature. Data-channel features (chat, files, location, tunnels, `mrd.fs`) work fully in TUI (ratatui) and in `--json` headless mode for scripting; voice is feasible (Opus + cpal audio I/O); video *rendering* is out of scope for a terminal, but the client can still send/receive-and-save tracks. Crucially, the terminal client is where SSH/FTP tunneling shines: `meridian tunnel ssh mrd1:…@org-b` forwards a local port over the encrypted P2P substrate — a headless server with the CLI becomes reachable through NATs with identity-based addressing and no inbound firewall holes.

---

## 7. Key data-flow walkthroughs

### 7.1 (a) 1:1 session setup across two signaling servers

```
Alice(dev A1)      Rendezvous A            Rendezvous B         Bob(dev B1)
   │ 1. lookup mrd1:K_B@chat.org-b              │                    │
   ├───────────────►│ 2. mTLS dial (DNS SRV or  │                    │
   │                │    static fed map)        │                    │
   │                ├──────────────────────────►│ 3. fetch prekey    │
   │                │                           │    bundle(K_B),    │
   │                │◄──────────────────────────┤    device record   │
   │ 4. bundle + device record                  │                    │
   │◄───────────────┤   — client VERIFIES sigs under K_B; mismatch ⇒ ABORT
   │ 5. X3DH → root key; init Double Ratchet (per B-device)          │
   │ 6. Envelope₁ = Sign_{K_A}( ratchet-encrypted { X3DH init, SDP offer,
   │        DTLS fingerprint, ICE candidates (trickled) } )          │
   ├───────────────►│ 7. route (opaque) ───────►│ 8. deliver (or     │
   │                │                           │    mailbox if      │
   │                │                           │    offline) ──────►│
   │                │                           │   9. Bob verifies K_A sig,
   │                │                           │      completes X3DH, decrypts
   │                │                           │      offer; message-request
   │                │                           │      gate if first contact
   │  11. answer envelope (same wrapping), then trickled ICE both ways
   │◄───────────────┼───────────────────────────┼────────────────────┤
   │ 12. ICE connectivity checks (direct pairs; TURN-A/TURN-B pairs) │
   │ 13. DTLS handshake; BOTH sides check negotiated fingerprint ==  │
   │     fingerprint from encrypted envelope; mismatch ⇒ teardown    │
   │ 14. ctrl channel opens; capability exchange; session live       │
   ╞═══════════════ E2E data/media, servers out of path ═════════════╡
```

The two properties to notice: every server-visible object is an opaque signed blob (servers route, never read or mint), and both the *bundle path* (step 4) and the *transport path* (step 13) are pinned to identity keys, so a malicious server anywhere yields abort, not downgrade.

### 7.2 (b) File transfer

Sender: generate per-file key `k_f`; chunk (64 KiB); build BLAKE3 merkle tree; send `mrd.file/1` OPEN on ctrl with manifest `{name, size, root, enc(k_f under ratchet)}` → recipient policy accepts → sender streams AEAD-sealed chunks (key `k_f`, nonce = chunk index) on a reliable-unordered channel, throttled by `bufferedAmount` watermarks; recipient writes by offset, verifies subtrees incrementally, ACKs ranges on ctrl; on disconnect, session redial + recipient sends missing-range bitmap → resume. Integrity = merkle root check; the per-file key means the *same ciphertext* can later be offered to other authorized peers (dedup/reshare) without re-encryption while remaining bound to an explicit key grant per recipient.

### 7.3 (c) Video call with relay fallback

Caller sends `mrd.call.video/1` OPEN (ring) over the *existing* signaling path even if no session is live (envelopes work offline-to-online); callee accepts → SDP renegotiation adds Opus/AV1 transceivers. ICE gathers host/srflx/relay; suppose both sides sit behind symmetric NATs: direct and srflx pairs fail connectivity checks, the TURN-relayed pair succeeds (caller's TURN-A allocation ↔ callee, or TURN-A↔TURN-B), and media flows as SRTP ciphertext through the relay — the TURN server can meter it but not decrypt it. Mid-call network change (Wi-Fi→LTE) triggers ICE restart within the session; the ratchet and call state persist across it. If policy is `relay-only`, host/srflx candidates were never offered and the call starts on the relay path directly, trading ~20–80 ms for IP privacy.

---


## 8. Architectural Decision Records

> Extracted into numbered ADRs under **[docs/adr/](../adr/README.md)**. The eight core decisions
> from this design (identity scheme, federation, E2EE protocol, group messaging, multi-device,
> terminal transport, offline delivery, infra topology) are ADRs 0001–0008; the five stack/repo
> decisions are ADRs 0009–0013. The [architect](../../.claude/agents/architect.md) subagent guards
> changes against these records.

## 9. Self-hosting & operations

### 9.1 What an org deploys

Two containers plus a database: `meridian-rendezvous` (single Rust binary; Postgres or embedded SQLite for prekeys/device records/mailbox/federation map), `coturn`, and TLS certs. Reference deploys: docker-compose (small org) and a Helm chart (K8s). Resource envelope: rendezvous is WebSocket fan-in + blob routing — a 2-vCPU node comfortably serves thousands of users; TURN sizing is bandwidth-bound (relayed calls ≈ 100–300 kbps audio / 1–3 Mbps video per leg) and is the only component with real capacity planning.

### 9.2 Config surface (deliberately small)

Domain + certs; federation policy (`open | allowlist | closed`) and the static federation map (air-gapped) or SRV (connected); registration admission (open, invite-token, or OIDC-gated per §3.2); mailbox TTL/quota; TURN secret + bandwidth caps; connection policy defaults (`direct|prefer-relay|relay-only`); rate-limit knobs. Everything else is client-side.

### 9.3 Air-gapped operation

Fully supported by construction: internal DNS + private CA for client-server and federation mTLS; static federation map instead of SRV; internal STUN/TURN only (clients accept an org-pushed ICE-server list, and in air-gapped mode the public-STUN default is disabled); no APNs/FCM → Android foreground-service wake, iOS foreground-only (named limitation); client updates via the org's artifact mirror with our release signatures verified offline. Nothing in the protocol phones home; there is no license server, telemetry endpoint, or key registry outside the org.

### 9.4 Observability without breaking E2EE

Exported (Prometheus): connection counts, envelope routing rates/latencies, mailbox depth/age, prekey pool levels (a real operational signal — depletion breaks first contact), federation link health, TURN allocations/bandwidth. Never exported: envelope contents (opaque by construction), contact-graph materializations, message sizes at per-user granularity (bucketed only). Logs are metadata-minimizing by default (hashed account keys with a per-deploy salt, short retention) with an org override — we document, rather than hide, that an org *can* log its own routing metadata (A1/A7 is in the threat model precisely because of this): the design's promise is that even that org reads no content and forges no identity. Client distribution is the one trust channel ops must keep out of the admins' hands alone: reproducible builds, signatures verified by the updater, and (for the web client) an audited serving origin.

---

## 10. Failure modes, mitigations, known limitations

**Failure modes → mitigations.** Home rendezvous down → outbound to other orgs still works via the *sender's* server? No — envelopes to K_B route via B's hint; mitigation: multi-hint IDs (Phase 3) and client retry with jittered backoff; existing live P2P sessions are unaffected (servers are out of the data path). Both peers behind symmetric NAT + no TURN reachable → session fails; mitigation: TURN/TLS-443 last-resort transport, and clear diagnostics (`meridian doctor`) that name the blocked path. Prekey depletion (targeted) → signed-prekey fallback (weakened first-message deniability, not confidentiality) + per-source issuance limits + operator alert. Clock skew breaking prekey/token validity windows → generous windows, server-supplied time hints (authenticated, advisory). Device loss without another linked device → **identity is unrecoverable by design** (no escrow); contacts see a key change and must re-verify — painful, honest, documented; optional user-managed encrypted key backup (age-encrypted file the user stores themselves) is the only softening we offer. Malicious federation partner → bilateral: rate limits, contact-token requirements, allowlist ejection; blast radius is spam/DoS, never content or impersonation. TURN compromise → metadata of relayed flows leaks (IPs, timing, volume); content safe; rotate HMAC secret. Ratchet state desync (restored backup) → sessions fail closed; automatic re-handshake via fresh X3DH with a user-visible notice.

**Known limitations, stated plainly:** (1) metadata per §1.3 — who-talks-to-whom is visible to the involved orgs' servers, and IPs to peers in `direct` mode; (2) offline delivery holds ciphertext server-side (ADR-7) — TTL-bounded, but it exists; (3) no PQ protection until the PQXDH bump lands — harvest-now-decrypt-later applies to v1 traffic; (4) browsers can't pin the app the way binaries can; (5) group properties (Phase ≥2) are weaker than 1:1 until MLS lands, and group *metadata* stays weaker after; (6) air-gapped iOS has no push; (7) deniability is weak-Signal-grade, not OTR-court-grade, and sealed-sender-style sender hiding from the *recipient's own server* is partial in v1.

---

## 11. Phased roadmap

**Phase 0 — Substrate (the risk burn-down):** meridian-core (identity, X3DH+Double Ratchet via audited lib, ctrl channel, `mrd.chat/1`), single-org rendezvous, CLI + one desktop client, direct+TURN ICE. Exit criterion: two CLIs on hostile NATs exchange verified, ratcheted messages via one org's stack.
**Phase 1 — Federation & Tier-1 core:** s2s mTLS federation (SRV + static map), ciphertext mailbox, `mrd.file/1`, voice/video/screenshare on 1:1 DTLS-SRTP with fingerprint-in-envelope binding, safety-number UX, browser + mobile clients. Exit: the §7.1 cross-org walkthrough works end-to-end on all five platforms.
**Phase 2 — Identity depth:** multi-device (device records, provisioning, fan-out), pairwise small groups (hard cap ~15), location + stickers, PQXDH bundle bump, message-request/anti-spam surface, ops hardening (Helm, dashboards, `doctor`).
**Phase 3 — Scale & privacy:** MLS groups on OpenMLS with rendezvous-as-DS commit log, mailbox padding/batching, multi-hint IDs, relay-only polish, sealed-sender-style envelope wrapping.
**Phase 4 — Reach:** `mrd.tunnel.tcp/1` + `mrd.fs/1` (SSH/FTP tier), QUIC transport negotiation for non-browser pairs, optional PKARR/DHT hint-resolution for server-less consumer mode, group calls (SFU + SFrame over MLS keys).

Sequencing rationale: everything trust-critical (identity, federation, verification) ships before anything convenient; Tier-2 waits because the stream abstraction (Phase 0) already guarantees it's additive.

---

## 12. Open questions & assumptions made

1. **Metadata ambition:** is org-bounded metadata (chosen) sufficient, or do any deployments require hiding who-talks-to-whom *from their own org*? That demands sealed-sender + padding at minimum, mixnet/Tor integration at maximum — a different cost tier; needs a stakeholder decision before Phase 3 scoping.
2. **Recovery vs. escrow:** we chose unrecoverable identity over any server-side backup. Enterprises often demand escrow/compliance export; if that requirement appears, it must be an *explicit org-visible client feature* (e.g., org-key as an additional recipient device, loudly indicated to all parties), never a server capability — flagging now because retrofitting it quietly would betray the design.
3. **libwebrtc vs. pure-Rust media** on desktop: prototype both in Phase 1; the answer decides ~30% of build-system pain.
4. **MLS Delivery Service semantics** on a federated rendezvous (which org sequences commits for a cross-org group?) — needs a design spike before Phase 3; candidate: the group creator's org, recorded in the signed group manifest.
5. **Abuse economics of open federation** (contact tokens vs. PoW vs. request-queue-only) — tune with real traffic in Phase 2.
6. Assumed: federating orgs have IP reachability between rendezvous servers; a store-and-forward "bridge" for orgs that can only exchange data diode-style is out of scope.
7. Assumed: regulatory constraints (lawful intercept, data residency) are handled at the deployment layer (where servers run, what they log) — the protocol offers no intercept capability, and we should confirm early that no target market makes that untenable.

---

*End of design document.*
