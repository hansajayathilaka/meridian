# Glossary

Shared vocabulary for Meridian. Terms are used consistently across design docs, ADRs, and code.

- **mrd1: ID** — the shareable identity string, `mrd1:<base32(key)>@<home-domain>`. The key part is the
  identity; the domain is an advisory routing hint. See [ADR 0001](./adr/0001-identity-scheme.md).
- **Rendezvous** — the signaling server (`meridian-rendezvous`): routes opaque envelopes, stores public
  prekeys, holds the ciphertext mailbox, federates. Holds no plaintext. See system design §2.
- **Relay / TURN** — coturn; relays ciphertext when direct P2P fails. See [ADR 0008](./adr/0008-infra-topology.md).
- **Envelope** — the only object servers route: a signed, ratchet-encrypted, header-encrypted blob.
  See [wire protocol](./api/wire-protocol.md).
- **X3DH** — Extended Triple Diffie-Hellman; asynchronous initial key agreement against a prekey bundle.
- **Double Ratchet** — the per-message key ratchet giving forward secrecy (FS) and post-compromise
  security (PCS). Implemented via **vodozemac** ([ADR 0011](./adr/0011-ratchet-library.md)).
- **FS / PCS** — Forward Secrecy (past messages safe after a key compromise) / Post-Compromise Security
  (the session self-heals after compromise ends).
- **Safety number** — a fingerprint over both parties' identity keys, compared out-of-band to detect
  MITM. See [verification UX](./security/verification-ux.md).
- **Prekey bundle** — signed X25519 signed-prekey + one-time prekeys, published to the rendezvous,
  enabling asynchronous X3DH.
- **Stream type** — a named, versioned protocol (`mrd.chat/1`, `mrd.file/1`, …) riding the session via
  the stream registry. See [stream-type-authoring skill](../.claude/skills/stream-type-authoring/SKILL.md).
- **DTLS-SRTP** — WebRTC's media encryption; end-to-end for 1:1, with the fingerprint bound to identity
  (design §4.6).
- **relay-only** — a connection policy that strips host/srflx ICE candidates so peers never learn each
  other's IPs, trading latency for IP privacy. See [ADR 0008](./adr/0008-infra-topology.md).
- **Home domain / hint** — the `@domain` in an ID; where a key currently agrees to be routed. Advisory,
  never a security anchor.
- **Federation** — server-to-server routing over mTLS so users on different rendezvous servers connect.
  See [ADR 0002](./adr/0002-federation-mechanism.md).
- **Mailbox** — TTL-bounded, ciphertext-only offline delivery store on the home rendezvous.
  See [ADR 0007](./adr/0007-offline-mailbox.md).
- **PQXDH** — the post-quantum hybrid slot (ML-KEM) reserved in the bundle format (design §4.2).
- **Meridian** — the project/product name used throughout these docs.
