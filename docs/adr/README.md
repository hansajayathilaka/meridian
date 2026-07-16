# Architecture Decision Records

Numbered, immutable-once-accepted decisions. ADRs 0001–0008 are the core protocol/architecture
decisions (extracted from the [system design](../architecture/system-design.md) §8); ADRs 0009–0013
are the stack/repo decisions (extracted from [stack](../architecture/stack.md) §6). The
[architect](../../.claude/agents/architect.md) subagent guards proposed changes against these.

| ADR | Decision | Source |
|-----|----------|--------|
| [0001](./0001-identity-scheme.md) | Self-certifying key + routing-hint identity | design §8 |
| [0002](./0002-federation-mechanism.md) | Server-to-server signaling over mTLS; DHT deferred | design §8 |
| [0003](./0003-e2ee-protocol.md) | X3DH + Double Ratchet at the application layer | design §8 |
| [0004](./0004-group-messaging.md) | Pairwise fan-out first, MLS as target group protocol | design §8 |
| [0005](./0005-multi-device.md) | Account-signed device subkeys, per-device sessions | design §8 |
| [0006](./0006-terminal-transport.md) | Native WebRTC (webrtc-rs/libdatachannel); QUIC deferred | design §8 |
| [0007](./0007-offline-mailbox.md) | Bounded ciphertext mailbox on home rendezvous | design §8 |
| [0008](./0008-infra-topology.md) | Per-org rendezvous+TURN pair, no shared global tier | design §8 |
| [0009](./0009-monorepo-tooling.md) | Native toolchains + thin task runner (no Bazel) | stack §6 |
| [0010](./0010-desktop-shell-tauri.md) | Tauri v2 for desktop (not Electron, not native-per-OS) | stack §6 |
| [0011](./0011-ratchet-library.md) | Ratchet lib: hand-wired X3DH (Accepted); Double Ratchet mechanism **superseded by 0015** | stack §6 |
| [0012](./0012-browser-ui-framework.md) | SvelteKit (React fallback) | stack §6 |
| [0013](./0013-server-web-framework.md) | axum server framework | stack §6 |
| [0014](./0014-media-stack.md) | Media: **libwebrtc for media, webrtc-rs for data** (Accepted) | design §12 |
| [0015](./0015-ratchet-composition.md) | Double Ratchet composed in `meridian-crypto` from RustCrypto primitives (Accepted; supersedes 0011's ratchet mechanism) | T03 spike |

**Previously-open decisions, now resolved at handoff:** [0011 ratchet library](./0011-ratchet-library.md)
X3DH layer → hand-wired over RustCrypto primitives (unchanged); Double Ratchet mechanism → composed
in-house, see [0015](./0015-ratchet-composition.md) (the `ratchet-header-enc` spike found vodozemac
0.10 could not seed from an external X3DH root key, use the frozen `v:1` bundle, or expose header
encryption); media stack → [0014](./0014-media-stack.md). Remaining *implementation* spike (not
architecture) tracked via the [/spike](../../.claude/commands/spike.md) command: libwebrtc packaging.