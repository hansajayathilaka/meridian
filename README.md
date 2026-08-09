# Meridian

A decentralized, end-to-end-encrypted, cross-platform communication platform. Self-hostable
signaling (rendezvous) and relay (TURN) infrastructure exists only to help peers discover and reach
each other; **no server ever sees plaintext content**. A shareable, key-derived identity
(`mrd1:…@domain`) lets users on different orgs' servers reach each other with no central directory —
your org runs its own server, peers connect P2P wherever possible, and messages fall back to an
opaque, signed relay only when they must.

The goal is a single Rust core (`meridian-core`) compiled to five targets — terminal, browser/WASM,
desktop, Android, iOS — so identity, crypto, and session logic are implemented and audited **once**.
See [docs/architecture/system-design.md](./docs/architecture/system-design.md) for the full design
and [docs/architecture/roadmap.md](./docs/architecture/roadmap.md) for the complete feature list
(16 features, of which 6 are built today — see below).

## Status

> Not a scaffold anymore: identity, E2EE messaging, P2P sessions, NAT traversal, and cross-org
> federation are implemented, tested, and demoable end to end. What's *not* here yet: offline
> mailbox, verified-contact/safety-number UX, file transfer, calls, browser/desktop/mobile clients,
> multi-device, and the self-hosting ops kit — see the roadmap table below.

**Built and working** ([docs/tasks/README.md](./docs/tasks/README.md) tracks delivery phase by
phase; Phases 0–2 below are done, Phase 3 is an in-progress hardening review of Phase 2):

| Feature | What you can do today |
|---|---|
| [01 — Identity & Keystore](./docs/architecture/features/01-identity-keystore-core.md) | Mint/parse/verify `mrd1:` IDs, OS-keychain or passphrase-file storage, QR export |
| [02 — Rendezvous Server](./docs/architecture/features/02-rendezvous-mvp.md) | Register, publish prekey bundles, fetch a peer's verified bundle (tamper detection built in) |
| [03 — E2EE Messaging (relayed)](./docs/architecture/features/03-e2ee-messaging-relayed.md) | X3DH + Double Ratchet chat through the server, which sees only opaque envelopes |
| [04 — P2P Session Substrate](./docs/architecture/features/04-p2p-session-substrate.md) | Chat moves to a direct WebRTC data channel; keeps going if the server goes down |
| [05 — NAT Traversal & Relay Policy](./docs/architecture/features/05-nat-traversal-relay-policy.md) | ICE across NATs, TURN relay fallback, `direct \| prefer-relay \| relay-only` policy |
| [06 — Cross-Org Federation](./docs/architecture/features/06-cross-org-federation.md) | Two independent orgs' servers federate over mTLS; peers on different servers chat with no shared directory |

**On the roadmap, not yet built:** offline ciphertext mailbox, verification & safety-number trust
UX, file transfer, voice/video/screenshare, browser & desktop clients, mobile clients, multi-device,
self-hosting ops kit, location/stickers, tier-2 tunnels — the full dependency-ordered list is in
[docs/architecture/roadmap.md](./docs/architecture/roadmap.md).

**Honest limits today:** TLS termination for the client-facing listener is a build/proxy concern
(demos below use plaintext `ws://` on localhost, per [ADR 0008](./docs/adr/0008-infra-topology.md));
the 5k-concurrent-connection capacity target is exercised but not yet demonstrated at scale (see
[feature 02](./docs/architecture/features/02-rendezvous-mvp.md#capacity-status-f12--task-119)); and
Meridian's privacy model is pseudonymity + E2EE + optional relay-only IP-hiding — **not Tor-grade
anonymity** (see [Security posture](#security-posture-read-before-contributing) below).

## Try it yourself

These use the CLI (`meridian`), the **reference client and demo driver** — every feature above ships
with a runnable demo here first. All commands assume you're in the repo root; build once with
`cargo build --workspace` (or use the [devcontainer](#development-environment-devcontainer), which
does this for you) and either prefix commands with `cargo run --bin meridian --` / `cargo run -p
meridian-rendezvous --`, or use the built binaries directly (`target/debug/meridian`,
`target/debug/meridian-rendezvous`).

### 1. Mint an identity — no server needed
```sh
meridian id new --store file --out alice.key --hint chat.example
# → Created mrd1:kq3f…x9dm@chat.example
meridian id show --qr                 # scannable QR in the terminal
echo "hello" > m.txt && meridian id sign m.txt > m.sig
meridian id verify m.txt m.sig mrd1:kq3f…x9dm@chat.example   # → OK
```

### 2. Two people, one server, real E2EE chat
Start a local rendezvous server (plaintext `ws://` for local dev; no config file needed, defaults
apply):
```sh
meridian-rendezvous --bind 127.0.0.1:8443
```
In two more terminals (each with its own `MERIDIAN_HOME` so the identities don't collide):
```sh
MERIDIAN_HOME=./alice meridian id new --out alice.key
MERIDIAN_HOME=./alice meridian register --server ws://127.0.0.1:8443

MERIDIAN_HOME=./bob   meridian id new --out bob.key
MERIDIAN_HOME=./bob   meridian register --server ws://127.0.0.1:8443
```
Then chat — the server relays only opaque, ratcheted ciphertext:
```sh
MERIDIAN_HOME=./alice meridian chat mrd1:<bob-id>@chat.example --server ws://127.0.0.1:8443
MERIDIAN_HOME=./bob   meridian chat mrd1:<alice-id>@chat.example --server ws://127.0.0.1:8443
```
Kill the server mid-conversation (`Ctrl-C`, or `docker stop` in a container setup) — the session has
already moved to a direct P2P data channel, so chat continues uninterrupted. `meridian session info`
on either side shows the live transport, path, and RTT.

### 3. Prove no plaintext ever reaches the server
```sh
meridian demo opacity-audit ./transcript.pcapish
# → 0 plaintext leaks; N envelopes; sizes only observable field
```

### 4. Diagnose connectivity
```sh
meridian doctor      # which candidate classes work, where the path is blocked
meridian config show # effective relay policy at each scope
```

### 5. The full cross-org federation walkthrough
Two complete, independent org stacks (rendezvous + coturn + private CA each) on one machine, no
internet required once built — proves federation actually crosses the org boundary, the air-gap
story is real (not asserted), and first contact is gated with an accept/reject prompt:
```sh
just two-orgs          # static federation map (air-gap default)
just two-orgs srv      # or: real internal DNS SRV discovery
```
See [demo/two-orgs/README.md](./demo/two-orgs/README.md) for what it proves and how to poke at the
running stack (`KEEP_UP=1`).

## Documentation
Everything starts at **[docs/INDEX.md](./docs/INDEX.md)**, which maps all design documents into:
- [Architecture](./docs/architecture/README.md) — system design, stack, data model, feature specs, diagrams.
- [ADRs](./docs/adr/README.md) — the binding decisions.
- [API & protocol](./docs/api/README.md) — canonical wire format and core contracts.
- [Security](./docs/security/README.md) — threat model, threat→mitigation matrix, privacy & retention.
- [Testing](./docs/testing/README.md) — verification strategy.
- [Operations](./docs/operations/README.md) — deployment, monitoring, runbook.

Delivery itself is tracked phase by phase in [docs/tasks/README.md](./docs/tasks/README.md) — one
scannable list of what's done, in progress, and next.

## Working with Claude Code
This repo is Claude-Code-ready. Read [CLAUDE.md](./CLAUDE.md) for the project memory, then use the
slash commands and subagents under [.claude/](./.claude/). Delivery is driven by five workflow
commands (`/pick-next-phase → /plan-phase → /next-task`, and `/start-review-phase →
/plan-review-phase → /next-task` for review sweeps) documented in the
[task-tracking skill](./.claude/skills/task-tracking/SKILL.md); `/new-task` remains as a manual
per-feature escape hatch outside that flow.

## Development environment (devcontainer)
The fastest way in: open the repo in the dev container. It installs Rust + wasm target, Node/pnpm,
Tauri's Linux build deps, SQLite, chromium + mermaid-cli, and Docker-in-Docker, then verifies the
workspace and enforcement lints — no manual setup.

1. Install Docker + VS Code's **Dev Containers** extension.
2. **Reopen in Container**. When setup prints ✅, run `just build` / `just test` / `just check-docs`.

Details and the opt-in heavy toolchains (Android, libwebrtc): [.devcontainer/README.md](./.devcontainer/README.md).

## Layout
```
CLAUDE.md            root memory       .claude/     commands · agents · skills · settings
docs/                all design docs   apps/        Rust workspace: core, crypto, identity, transport,
.github/workflows/   CI (lint·test·build)           rendezvous server, CLI, web client + scoped memory
demo/                runnable acceptance demos       infra/       deploy · coturn + scoped memory
```

## Security posture (read before contributing)
Meridian provides pseudonymous key-identity, E2EE for all modalities, and **optional** relay-only
IP-hiding. It is **not** Tor-grade anonymity, and the docs are deliberately honest about what metadata
remains visible. See [docs/security/anonymity-and-retention.md](./docs/security/anonymity-and-retention.md).
