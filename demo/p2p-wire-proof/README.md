# `demo/p2p-wire-proof/` — Docker-based wire-level proof of the core P2P claim

> **Nav:** [feature 04 spec](../../docs/architecture/features/04-p2p-session-substrate.md) ·
> [feature 05 spec](../../docs/architecture/features/05-nat-traversal-relay-policy.md) ·
> [test strategy](../../docs/testing/strategy.md) · [`tools/netns-nat-matrix.sh`](../../tools/netns-nat-matrix.sh)
> (the CI-internal netns/pcap counterpart this demo complements, not replaces)

Meridian's headline architectural claim: **a message travels directly from peer to peer; no
server ever sees it, logs it, or relays it.** Infrastructure (`meridian-rendezvous` + coturn)
only helps peers *find* each other and, when direct connectivity is impossible, relays opaque
ciphertext. This demo makes that claim checkable by anyone with Docker — not by trusting the
CLI's own self-report, but from an actual third-party packet capture running alongside the
containers.

`bash run-wire-proof.sh` brings up **one rendezvous server, one coturn TURN relay, two clients
(alice/bob), and a packet-capture sidecar** on a single docker-compose network, drives a real
`meridian session connect --transport webrtc` exchange between the two clients — first under the
default `direct` policy, then again forced through TURN via `relay-only` — and asserts, from the
capture, exactly which flows carried the session and which never saw a byte of the chat payload.

## What this proves (and what it deliberately doesn't overclaim)

- **Direct policy: the message goes client-to-client.** Real UDP/DTLS/SCTP traffic flows straight
  between alice's and bob's containers; the rendezvous is never touched again once the session is
  up (feature 04's "servers are out of the data path, demonstrably").
- **Relay-only policy: TURN carries the session, never in cleartext.** Host/srflx candidates are
  stripped *before gathering* (feature 05) — the direct alice↔bob flow is completely silent (zero
  IP packets, not just zero content), while coturn visibly carries real traffic volume. coturn
  relays DTLS ciphertext only; it never terminates it.
- **Nobody sees the plaintext chat body — not the server, not even the direct P2P leg itself.**
  This is the important nuance: Meridian is *end-to-end encrypted*, so the known-plaintext oracle
  (the literal strings `meridian session connect` sends — see "How it checks", below) is asserted
  **absent from every flow, uniformly** — rendezvous↔alice, rendezvous↔bob, alice↔bob,
  alice↔coturn, bob↔coturn. A cleartext hit anywhere would be the actual bug; the direct P2P leg
  is not a special case that's *allowed* to leak it.
- **Server-side logs also never contain it** — mirrors [`demo/two-orgs`](../two-orgs/README.md)'s
  own convention of grepping the rendezvous's own `docker compose logs`, not just the wire.
- **Honest boundary, not an overclaim:** after both phases, the script stops rendezvous + coturn
  and confirms a *third*, brand-new `session connect` attempt cannot establish. The server's real
  role is bootstrapping (ICE/SDP signaling for a session that doesn't exist yet) — this demo never
  claims "the server is needed for nothing at all", only that it never carries message content.

## Also: proof against a real, already-deployed server

Everything above runs a local Docker stack. [`run-live-server-proof.sh`](./run-live-server-proof.sh)
runs the same core proof — real `session connect`, a real packet capture, the same
known-plaintext-oracle assertions — against an **already-deployed, real rendezvous server** instead
(no Docker needed, just two client processes + the host's own `tcpdump`). See
[`LIVE-SERVER-PROOF.md`](./LIVE-SERVER-PROOF.md) for a recorded run against
`wss://rendezvous.hansajayathilaka.com`, including the detailed breakdown of every flow the
capture showed (signaling, TURN candidate probing, and the actual P2P data channel) and an honest
note on that run's same-host topology.

## Relationship to `tools/netns-nat-matrix.sh`

The project already has a CI-wired, wire-level pcap proof of nearly the same properties — see
[`docs/testing/strategy.md` §4](../../docs/testing/strategy.md#4-network-realism-nat-matrix) and
[1.27](../../docs/tasks/phase-1/1.27-pcap-assertions-ci.md). That rig uses Linux network
namespaces (not Docker containers) to simulate four NAT topologies and runs automatically in CI
when `NET_ADMIN` is available. This demo is a **separate, complementary artifact**: real Docker
containers anyone can `docker compose up` and inspect by hand, a capture-analysis sidecar that
ships with the demo instead of requiring host tooling, and (new relative to nat-matrix) an
explicit "stop the server and prove a new session can't start" boundary check. It is not wired
into CI — like `demo/two-orgs`, it's a manual, on-demand verification run (`just p2p-wire-proof`).

## Prerequisites

- Docker Engine + Compose v2 (`docker compose version`, not the standalone v1 `docker-compose`).
- A running Docker daemon.
- The Rust toolchain (the script builds `meridian-rendezvous --features sqlite` and
  `meridian-cli --features webrtc` **on the host**, then copies the two binaries into the image —
  see the Dockerfile's header for why: the root `.dockerignore` excludes `/target` from every
  other image's build context, and building the workspace *inside* the image on every run would be
  far slower than reusing the host's incremental `cargo build`).
- `openssl` (generates a fresh, random `TURN_SHARED_SECRET` per run — never committed).

## Quick start

```sh
just p2p-wire-proof
```

or directly:

```sh
cd demo/p2p-wire-proof
bash run-wire-proof.sh
```

Tears the stack down on exit (success or failure). Set `KEEP_UP=1` to leave it running afterward
for manual poking — the script prints the teardown command it would otherwise have run.

A full run takes a few minutes (mostly the host `cargo build`, which is incremental after the
first run). Expect this on a clean tree:

```
[wire-proof] === Phase A: direct policy — establishing a real P2P session ===
[wire-proof] both sides report established:true — "path":"direct"
[wire-proof] phaseA: PASS — alice<->bob direct traffic carried 234 packet(s) — confirmed real traffic on this path
[wire-proof] phaseA: PASS — alice<->bob direct traffic (plaintext check) carries zero occurrences of the chat payload
[wire-proof] phaseA: PASS — rendezvous<->alice traffic carries zero occurrences of the chat payload
[wire-proof] phaseA: PASS — rendezvous<->bob traffic carries zero occurrences of the chat payload
[wire-proof] === Phase B: relay-only policy — forcing the session through TURN ===
[wire-proof] both sides report established:true — "path":"relay"
[wire-proof] phaseB: PASS — alice<->bob direct traffic is silent (0 packets) under relay-only policy
[wire-proof] phaseB: PASS — alice<->coturn relay traffic (plaintext check) carries zero occurrences of the chat payload
[wire-proof] phaseB: PASS — bob<->coturn relay traffic (plaintext check) carries zero occurrences of the chat payload
[wire-proof] phaseB: PASS — rendezvous<->alice traffic carries zero occurrences of the chat payload
[wire-proof] phaseB: PASS — rendezvous<->bob traffic carries zero occurrences of the chat payload
[wire-proof] PASS — coturn actually carried the session (alice: 106 pkts, bob: 80 pkts), zero of it in cleartext
[wire-proof] PASS — rendezvous server logs contain zero occurrences of the chat payload
[wire-proof] === Boundary check: stopping rendezvous + coturn, then trying to start a THIRD session ===
[wire-proof] PASS — with the rendezvous stopped, a NEW session cannot be established (rc=124) — confirms the server's actual role: bootstrapping only, never message content
[wire-proof] === ALL ASSERTIONS PASSED ===
```

Captures are kept at `capture/phaseA.pcap` and `capture/phaseB.pcap` after the run (gitignored —
inspect them directly with `tcpdump -r` / Wireshark if you have them locally, or reuse the
running `monitor` sidecar under `KEEP_UP=1`: `docker exec p2p-wire-proof-monitor tcpdump -r
/capture/phaseA.pcap ...`).

## What the script actually does

1. Builds `meridian-rendezvous`/`meridian` on the host, copies them into `demo/p2p-wire-proof/bin/`
   (gitignored — the Dockerfile only `COPY`s them in, no compiler/package manager in the image at
   all), and `docker compose up`s rendezvous + coturn + alice + bob on a static-IP network
   (`172.30.0.0/24`: rendezvous `.10`, coturn `.11`, alice `.21`, bob `.22`).
2. Starts the `monitor` sidecar (`nicolaka/netshoot`, `network_mode: host`,
   `cap_add: [NET_ADMIN, NET_RAW]`), capturing with `tcpdump -i any` scoped to the demo's own
   subnet. **Note on the capture technique:** capturing on the compose network's own bridge
   *master* device (`br-xxxx`) does **not** show container-to-container unicast traffic in this
   environment — verified experimentally, not assumed (a real, successful ping between two test
   containers produced zero packets on a bridge-device capture). Linux's `any` pseudo-interface,
   which taps every individual `veth` separately, does. The tradeoff: every packet is recorded
   twice (once per interface it crosses) — irrelevant to this demo's presence/absence assertions,
   which never depend on exact counts.
3. alice/bob each create an identity (`id new --store file`) and `register` with the rendezvous.
4. **Phase A** (default `direct` policy): both run `meridian session connect <peer> --transport
   webrtc --json` concurrently (retried up to 5× as a pair — see the script's `connect_both`
   comment for why a single one-shot attempt can occasionally race on "recipient offline" purely
   as a rendezvous-connection-bookkeeping timing artifact, not a real failure). Splits the capture
   into `phaseA.pcap` and asserts real traffic on the alice↔bob flow, zero chat-payload cleartext
   anywhere.
5. **Phase B**: both sides `config set policy relay-only`, connect again, capture splits into
   `phaseB.pcap`. Asserts the alice↔bob flow is completely silent, coturn carries real traffic
   volume in both directions, and — again — zero cleartext anywhere.
6. Greps the rendezvous container's own logs for the chat payload (zero occurrences).
7. Stops rendezvous + coturn and confirms a third `session connect` attempt cannot establish
   (times out) — the honest "what the server is actually for" boundary check.

### The known-plaintext oracle

The chat body strings are fixed, not scripted by this demo: `apps/cli/src/session_connect.rs`'s
`run_webrtc` always sends the literal `hello over p2p` (initiator) and `hi back — no server in the
path` (responder) as real application data over the established session — the same oracle
`tools/netns-nat-matrix.sh`'s `assert_dtls_ciphertext_only` uses. If either string ever appears as
cleartext bytes on any captured flow, that's a hard failure, never a downgrade.

## Troubleshooting

- **Docker daemon not running.** `dockerd &`, then `docker info` to confirm.
- **A `connect attempt N/5` retry line appears.** Expected occasionally — see point 4 above; the
  script only fails if all 5 attempts exhaust.
- **`bridge interface ... not found` (older versions of this script).** Fixed — capture now uses
  `-i any`, not a specific bridge device name; if you see this error you have a stale checkout.
- **Rebuilding after an `apps/` code change does nothing.** `docker compose up -d --build` is
  what the script already does every run — if you're driving the compose file by hand instead,
  remember `bin/` is populated by `run-wire-proof.sh`'s host build step, not by the image build.
- **`tcpdump: command not found` if you try to inspect a `.pcap` on the host directly.** Expected
  on a host without `tcpdump` installed — that's exactly why analysis runs inside the `monitor`
  container (`nicolaka/netshoot`) instead of assuming a host dependency; use `docker exec
  p2p-wire-proof-monitor tcpdump -r /capture/<file> ...` (works under `KEEP_UP=1`).

## Cleanup

The script tears itself down unless `KEEP_UP=1`. To clean up a `KEEP_UP=1` run, or one left over
from a crashed script:

```sh
docker rm -f p2p-wire-proof-monitor
docker compose -p p2p-wire-proof down -v
```

`bin/` and `capture/` are gitignored scratch directories — safe to delete by hand at any time.
