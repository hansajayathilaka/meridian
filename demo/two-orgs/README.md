# `demo/two-orgs/` — the feature-06 (cross-org federation) acceptance demo

> **Nav:** [task 2.11](../../docs/tasks/phase-2/2.11-demo-two-orgs.md) ·
> [feature spec](../../docs/architecture/features/06-cross-org-federation.md) ·
> [ADR 0008](../../docs/adr/0008-infra-topology.md) (one rendezvous+TURN pair per org) ·
> [deployment topology diagram](../../docs/operations/diagrams/deployment-topology.mermaid) ·
> [deployment.md §9.3](../../docs/operations/deployment.md) (air-gapped operation)

`docker compose up` brings up **two complete, independent org deployments** — `org-a.test` and
`org-b.test`, each with its own `meridian-rendezvous` + `coturn`, TLS-terminating edge, and a
private CA — on one machine, with no internet required once the images are built, and drives a
real cross-org E2EE chat (and, when it establishes, a real P2P/DTLS session) between them. This is
the feature spec's §7.1 walkthrough, made runnable rather than illustrative pseudo-code.

## What this proves

- **Federation actually crosses the org boundary.** Alice registers only with `org-a.test`; Bob
  registers only with `org-b.test`. Alice's client only ever talks to `org-a.test` — never
  `org-b.test` directly (the routing invariant, system-design.md §3.3) — yet her message reaches
  Bob, because `org-a.test`'s rendezvous federates to `org-b.test`'s over mTLS.
- **The private-CA / air-gap story is real, not asserted.** The `meridian-demo` network is
  `internal: true` (Docker refuses it a default route out — structural, not a convention), and both
  discovery modes are genuinely exercised: **static** (`federation_map.toml`, no DNS needed at all)
  and **SRV** (a real internal `dnsmasq` serving `_meridian-fed._tcp.<domain>` records).
  `run-walkthrough.sh` asserts both: no egress reaches the public internet, and (in SRV mode) `dig`
  resolves a genuine SRV record rather than a hand-waved one.
- **First contact is gated, not silently delivered.** Task 2.10's message-request queue fires
  across the org boundary exactly as it would locally: Bob sees "message request from
  `mrd1:<alice>…` — accept?" before anything is handed to his chat UI.
- **No server ever sees plaintext.** `meridian-rendezvous` routes opaque, signed envelopes only —
  the script proves this isn't just a claim by grepping both servers' own logs for the literal
  chat message body after the exchange and asserting zero occurrences (see the "plaintext" gotcha
  below).
- **(When it establishes) real P2P, real DTLS.** `meridian session connect --transport webrtc`
  runs the same handshake across the org boundary, using each org's own `coturn` for ephemeral
  ICE/TURN credentials (never a static per-user secret — the server mints them per session via
  HMAC), and both sides report `established:true` once the DTLS fingerprint is verified.

## Prerequisites

- `openssl` (for `infra/deploy/bootstrap-ca.sh` — the private CA is generated locally, once, into a
  gitignored `.ca/` directory; nothing is ever committed).
- Docker Engine + **Compose v2** (the `docker compose` plugin, not the standalone `docker-compose`
  v1 binary — check with `docker compose version`).
- A running Docker daemon (`dockerd &`, or Docker Desktop). The first build needs internet egress
  to pull `rust:1-slim` / `debian:stable-slim` and to fetch crates — **only the build**; the running
  stack itself has none (see the air-gap note above).
- A few GB of free disk (a `rust:1-slim` release build of the workspace) and, on a cold cache,
  several minutes for the first `--build`.

## Quick start

```sh
just two-orgs             # static discovery mode (the air-gap default)
just two-orgs srv         # DNS SRV discovery mode
```

or directly:

```sh
cd demo/two-orgs
bash run-walkthrough.sh            # static mode
bash run-walkthrough.sh srv        # SRV mode
```

The script tears the stack down when it exits (success or failure). Set `KEEP_UP=1` to leave it
running for manual poking afterward, and `SKIP_P2P=1` to skip the `session connect` (WebRTC/DTLS)
leg and only prove the (primary, load-bearing) cross-org chat delivery — useful on a host where UDP
between containers is constrained.

Both modes are meant to be run — CI-shaped verification would run both (per the feature's
acceptance criteria: "the walkthrough passes with *both* discovery modes").

## What the script actually does

1. **Bootstraps the private CA** via `infra/deploy/bootstrap-ca.sh` (reused as-is, not forked) into
   `demo/two-orgs/.ca/` (gitignored) — one CA, two leaf certs (`org-a.test`, `org-b.test`), each
   carrying a `subjectAltName` (required — see the note in `bootstrap-ca.sh` on why a CN-only cert
   fails modern TLS hostname verification outright).
2. Generates a fresh, random `TURN_SHARED_SECRET` for this run only (coturn's
   `static-auth-secret` == the rendezvous's `[turn].secret` — never a value baked into the repo or
   image; see `infra/coturn/turnserver.conf`'s header).
3. `docker compose -f docker-compose.yml -f docker-compose.<mode>.yml up -d --build` — two
   rendezvous, two coturn, two TLS-terminating edges, (SRV mode only) one internal DNS, and one
   `client` driver container with the `meridian` CLI + this demo's CA already trusted.
4. Waits for both rendezvous containers to report `healthy`, then asserts the air-gap: a `curl` to
   the public internet from inside the network must fail. (SRV mode) confirms
   `_meridian-fed._tcp.org-b.test` resolves to a real SRV record via `dig`.
5. Creates `alice@org-a.test` / `bob@org-b.test` (`meridian id new` + `meridian register`, each
   publishing a prekey bundle), determines who initiates by the same deterministic key-order rule
   `meridian chat` itself uses, and starts each side's `meridian chat --json` in the `client`
   container (driven over per-identity FIFOs so the script can feed typed lines — including the
   `y` that accepts the message request — into a long-running interactive process).
6. Sends one message across the org boundary and asserts, in order: the sender sees
   `delivered:true`; the recipient sees a `message_request` event (task 2.10's gate firing);
   accepting produces `request_accepted` and then the actual message body, end to end.
7. (Unless `SKIP_P2P=1`) runs `meridian session connect --transport webrtc` on both sides
   concurrently and asserts both report `established:true` with a verified DTLS fingerprint.
8. Greps both rendezvous' (and the edges' and coturns') own `docker compose logs` for the literal,
   per-run-random chat message body and asserts **zero** occurrences.

### The "plaintext" gotcha

The feature spec's demo script says `grep -c plaintext /logs/* # → 0`. Taken literally, that check
is a trap: `meridian-rendezvous`'s own startup line is *"…listening on … — holds no plaintext by
construction"* (`apps/rendezvous/src/main.rs`) — a benign self-description containing the literal
word "plaintext", not a leak. A naive `grep -c plaintext` would report `1` per rendezvous instance
and look like a failure when nothing is wrong. `run-walkthrough.sh` does the check that actually
matters — grepping for the real, per-run-random **message body** (a much stronger assertion: it
proves *this run's specific content* never appeared, not just that a magic word is absent) — and
separately verifies that any literal occurrences of the word "plaintext" are accounted for exactly
by that one banner line, never more.

`meridian-rendezvous` doesn't have request/response-level logging at all today (by design — see
`apps/rendezvous/src/logid.rs`'s header on why identifiers are never logged raw), so this is
currently a fairly easy bar to clear; it's here so it stays easy to clear as observability
(monitoring.md) grows.

## Both discovery modes, concretely

| | Static (`docker-compose.static.yml`) | SRV (`docker-compose.srv.yml`) |
|---|---|---|
| How a partner is found | `federation_map.toml` — `endpoint` (dial target) is deliberately a *different* name from `domain` (the cert-validation target), to keep discovery and trust visibly separate (ADR 0017) | Real `_meridian-fed._tcp.<domain>` SRV records, served by `demo/two-orgs/dns/` (dnsmasq) |
| Peer trust root | Private CA, pinned per partner (`pinned_identity` in the map) — `federation.ca_bundle_path` set | OS/system trust store (WebPKI mode) — `federation.discovery = "srv"` requires `ca_bundle_path` to be *empty* (`apps/rendezvous/src/config.rs`'s `Federation::validate`), so this demo's CA is installed into each container's system trust store instead (`demo-entrypoint.sh`) |
| DNS needed | No — the whole point of the air-gap map | Yes — `dns` service, `172.28.0.53` |
| Represents | `deployment.md §9.3`'s air-gapped/enterprise deployment | A connected deployment doing real internet-standard discovery |

Either way, the client-facing `wss://org-a.test:8443` / `wss://org-b.test:8443` names resolve to the
TLS-terminating `edge-a`/`edge-b` proxies (never straight to the rendezvous's plaintext c2s port —
ADR 0008), and the s2s federation mTLS on `:8444` terminates **in the rendezvous itself**, never a
proxy (ADR 0017 C7) — see `docker-compose.yml`'s header comment for the full topology rationale.

## Troubleshooting

- **`docker compose version` shows a v1 (`docker-compose`) binary or errors.** Install the
  `docker compose` v2 plugin; this demo relies on `-f a.yml -f b.yml` override merging and
  `exec -T`, both v2-only ergonomics (v1 `docker-compose` also supports `-f`/`-T`, but is
  unsupported upstream — use v2).
- **Docker daemon not running.** `dockerd > /tmp/dockerd.log 2>&1 &`, then `docker info` to confirm.
- **`docker compose exec` / `curl .../healthz` never succeeds; `rendezvous-a`/`-b` never go
  `healthy`.** Almost always a stale `.ca/` from a previous, differently-shaped run — `rm -rf .ca`
  and re-run (the bootstrap script only issues certs that don't already exist). Also check
  `docker compose logs rendezvous-a` directly — a bad/missing `subjectAltName` on the leaf cert
  (fixed in `infra/deploy/bootstrap-ca.sh` — see its header) surfaces here as a TLS handshake
  failure on the *federation* link between the two rendezvous, not the client-facing one.
- **`meridian id new` / `register` hangs on a passphrase prompt.** The script always sets
  `MERIDIAN_PASSPHRASE` for its own scripted accounts; if you're driving the container by hand,
  export `MERIDIAN_PASSPHRASE` yourself or expect an interactive prompt.
- **The chat message never gets delivered (`delivered:false`).** The *recipient's* `meridian chat`
  process must already be connected when the sender routes — there is no offline mailbox yet (T07).
  `run-walkthrough.sh` starts the responder's chat session first and waits a few seconds before the
  initiator sends for exactly this reason; if you're driving it by hand, make sure both sides are
  already running `meridian chat` before either types anything.
- **`session connect --transport webrtc` doesn't establish.** This is the "at minimum" fallback the
  task explicitly allows for: real P2P needs UDP (or TCP/TLS-relay fallback) actually working
  between the two `meridian` processes, which in this demo run inside the *same* `client` container
  (single network namespace) — normally trivial, but a restrictive host/CI network sandbox can still
  block it. Re-run with `SKIP_P2P=1`; the cross-org chat-delivery proof above is the primary
  acceptance property either way (a full separate-network P2P proof is out of this task's scope —
  see 2.11's "Out" line).
- **First build is slow / transfers a huge build context.** Every image in this repo builds with
  the workspace root as context; make sure `.dockerignore` (repo root) exists and excludes
  `/target` — without it, `COPY . .` ships the entire (many-GB) Cargo build cache into the image
  build on every invocation.
- **Rebuilding after an `apps/` code change does nothing.** `docker compose up -d --build` is
  required (not plain `up -d`) — the image bakes the binaries in, they're not bind-mounted.

## Cleanup

`run-walkthrough.sh` tears the stack down itself (`docker compose down -v`) unless `KEEP_UP=1`. To
tear down a `KEEP_UP=1` run, or one left over from a crashed script:

```sh
docker compose -f docker-compose.yml -f docker-compose.static.yml down -v --remove-orphans
# or docker-compose.srv.yml, whichever mode was up
rm -rf .ca
```

## Relationship to `infra/deploy/two-orgs.compose.yml`

`infra/deploy/two-orgs.compose.yml` is the earlier scaffold stub for this same demo (image
placeholders, commented-out config, a `TODO: confirm ports…` note). This directory is the real
thing the feature spec asks for and the task tracker points at (2.11's Deliverables literally name
`demo/two-orgs/`). `infra/deploy/two-orgs.compose.yml` now says so and points here rather than
silently diverging — see the task file's Outcome section for the full reasoning.
