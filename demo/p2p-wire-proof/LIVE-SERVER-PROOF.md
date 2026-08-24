# Live-server wire proof — `rendezvous.hansajayathilaka.com`

Run **2026-08-24**, against the real, already-deployed rendezvous server at
`wss://rendezvous.hansajayathilaka.com` (owner-operated, not a local/Docker stand-in). This
records what was actually observed on the wire, reproducible via
[`run-live-server-proof.sh`](./run-live-server-proof.sh):

```sh
RENDEZVOUS_URL=wss://rendezvous.hansajayathilaka.com bash run-live-server-proof.sh
# (RENDEZVOUS_URL defaults to exactly this URL, so `bash run-live-server-proof.sh` alone repeats
#  this exact run against this exact server)
```

## Result: PASS, twice in a row

```
[live-proof] resolving rendezvous.hansajayathilaka.com…
[live-proof] rendezvous.hansajayathilaka.com -> 161.97.71.217
[live-proof] creating identities…
[live-proof] alice = mrd1:5uaxhsdapvae5i6mmtt3mu66epgtltk2ssyuuzs7uelfatbicmzovghlgsgco@rendezvous.hansajayathilaka.com
[live-proof] bob   = mrd1:5ua6gerju5npptdqfwdoy4uciddx4grue3xb2b3txqbao5hviocfrl6ed7cjq@rendezvous.hansajayathilaka.com
[live-proof] registering both with wss://rendezvous.hansajayathilaka.com…
  alice: registered mrd1:5uaxhsdapvae5i6mmtt3mu66epgtltk2ssyuuzs7uelfatbicmzovghlgsgco@rendezvous.hansajayathilaka.com — published bundle with 100 one-time prekeys
  bob:   registered mrd1:5ua6gerju5npptdqfwdoy4uciddx4grue3xb2b3txqbao5hviocfrl6ed7cjq@rendezvous.hansajayathilaka.com — published bundle with 100 one-time prekeys
[live-proof] capture running (pid 12884) -> demo/p2p-wire-proof/live-proof-work/live.pcap
[live-proof] running session connect on both sides against wss://rendezvous.hansajayathilaka.com…
[live-proof] both sides established — "path":"direct"
[live-proof] PASS — server flow (rendezvous.hansajayathilaka.com, 161.97.71.217): 98 packets, zero occurrences of the chat payload
[live-proof] PASS — non-server (P2P) flow: 48 packets, zero occurrences of the chat payload in cleartext (expected: it's E2E encrypted)

[live-proof] === ALL ASSERTIONS PASSED against the live server (wss://rendezvous.hansajayathilaka.com) ===
[live-proof] Negotiated path: "path":"direct"
[live-proof] Server flow:  98 packets total, 0 containing the chat payload.
[live-proof] P2P flow:     48 packets total, 0 containing the chat payload (encrypted, as always).
```

Both accounts (`alice`, `bob`) were created fresh for this run, registered a real prekey bundle
with the real server, and ran `meridian session connect --transport webrtc` against it — the exact
same command [`docs/architecture/features/04-p2p-session-substrate.md`](../../docs/architecture/features/04-p2p-session-substrate.md)'s
acceptance demo uses. `established:true`, `"path":"direct"` on both sides.

## What the capture actually showed, in detail

Three distinct traffic classes appeared, each independently captured and analyzed with `tcpdump`
(same known-plaintext-oracle technique as [`run-wire-proof.sh`](./run-wire-proof.sh) and
[`tools/netns-nat-matrix.sh`](../../tools/netns-nat-matrix.sh) — the fixed, literal chat strings
`apps/cli/src/session_connect.rs` sends, `hello over p2p` / `hi back — no server in the path`,
grepped for in every flow):

1. **Signaling (`161.97.71.217:443`, TCP/TLS)** — two independent WebSocket connections (one per
   client), carrying `register`/`fetch_bundle`/envelope-routed offer-answer-ICE traffic. **Zero**
   occurrences of the chat payload, at any point — expected, since the chat body is only ever sent
   *after* the P2P session is established and the signaling connection is being dropped, but also
   because the offer/answer envelopes themselves are ratchet-encrypted (T04), so even the SDP
   never appears in cleartext here.
2. **TURN/coturn candidate probing (`161.97.71.217:3478`, UDP)** — 18 short UDP packets (20–36
   bytes each: STUN Binding/Allocate-class headers, no substantial payload). This is `session
   connect`'s unconditional TURN-credential-mint-and-probe step
   (`session_connect.rs`: "Always attempt to mint a real ephemeral TURN credential... before
   dialing") — candidate *gathering*, not actual relay use. Confirmed by the CLI's own report:
   `path: "direct"`, `relay_fallback: false` — the gathered relay candidate was never the
   nominated pair. Zero chat-payload occurrences here either, as expected for gathering-only
   traffic that carries no application data at all.
3. **The actual P2P data channel** — 48 UDP packets, growing from small STUN connectivity-check
   frames (48–116 bytes) through a DTLS handshake (frames up to 734 bytes — ClientHello/
   ServerHello-sized) down to steady-state SCTP DATA chunks (39–113 bytes — exactly the size class
   of one short chat message's ciphertext). **Zero** occurrences of the chat payload in cleartext,
   as always with Meridian (end-to-end encryption doesn't stop applying just because the transport
   is now direct) — this is the flow that actually carried `hello over p2p` / `hi back — no server
   in the path`, and it's ciphertext the entire way.

## An honest caveat: same-host topology

Both `alice` and `bob` ran on **this one machine** (the session driving this test), so the ICE
agent's negotiated "direct" host-candidate pair resolved to this host's own address talking to
itself — the kernel short-circuits that onto the **loopback interface** (`lo`) rather than sending
it out over the real network, visible directly in the capture:

```
12:43:40.911337 lo  In  IP 192.0.2.2.36848 > 192.0.2.2.51981: UDP, length 112
...
12:43:49.398484 lo  In  IP 192.0.2.2.36848 > 192.0.2.2.51981: UDP, length 39
```

That's a genuine limitation of running both peers from a single machine: it does **not** exercise
real NAT traversal or a real cross-network P2P hop. What it still proves cleanly — the property
this whole exercise is actually about — is that **the server's own flow never carries the message,
at any point, under a real deployment with a real domain and a real TLS certificate**, and that the
P2P leg (wherever it physically lands) is genuinely separate from and never routed through that
server flow. Real cross-network P2P and forced-relay-through-TURN are exercised separately and
already proven elsewhere in this repo:

- [`run-wire-proof.sh`](./run-wire-proof.sh) / [`README.md`](./README.md) — a local multi-container
  Docker rig where alice and bob are genuinely separate hosts on their own network, including a
  forced `relay-only` policy phase that drives real traffic through a real coturn relay.
- [`tools/netns-nat-matrix.sh`](../../tools/netns-nat-matrix.sh) — real NAT topologies (full-cone,
  port-restricted, symmetric×symmetric, UDP-blocked) via Linux network namespaces, CI-wired.

This run's unique contribution is the one thing those can't provide: proof against the actual,
live, publicly-reachable, TLS-terminated deployment a real user is running today, not a synthetic
stand-in.

## Reproduce it yourself

```sh
cd demo/p2p-wire-proof
bash run-live-server-proof.sh                                    # this server, by default
RENDEZVOUS_URL=wss://your-own-server bash run-live-server-proof.sh   # any other server
```

Requires `tcpdump` on the host (`apt-get install tcpdump` if missing) and a `meridian` binary
built with `--features webrtc` (built automatically on first run if not already present). No
Docker needed — see the script's own header for exactly what it does and why.
