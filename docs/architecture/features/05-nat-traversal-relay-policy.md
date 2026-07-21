<!-- Source: tasks/T05-nat-traversal-relay-policy.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T05 — NAT Traversal & Relay Policy

**Priority:** P1 · **Design refs:** §5.4, §7.3, ADR-8 · **Depends on:** T04 · **Indicative effort:** 1–2 eng-weeks

## Goal
Make sessions succeed on hostile real-world networks: full ICE with org-operated coturn, ephemeral HMAC credentials minted by the rendezvous, and the three-position privacy policy (`direct | prefer-relay | relay-only`) implemented and observable.

## Scope
In: coturn deployment config + rendezvous endpoint minting time-limited TURN credentials per session; TURN/UDP, TURN/TCP, TURN/TLS-443 candidate ladder; policy knob at org-default, per-user, and per-contact levels — `relay-only` strips host/srflx candidates *before gathering* (never offered, not merely unselected); `meridian doctor` connectivity diagnostic (which candidate classes work, where the path is blocked); netns test matrix: full-cone, port-restricted, symmetric×symmetric, UDP-blocked.
Out: media (T10 reuses this unchanged), TURN autoscaling guidance (T14).

## Deliverables
1. coturn container + config in the reference stack; credential-minting API + client integration.
2. Policy implementation + `session info` showing selected path and *why*.
3. `meridian doctor` subcommand.
4. NAT test matrix in CI (netns-based, no cloud dependency).

## Working output (demo script)
```
$ ./testrig up --nat symmetric:symmetric --block-udp=false
$ meridian chat …            # → [session] path=relay (turn-a, udp) rtt=9ms
$ ./testrig up --block-udp   # → path=relay (turn-a, tls-443)  ← hostile-egress fallback
$ meridian config set policy relay-only && meridian chat …
$ meridian session info      # → candidates offered: relay only; peer never saw our host/srflx IPs
$ tcpdump on the "peer" netns confirms: no packets from our real address
```

## Acceptance criteria
All four NAT matrix cells connect (symmetric×symmetric via relay); TLS-443 fallback works with UDP fully dropped; credentials expire and are distinct per request (reuse of a captured credential within its TTL is bounded by coturn's `user-quota`, not rejected outright); in `relay-only`, a packet capture at the peer contains zero of our host/srflx addresses; TURN sees only DTLS ciphertext (capture inspected in CI).

## Risks / notes
This task creates the latency-vs-privacy trade surface — the demo must *show* the cost (rtt printed per path) so the org-level decision in §5.4 is made with numbers, not vibes.

**Verification status (recorded honestly, F9 — updated as of 1.16):** `relay-only` candidate-stripping is
now enforced from **observed** gathered candidates, not just derived from policy —
[1.16](../../tasks/phase-1/1.16-nat-acceptance-matrix.md) added a fail-closed check
(`apps/core/src/session.rs::enforce_relay_only`) that aborts the dial/answer before any offer/answer
carrying a host/srflx candidate is sent to the peer, against both `LoopbackTransport` and the real
webrtc-rs backend from [1.15](../../tasks/phase-1/1.15-webrtc-backend.md). The NAT test matrix above is
still validated only via the `netns` simulation rig against the non-webrtc-rs `Transport` test double,
not against real ICE/TURN negotiation or an actual packet capture — treat the four-cell matrix and the
"packet capture confirms zero of our address" acceptance criterion as **simulation-only** until
[1.27](../../tasks/phase-1/1.27-pcap-assertions-ci.md) lands the wire-level netns/tcpdump matrix's
pcap assertions (the chain: [1.24](../../tasks/phase-1/1.24-real-signaling-p2p-cli.md) real-signaling
CLI + [1.25](../../tasks/phase-1/1.25-netns-topology-coturn.md) netns/coturn topology →
[1.26](../../tasks/phase-1/1.26-netns-drive-and-capture.md) drive+capture → 1.27 assertions; depends on
[1.22](../../tasks/phase-1/1.22-webrtc-cli-transport.md)'s CLI transport wiring and 1.14's coturn quota).
