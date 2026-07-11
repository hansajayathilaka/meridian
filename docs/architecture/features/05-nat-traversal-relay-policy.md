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
All four NAT matrix cells connect (symmetric×symmetric via relay); TLS-443 fallback works with UDP fully dropped; credentials expire and are single-session (reuse rejected by coturn); in `relay-only`, a packet capture at the peer contains zero of our host/srflx addresses; TURN sees only DTLS ciphertext (capture inspected in CI).

## Risks / notes
This task creates the latency-vs-privacy trade surface — the demo must *show* the cost (rtt printed per path) so the org-level decision in §5.4 is made with numbers, not vibes.
