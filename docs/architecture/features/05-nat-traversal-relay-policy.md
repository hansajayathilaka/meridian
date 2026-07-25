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
All four NAT matrix cells connect (symmetric×symmetric via relay; `udp-blocked` + `relay-only` excepted — proven impossible at the pinned dependency version, see [1.30](../../tasks/phase-1/1.30-turn-tcp-dependency-gap.md)); TLS-443 fallback works with UDP fully dropped; credentials expire and are distinct per request (reuse of a captured credential within its TTL is bounded by coturn's `user-quota`, not rejected outright); in `relay-only`, a packet capture at the peer contains zero of our host/srflx addresses; TURN sees only DTLS ciphertext (capture inspected in CI).

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

**`udp-blocked` + `relay-only` against the real backend — updated at 1.30, sharper than "not yet
proven":** driving real peers across the netns/coturn rig ([1.26](../../tasks/phase-1/1.26-netns-drive-and-capture.md))
found this specific combination is not merely unverified against a real backend — it is **proven
impossible at the pinned dependency version**. Direct inspection of `webrtc-ice` 0.17.1's
`agent_gather.rs::gather_candidates_relay` (and, at [1.30](../../tasks/phase-1/1.30-turn-tcp-dependency-gap.md),
confirmed still true of the successor patch release 0.17.2) shows client-side TURN-over-TCP support
does not exist at all in this dependency: any `transport=tcp`/`turns:` TURN URL hits an explicit
`else` branch (with an upstream `TODO` acknowledging the gap) that silently drops the URL rather than
gathering a relay candidate from it. Under `relay-only` with UDP egress genuinely blocked, this
leaves the session with no usable relay candidate at all — a real, dependency-level ceiling, not a
gap this codebase's wiring can paper over. [1.30](../../tasks/phase-1/1.30-turn-tcp-dependency-gap.md)
added a bounded overall timeout around the gather flow (`apps/transport/src/webrtc_backend.rs`) so
this combination now fails loud within seconds with a clear error instead of hanging, but does not
and cannot make the combination succeed. Treat `udp-blocked + relay-only` as a currently-unsupported
real-backend combination until a `webrtc-ice` release adds client TURN/TCP support (checked at 1.30:
none exists yet) or the ICE-agent dependency changes — see 1.30 for the full disposition.

**`direct`/`prefer-relay` under a real NAT — two-phase fallback added at 1.29 (Bug A), supersedes the
single-phase model above:** driving real peers across the netns/coturn rig ([1.26](../../tasks/phase-1/1.26-netns-drive-and-capture.md))
found that `full-cone`/`port-restricted` (`direct`) and `symmetric:symmetric` (`prefer-relay`) never
established at all against the real backend — not a slow-but-working path, a permanent stall
(`transport error: no candidate pair selected yet`), even though the identical topology connects
cleanly under `relay-only`. Root-caused against the real rig (live reproduction + reading the pinned
`webrtc-ice` 0.17.1 source, not a guess): real, permanently-unreachable host/srflx pairs can sit in
the ICE agent's `Checking` phase without ever nominating a pair — including, empirically, the
relay-vs-relay pair itself — inside `Transport::selected_path`'s bounded wait, so a working relay
path is never reached in time even though a `relay-only` session on the same servers connects
quickly. Tightening `webrtc-rs`'s `SettingEngine::set_ice_timeouts` (config-only, still landed as a
genuine improvement — it bounds the ICE agent's own give-up horizon inside the transport's wait
instead of past it) was tried first per architect-approved ordering and, verified experimentally
against the real rig, proved **insufficient on its own** to make nomination converge — the underlying
non-convergence is not a timeout-tuning problem. The **shipped fix** is a session-level fallback in
`apps/core/src/session.rs` (`dial_with_config`/`answer_with_config`): if the first attempt's
`selected_path` wait times out (`TransportError::NoPath`) under `Direct`/`PreferRelay` **and** a TURN
grant was actually configured, the substrate closes that attempt and retries the *entire*
offer/answer/ICE exchange once more forcing `IcePolicy::RelayOnly` — a second full round trip
through the signaling relay, not an instant retry. This is a genuine, real behavioral change to the
single-ICE-gathering-phase model [`seq-call-relay-fallback.mermaid`](../diagrams/seq-call-relay-fallback.mermaid)
documented before 1.29 (now updated with the two-phase retry) — per this task's own risk note above
("the demo must *show* the cost, rtt printed per path"), the added retry latency is never hidden:
`SessionInfo::relay_fallback` and `SessionInfo::relay_fallback_wait_ms` (surfaced in `session
info`/`session connect --json`/`doctor`) tell the operator both that a fallback happened and how long
the abandoned first attempt was stuck before it did. **Architect-signed-off (2026-07-23)** — this
supersedes the acceptance criterion's implicit single-phase assumption above; see
[1.29](../../tasks/phase-1/1.29-ice-nomination-relay-fallback.md) for the full sign-off record.
