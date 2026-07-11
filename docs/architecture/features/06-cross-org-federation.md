<!-- Source: tasks/T06-cross-org-federation.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T06 — Cross-Org Federation

**Priority:** P1 — the requirement-3 proof · **Design refs:** §3.3–3.5, §7.1, ADR-2 · **Depends on:** T04 (T05 recommended) · **Indicative effort:** 3 eng-weeks

## Goal
A user registered on Org A's rendezvous establishes a verified E2EE P2P session with a user on Org B's rendezvous, with servers discovering each other via DNS SRV *or* a static federation map (air-gap mode) — the complete §7.1 walkthrough, runnable as one script.

## Scope
In: s2s protocol over mTLS (WebPKI and private-CA modes); federated prekey fetch + envelope forwarding (client → own server → foreign server → client, never client → foreign server, §3.3 step 2); DNS SRV `_meridian-fed._tcp` discovery + `federation_map.toml` static mode; federation policy `open | allowlist | closed`; per-origin-server and per-account rate limits at the federation edge; first-contact **message-request gate** (§3.5) — sender's intro lands in a request queue until accepted; s2s protocol doc.
Out: contact tokens & PoW stamps (T08/T14 follow-ups), multi-hint IDs (Phase 3), presence across orgs (deliberately per-request only, §3.4).

## Deliverables
1. Federation module in rendezvous; `demo/two-orgs/` docker-compose bringing up **two complete stacks** (rendezvous+coturn ×2, private CA, static map) on one machine.
2. `federation-protocol-v1.md`.
3. Abuse tests: rate-limit enforcement, allowlist rejection, oversized-envelope rejection, and the *cross-org* malicious-server bundle-substitution test (Org B's server lies → Alice's client aborts).

## Working output (demo script)
```
$ cd demo/two-orgs && docker compose up          # org-a.test + org-b.test, private CA, no internet
$ meridian register --server wss://org-a.test --id alice.key
$ meridian register --server wss://org-b.test --id bob.key
$ meridian chat mrd1:<bob>@org-b.test            # from alice
  [fed] org-a.test → org-b.test (mTLS, static map)
  [bundle] verified under requested key ✔
  [bob] message request from mrd1:<alice>… — accept? y
  [session] P2P direct, DTLS fp verified ✔ — chat is live across orgs
$ docker compose exec org-a grep -c plaintext /logs/*   # → 0 (opacity audit runs cross-org)
```

## Acceptance criteria
The walkthrough passes with *both* discovery modes; a `closed`-policy org rejects inbound federation with a clean client-side error; substituted bundle from the foreign server fails closed; killing either rendezvous after session setup does not interrupt the P2P session; envelopes at both servers pass the opacity audit.

## Risks / notes
This is the task where the "hint is advisory" property gets stress-tested — include the stale-hint case (Bob re-registered at org-c) and confirm the failure is a clear "unreachable at hint" message, never a security warning (per ADR-1 consequences).
