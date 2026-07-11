<!-- Source: tasks/T03-e2ee-messaging-relayed.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T03 — E2EE Messaging, Server-Relayed

**Priority:** P0 · **Design refs:** §4.2–4.3, ADR-3, ADR-7 (context) · **Depends on:** T02 · **Indicative effort:** 2–3 eng-weeks

## Goal
Working end-to-end-encrypted 1:1 chat between two online CLIs, with envelopes *relayed through* the rendezvous (WebRTC comes in T04). This deliberately proves the design's key property early: content security must not depend on the transport path (§4.3 point 2) — the same ratcheted envelopes will later ride data channels and the mailbox unchanged.

## Scope
In: X3DH initiation against fetched bundles; Double Ratchet with header encryption (audited lib: libsignal-client or equivalent — **no hand-rolled ratchet**, ADR-3); `mrd.chat/1` message schema (text, delivery receipt); persistent encrypted session store (ratchet state survives restart, key from T01 `SecretStore`); envelope format: `Sign_IK{ ratchet_ct }` with sender key inside per §7.1 step 6; TUI chat mode + `--json` line mode.
Out: P2P transport (T04), offline delivery (T07), safety-number UX (T08 — but the *fingerprint computation* lands here for T08 to consume), attachments (T09).

## Deliverables
1. `meridian-core` session module (X3DH, ratchet lifecycle, session persistence, desync→fresh-X3DH recovery per §10).
2. `meridian chat <id>` TUI + headless mode.
3. **Opacity audit harness:** a proxy that dumps every byte the server handles for a scripted conversation and asserts (a) no plaintext substrings, (b) header encryption hides ratchet counters, (c) message sizes are the only observable variation.
4. Protocol doc `messaging-envelope-v1.md`.

## Working output (demo script)
```
$ meridian chat mrd1:<bob>@localhost        # terminal 1 (alice)
$ meridian chat mrd1:<alice>@localhost      # terminal 2 (bob)
  — messages flow both ways with delivery receipts —
$ meridian demo opacity-audit ./transcript.pcapish
  → 0 plaintext leaks; 214 envelopes; sizes only observable field
$ kill -9 <alice-cli> && meridian chat mrd1:<bob>@localhost
  → session restored from encrypted store; ratchet continues (no re-handshake)
```

## Acceptance criteria
Forward secrecy test: harness snapshots ratchet state at message N, proves messages <N are undecryptable from it; PCS test: after simulated state theft, session heals within one round-trip; out-of-order delivery (server shuffles envelopes) decrypts correctly via skipped-message keys; opacity audit passes in CI on every commit.

## Risks / notes
Library FFI choice made here propagates to WASM/mobile (T11/T12) — validate the chosen ratchet lib compiles for wasm32 and aarch64 targets *this task*, not later.
