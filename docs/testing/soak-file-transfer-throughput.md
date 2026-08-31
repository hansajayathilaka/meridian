<!-- Task 10.14 — soak test: 1 GiB / 10 GiB transfers + throughput report. -->
> **Nav:** [testing index](./README.md) · [strategy](./strategy.md) ·
> [feature spec T09](../architecture/features/09-file-transfer.md) ·
> [system design §5.1](../architecture/system-design.md) · [ADR 0006](../adr/0006-terminal-transport.md)

# Soak test: `meridian send` throughput (T09 / task 10.14)

## What this document is

The feature spec for `mrd.file/1` (T09) names a specific soak test as an acceptance-relevant
deliverable: 1 GiB and 10 GiB transfers on the netns rig under the 1% loss / 80 ms RTT profile
(task 10.13's `file-transfer` profile), producing a throughput report that "feeds ADR-6's
SCTP-over-DTLS-vs-QUIC question with real numbers" — [system design §5.1](../architecture/system-design.md#51-why-webrtc-and-what-it-costs)
names "SCTP over DTLS underperforms QUIC for bulk transfer" as an accepted cost of the WebRTC
choice, deferred to [ADR 0006](../adr/0006-terminal-transport.md) ("terminal/non-browser
transport"), which already "accepts SCTP throughput ceilings near-term" and reserves a Phase-4
`transport=quic` capability-negotiation slot for CLI↔CLI bulk transfer. This document is that
report — "ship the numbers, don't hide them," including where the number is that no number could
be produced.

## Headline finding: a blocking, pre-existing defect, not a throughput ceiling

Before any loss/RTT profile — even before any netns rig — comes into play at all, attempting this
soak test surfaced a **functional defect** in the existing `mrd.file/1`-over-real-`WebRtcTransport`
wiring: **any file transfer requiring more than one 64 KiB chunk fails deterministically on the
first full chunk**, over plain loopback, with no network impairment involved:

```
error: <name>: session error while sending a chunk: transport error: transport backend error:
outbound packet larger than maximum message size
```

### Root cause

- `mrd.file/1`'s wire format chunks a file into 64 KiB (65536-byte) pieces
  (`apps/streams/src/merkle.rs`, pinned in `docs/api/stream-types-v1.md`) and sends each chunk as
  **one transport message** — "SCTP already frames messages, so there is no separate length prefix
  on the wire" (`docs/api/stream-types-v1.md`'s "Stream framing" section).
- Every stream frame is ratchet-sealed directly (one Double Ratchet step per frame), and the
  chunk itself is separately AEAD-sealed under its own per-file key before that — so the actual
  bytes handed to the SCTP data channel for one "full" chunk are **65536 bytes of chunk plaintext
  plus per-chunk AEAD overhead plus the outer ratchet header/tag plus a small CBOR framing
  overhead** — comfortably more than 65536 bytes total.
- `apps/transport/src/webrtc_backend.rs`'s `WebRtcTransport::new()` builds its `SettingEngine`
  with no SCTP max-message-size override, so `webrtc-rs`/`webrtc-sctp`'s own default applies:
  **`SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE = 65536`** (`webrtc-sctp` crate,
  `api/setting_engine/mod.rs`). Two `webrtc-rs` peers with neither side configuring a larger value
  (exactly the CLI↔CLI, terminal-client scenario `meridian send` is built for — no browser is
  involved to advertise a larger `a=max-message-size`) negotiate that same 65536-byte ceiling.
- Net effect: **every full 64 KiB chunk is, by a small margin, too big for the channel it's sent
  on.** Only a transfer whose entire content fits in a single, necessarily-short final chunk
  (empirically confirmed up to ~65400 bytes of plaintext) can complete at all today.

### Reproduction (confirmed twice, independently)

1. This task's own `tools/soak-file-transfer.sh loopback` run (below): a 2 MiB file fails
   immediately on the first full chunk; a 60000-byte (single-chunk) file completes and verifies
   byte-perfect.
2. **Independently reproduced by task 10.15** (kill/resume automation, landing concurrently with
   this task), whose `apps/cli/examples/kill_resume_netns_drive.rs` example — a different driver,
   built directly against `P2pSession`/`WebRtcTransport` rather than through the `meridian send`
   CLI — hit the exact same error string on its own ~1.5 MiB test file, independent of this task's
   own work. Two independently-built harnesses hitting the identical, specific SCTP error is strong
   evidence this is a real, systemic defect rather than an artifact of either harness's own setup.

### Why this isn't "the ADR-6 numbers, but bad" — it's a correctness bug blocking them

ADR 0006 already accepted "SCTP throughput ceilings" as a *known, priced-in* cost of the WebRTC
choice — a *slower* number was the expected outcome this soak test was designed to quantify. What
was found instead is qualitatively different: **zero bytes per second for any real file**, because
the wiring cannot move a single full-size chunk at all. This is not evidence for or against
QUIC — it is a bug in the existing SCTP configuration that must be fixed before ADR-6 can be fed
any real throughput number, on any network condition, in any environment.

### Recommended fix (not applied here — out of this task's explicit scope)

Configure a larger negotiated SCTP max-message-size in `WebRtcTransport::new()`'s `SettingEngine`
(`webrtc-rs` exposes `SettingEngine::set_sctp_max_message_size_can_send`), comfortably above
65536 bytes plus the framing overhead measured above — e.g. 256 KiB, a size several real-world
WebRTC stacks already default to. This task deliberately does **not** make that change: task
10.14's own scope is explicitly "this task reports, it does not fix," and the change belongs to
`apps/transport/src/webrtc_backend.rs`, a transport-layer file this task was told not to touch.
See the "Carry-forward" section below for how this is being handed off.

## What this task actually measured

### Loopback (127.0.0.1, no netns, no loss/RTT injection) — real, honest data

Run via `tools/soak-file-transfer.sh loopback`, two real `meridian` CLI processes (built with
`--features webrtc`), a real local `meridian-rendezvous`, fresh identities each run:

| Size | Result | Notes |
|---|---|---|
| 60000 bytes (single chunk) | **PASS** — sha256 identical on both ends | ~0.02 MB/s *as measured*, but this number is **not a meaningful throughput figure** — a single ~60 KB message dominated by X3DH/session-establishment and ratchet/AEAD overhead, not a steady-state multi-chunk transfer. Included only as the one payload size that completes at all today, and as the harness's own smoke-tested "PASS" path. |
| 2 MiB, 4 MiB (multi-chunk) | **BLOCKED** — `outbound packet larger than maximum message size` on the first full chunk | Fails in ~1–4s (immediately, not after any meaningful transfer), independent of size |
| 1 GiB (feature spec's named size) | **not attempted for real** | Given the above, a 1 GiB run would fail identically, immediately, on the very first chunk — running it for real would burn disk/time (this sandbox had ~1–3 GiB of free disk margin during this task) to reproduce a result already proven at 2 MiB. Re-run `tools/soak-file-transfer.sh loopback --size-gib 1` once the SCTP fix lands. |
| 10 GiB (feature spec's named size) | **not attempted, and not practical in this sandbox regardless of the defect** | This sandbox's root filesystem had on the order of 1–3 GiB free at various points during this task (checked directly via `df`) — a real 10 GiB source file plus its received copy would not fit. A real 10 GiB run needs a CI/scheduled job with adequate disk (a self-hosted or larger-disk runner), matching task 10.13's own "not yet observed on a real runner" caveat pattern. |

### netns + `file-transfer` profile (1% loss / 80 ms RTT) — gated, correctly skips here

`tools/soak-file-transfer.sh netns` sources `tools/netns-netem.sh` and gates on that script's own
`need_root()`/`need_netem()`. This sandbox's kernel lacks `CONFIG_NET_SCH_NETEM` (confirmed
directly: `tc qdisc add ... netem` reports "Specified qdisc kind is unknown", the same finding task
10.13 made independently) — so a **real** netem-affected soak run was not observed here, and
(independent of that) would hit the exact same blocking defect above the moment any full chunk is
sent, before loss/RTT could even become the limiting factor. Both are honest absences, not
elided:

- **netem itself**: not exercised for real in this sandbox — the mechanism for observing it for
  real is the same scheduled/`workflow_dispatch` CI job pattern task 10.13 established
  (`.github/workflows/netns-netem-smoke.yml`); see `.github/workflows/soak-file-transfer.yml` (new,
  this task) for the equivalent for this harness.
- **The harness's own orchestration** (network namespaces, veth routing, a rendezvous server bound
  inside one namespace and reachable from the other across the veth link, real identity generation,
  a real WebRTC ICE/DTLS/SCTP session establishing across two isolated network namespaces, a real
  X3DH handshake, sha256 verification, and full teardown) **was validated for real** in this
  sandbox, using task 10.13's own documented technique: temporarily shadowing `tc` with a no-op
  stub so `need_netem()`'s probe succeeds (no real netem effect — this validates orchestration, not
  loss/RTT injection, which 10.13's own smoke test already independently covers) and driving a
  single-chunk (60000-byte) transfer end-to-end across the real netns topology. Result: **PASS**,
  sha256-identical, full topology teardown confirmed (`ip netns list` clean afterward). This
  confirms the harness's own logic is sound; it does not and cannot substitute for a real
  netem-affected run.

## Comparison against system design's named risk

[System design §5.1](../architecture/system-design.md#51-why-webrtc-and-what-it-costs) names the
cost qualitatively ("SCTP over DTLS underperforms QUIC for bulk transfer") without citing a
specific MB/s ceiling anywhere in the docs tree (checked: no numeric SCTP throughput figure exists
in `system-design.md`, the ADRs, or the feature spec) — so there is no pre-existing number to
compare a measurement against; this report's job was to *produce* the first one. It could not:
the defect above means **no steady-state throughput number exists yet for the real transport**,
at any size, under any network condition. The single honest data point available (60000 bytes,
~0.02 MB/s including full X3DH session setup) is explicitly not that number — see the caveat in
the table above.

## Follow-up (superseded — now owned by task 10.18, not an unowned carry-forward)

This section originally drafted a carry-forward bullet for `docs/tasks/README.md`'s "Live
carry-forwards" (rather than editing that file directly, since it had concurrent, in-flight edits
from task 10.15 at the time this task ran). That draft is now superseded: the finding below was
promoted to its own task, [10.18](../tasks/phase-10/10.18-sctp-max-message-size-fix.md), rather than
left as an unowned tracker bullet, since it blocks task 10.17's phase-exit demo from running over
real transport at all. Recorded here for context, not as an open carry-forward:

> **The real `WebRtcTransport` cannot send a full 64 KiB `mrd.file/1` chunk — any transfer needing
> more than one chunk fails deterministically** (found independently by task 10.14's own
> soak-throughput run and task 10.15's `kill_resume_netns_drive` example, both against
> `apps/transport/src/webrtc_backend.rs`'s real backend). Root cause: `webrtc-sctp`'s default
> `max_message_size` (65536 bytes) is smaller than a full 64 KiB chunk plus its per-chunk AEAD +
> ratchet-header + CBOR framing overhead once sealed for the wire, and `WebRtcTransport::new()`'s
> `SettingEngine` never overrides it. Confirmed reproducible: a 60000-byte (single-chunk) transfer
> completes and verifies byte-perfect; a 2 MiB (multi-chunk) transfer fails immediately with
> `outbound packet larger than maximum message size`. Fix now tracked and owned by task 10.18.

Correction to an earlier claim in this doc's draft: it previously said `tools/netns-kill-resume.sh`
"uses that same `timeout N wait "$pid"` idiom" as a bug this task found in its own harness. That claim
was stale/false as landed — task 10.15's `netns-kill-resume.sh` already implements the correct
`kill -0` polling loop under its own `wait_pid_with_timeout`, independently of this task, with its own
comment explaining the same pitfall. No cross-task bug exists here; correcting the record rather than
leaving an inaccurate claim in a checked-in doc.

## Harness

`tools/soak-file-transfer.sh` (this task) — see its own header comment for full usage. Two
subcommands:

- `loopback [--size-mib N | --size-gib N | --size-bytes N] [--timeout-secs N]` — real CLI-to-CLI
  transfer on 127.0.0.1, no root needed, always runnable. The one data point this task can produce
  in any sandbox.
- `netns [--size-mib N | --size-gib N | --size-bytes N] [--profile file-transfer] [--timeout-secs N]`
  — the full soak scenario: two network namespaces joined by a veth pair, the named profile applied
  via `tools/netns-netem.sh apply-pair`, sourcing that script's own `need_root()`/`need_netem()`
  gates (graceful exit 0 on either being unavailable, matching task 10.13's convention). `netns down`
  tears down a leftover topology.

Both subcommands: generate a real pseudorandom test file, run fresh identities against a fresh
rendezvous every time (see the script's own comment on why — stale one-time-prekeys from a reused
identity against a still-running rendezvous produced a confusing, unrelated
`no matching prekey secret` failure during this task's own development), verify sha256 identity
between source and received file (the feature spec demo script's own final check), and report
elapsed time / MB/s for whatever actually completed. Neither subcommand ever fabricates a
throughput number for a run that didn't verify byte-perfect delivery of the requested size; both
detect the specific SCTP defect above by its exact stderr substring and fail loudly (a real exit 1)
rather than hanging or reporting a misleading result.

`--ignored` / CI: mirroring task 10.13's own precedent (`.github/workflows/netns-netem-smoke.yml`),
this task adds `.github/workflows/soak-file-transfer.yml` (scheduled + `workflow_dispatch`) rather
than a blocking `cargo nextest`-driven `#[ignore]`d Rust test — the harness is a standalone shell
script (like `tools/netns-netem.sh`/`tools/netns-kill-resume.sh`), not a Rust integration test, so
there is no `cargo nextest run --ignored` invocation to gate; the workflow is the "ignored by
default, run on a schedule/dispatch" mechanism instead. The workflow currently runs the `loopback`
leg (always available, no privileged runner needed) plus the `netns` leg at a modest size — a real
1 GiB/10 GiB run needs a `workflow_dispatch` input or a dedicated follow-up job with a
disk/time budget this default schedule does not assume, **and** the SCTP fix above landed first
(otherwise every scheduled run will red the moment it hits a multi-chunk file, which is expected
and correct given the current state of the code, not a flaky test).

## What a devops reviewer should check

- CI workflow structure (`.github/workflows/soak-file-transfer.yml`) against the
  `netns-netem-smoke.yml`/`p2p-wire-proof.yml` precedents this mirrors.
- Whether the scheduled workflow should red (fail) on the known SCTP defect right now, or should
  itself skip/xfail until that fix lands — this task chose to let it fail loudly (matching "never
  weaken an assertion to get green"), which means **this new CI job is expected to be red from its
  first scheduled run** until the SCTP fix (carry-forward above) lands. That is a deliberate,
  documented choice, not an oversight — flagging explicitly so a reviewer doesn't mistake it for a
  flaky/broken workflow.
- Real 10 GiB run resource requirements: needs a runner with materially more free disk than a
  standard GitHub-hosted `ubuntu-latest` (which typically has on the order of tens of GB free, so
  it may in fact be sufficient — this sandbox's own ~1–3 GiB constraint is a sandbox-specific
  limit, not necessarily representative of the real CI runner class) and a longer job timeout than
  this task's default.
