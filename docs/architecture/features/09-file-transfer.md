<!-- Source: tasks/T09-file-transfer.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T09 — File Transfer Stream (`mrd.file/1`)

**Priority:** P2 — first non-chat stream type; proves the T04 extension contract · **Design refs:** §5.3, §7.2 · **Depends on:** T04 · **Indicative effort:** 2 eng-weeks

## Goal
Resumable, integrity-verified P2P file/image transfer implemented purely as a stream type against the T04 registry — no changes to core session code allowed. That constraint is the point: this task *validates* that "ultimate sharing platform" is an architectural property.

## Scope
In: manifest on ctrl (name, size, BLAKE3 merkle root, per-file key sealed under the ratchet); 64 KiB chunks, AEAD per chunk (nonce = index), reliable-unordered channel; backpressure via bufferedAmount watermarks; resume via missing-range bitmap after redial; incremental subtree verification; recipient accept/reject policy hook (auto-accept images < N MB configurable); inline image preview in TUI (sixel/kitty where available) and progress UI; multi-file batches.
Out: reshare/dedup of identical ciphertext to other peers (design allows it, §7.2 — record as follow-up), mailbox'd attachments (offline file delivery is out of scope by design: files require a live session; small images may fall back to inline chat payloads ≤ 64 KiB).

## Deliverables
1. `mrd.file/1` implementation + spec section in `stream-types-v1.md` (written to be implementable by a third party from the doc alone).
2. Soak test: 1 GiB and 10 GiB transfers on the netns rig with 1% loss / 80 ms RTT profiles; throughput report (this is where the ADR-6 SCTP question gets its final numbers).
3. Kill/resume test automation.

## Working output (demo script)
```
$ meridian send mrd1:<bob>@org-b.test ./video-1GiB.bin
  [file] merkle root b3:9af2… | 16384 chunks | direct path
  38% ▓▓▓▓▓░░░░ 41 MB/s
$ # yank the network mid-transfer (testrig cuts the veth), then restore
  [session] ICE restart… reconnected
  [file] peer reports 6211 missing ranges — resuming at 38%
  done ✔ verified b3:9af2… matches
$ sha256sum on both ends → identical
```

## Acceptance criteria
Byte-perfect delivery under the loss profile; resume never re-sends >2% already-delivered data; corrupted chunk (injected) is detected by AEAD/merkle and re-requested, never written; a *reference third-party check*: an engineer not on the task implements a toy `mrd.echo/1` stream from `stream-types-v1.md` in <1 day — if they can't, the contract doc fails acceptance.

## Risks / notes
Throughput ceiling risk from SCTP-over-DTLS (§5.1): the soak report feeds the Phase-4 QUIC decision (ADR-6). Ship the numbers, don't hide them.
