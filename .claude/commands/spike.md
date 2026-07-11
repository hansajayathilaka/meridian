---
description: Run a time-boxed decision spike, then record the outcome as an ADR.
---
Run a structured spike for the open question: **$ARGUMENTS**

Use this for *implementation* forks that need evidence before committing (e.g. `ratchet-header-enc`,
`libwebrtc-packaging`). A spike produces a **decision**, not shipped feature code.

1. **Frame the question and the exit criteria up front.** What are we choosing between, and what
   measurements decide it? Write these down before coding. Keep it time-boxed (state the box).
2. **Read the relevant docs/ADRs** so the spike is grounded — e.g.
   [ADR 0011](../../docs/adr/0011-ratchet-library.md) for ratchet questions,
   [ADR 0014](../../docs/adr/0014-media-stack.md) for media/packaging.
3. **Build the minimum throwaway** to get the measurements (build cleanliness on wasm32/aarch64, API
   fit, size, latency — whatever the exit criteria named). Mark it clearly as throwaway; it does not
   merge into product crates.
4. **Report** the measurements against the exit criteria and make the call.
5. **Record it** via [/adr](./adr.md) — a spike that doesn't end in an ADR was wasted. Update any
   `TODO: confirm` or "remaining spike" notes that the outcome resolves.

Never let a spike silently become the implementation. Decision first, then a clean implementation task
via [/new-task](./new-task.md).
