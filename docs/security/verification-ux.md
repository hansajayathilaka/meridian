# Verification UX — Canonical Warning Wording

<!-- Synthesis of p2p-comms-design.md §4.4 (safety numbers), §3.5 (impersonation), §1.2 goal 2.
     This is CANONICAL: clients MUST NOT soften, auto-dismiss, or reword these below the intent stated
     here. The malicious-server defense is exactly as strong as the unskippability of these warnings. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](./threat-model.md) · [feature 08: verification & trust](../architecture/features/08-verification-trust.md) · [trust state machine](../architecture/diagrams/trust-state-machine.mermaid)

## Why this file exists
A fully malicious signaling server (or a colluding pair across a federation) cannot forge identity, but
it *can* try to substitute keys. The only thing that turns that from "silent MITM" into "detected and
blocked" is the human-facing verification layer behaving correctly and un-bypassably. Every product
request to "make this less annoying" must be checked against this file. See
[threat model](./threat-model.md) goal 2.

## States (see the [trust state machine](../architecture/diagrams/trust-state-machine.mermaid))
`new → pinned (TOFU) → verified`, plus `blocked`. Petnames are assigned locally and are never taken
from the wire.

## Required behaviors (normative)

### Safety-number verification
- Present both a **60-digit number** and a **QR code**; comparison is out-of-band (in person / over an
  existing trusted channel / on a video call).
- Numbers are **order-independent** — both parties see the identical string.
- On success, mark the contact **verified**.

### Key change on a VERIFIED contact — **BLOCK**
- Sends are **blocked** until the user re-verifies. This is not a warning-with-continue; it is a hard
  stop.
- Canonical intent of the message: *"The safety number for <petname> has changed. This can happen if
  they reinstalled or switched devices — but it can also mean someone is intercepting your messages.
  Messages are paused until you verify the new safety number with them through a channel you trust."*
- Provide a **Verify** action (re-run safety-number/QR) and a **Block** action. Do **not** provide a
  one-tap "trust anyway / dismiss" that silently re-pins without verification.

### Key change on a PINNED (TOFU, not verified) contact — **PROMINENT WARNING**
- Show a prominent, blocking-until-acknowledged warning; org policy MAY escalate this to the same hard
  block as verified.
- Canonical intent: *"The safety number for <petname> has changed. Verify it with them before sending
  anything sensitive."* Acknowledgement re-pins; offer **Verify** as the primary action.

### First contact (message request)
- Before any session is accepted, show the sender's **key / safety number** and a short encrypted
  intro. The user explicitly accepts before further envelopes are processed (design §3.5).

### Device-list change on a verified contact
- Treated with the **same blocking semantics as a key change** (a new device is account-signed but must
  be surfaced). Canonical intent mirrors the key-change wording, naming "a new device was added."

## Hard prohibitions (any of these is a security defect)
1. No auto-dismiss, no "remember my choice" that skips verification, no timed auto-accept of a changed
   key.
2. No wording that implies the change is definitely benign ("they got a new phone!") without also
   stating the interception possibility.
3. No burying the block behind an easily-missed banner — it must gate sending.
4. The [security-reviewer](../../.claude/agents/security-reviewer.md) treats softening this UX as
   blocking.

<!-- TODO: confirm final user-facing copy with design/UX; the wording above is the canonical INTENT
     that implementations must preserve, not necessarily the last word on phrasing. -->
