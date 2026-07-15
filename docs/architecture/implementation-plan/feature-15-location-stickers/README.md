> **Nav:** [plan index](../README.md) · **Milestone M3** · [canonical spec: T15](../../features/15-location-stickers.md) · [stream-types-v1](../../../api/stream-types-v1.md) · [threat model](../../../security/threat-model.md)

# Feature 15 — Location Sharing & Sticker Libraries (Tier-1 completion)

**Milestone:** M3 · **Depends on:** Feature 09, Feature 11 (Feature 12 for mobile location UX) ·
**Canonical spec:** [T15](../../features/15-location-stickers.md).

**Goal (from spec).** The two remaining Tier-1 stream types — both **purely against the registry (zero
core changes)** — with live-location auto-expiry and the decentralized signed sticker-pack model.
Location is the most privacy-sensitive Tier-1 feature; **`[SEC]`** with the expiry-no-"forever" constraint
(A4) held firm.

**Exit acceptance (spec §Acceptance).** Expiry enforced on both ends within ±5 s; fuzzed precision provably
quantized **before encryption** (unit test on plaintext coords); tampered sticker chunk fails BLAKE3 and is
not installed; air-gapped map renders with **zero external egress**; both features implemented without
touching core session code (CODEOWNERS-enforced).

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F15.1 | `mrd.location/1` static pin (chat message) + live mode (unreliable-unordered, ≤1 Hz deltas) | [ADR][SEC] | M3 F09 | ☐ |
| F15.2 | Mandatory-expiry grant (15 m/1 h/8 h; no "forever") + sender stop + recipient TTL (belt & braces) | [SEC] | F15.1 | ☐ |
| F15.3 | Precision options (exact / ~1 km fuzz) quantized before encryption | [SEC] | F15.1 | ☐ |
| F15.4 | Map render (browser/desktop) with offline/air-gapped tile source (no hardcoded public URL) | [SEC] | F15.1 | ☐ |
| F15.5 | `mrd.sticker/1` content-addressed packs (BLAKE3 root = id) signed by author key, fetched P2P via `mrd.file/1` | [ADR][SEC] | F09 | ☐ |
| F15.6 | Pack install/trust UX (author key shown) + `meridian sticker pack` creation CLI | — | F15.5 | ☐ |
| F15.7 | `location-privacy.md` + `stream-types-v1.md` sections + signed community demo pack | [SEC] | F15.2, F15.5 | ☐ |

- **F15.1 [ADR][SEC]** — location stream, zero core edits. Tests: static + live modes; core diff empty. DoD 3,6.
- **F15.2 [SEC]** — the deliberate product constraint: **no "forever"**; enforced sender-side stop *and* recipient-side TTL. Tests: both ends end within ±5 s; sender-kill still ends on time. DoD 4.
- **F15.3 [SEC]** — fuzz quantized **on plaintext coords before encryption**. Tests: unit test asserts quantization pre-encryption. DoD 4.
- **F15.4 [SEC]** — air-gapped map tiles; **never a hardcoded public tile URL** (egress leak). Tests: air-gapped render, zero external egress. DoD 4,7.
- **F15.5 [ADR][SEC]** — signed content-addressed packs via file machinery; tampered chunk fails BLAKE3. Tests: tampered pack not installed. DoD 3,4,6.
- **F15.6** — install/trust UX shows the author key (org registry = an ordinary signing account). Tests: install flow; cached re-send renders instantly. DoD 4.
- **F15.7 [SEC]** — privacy note (what A4 gets = whatever you granted, until expiry — no more) + demo pack signed by a community author key distinct from any org. DoD 7.
