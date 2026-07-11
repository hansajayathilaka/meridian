<!-- Source: tasks/T15-location-stickers.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T15 — Location Sharing & Sticker Libraries (Tier-1 completion)

**Priority:** P4 · **Design refs:** §5.3 (stream table) · **Depends on:** T09, T11 (T12 for mobile location UX) · **Indicative effort:** 2 eng-weeks

## Goal
Complete Tier-1 with the two remaining stream types — both implemented purely against the registry contract (like T09, zero core changes allowed) — demonstrating live-location semantics with auto-expiry and the decentralized, signed sticker-pack model.

## Scope
In: `mrd.location/1` — static pin as a chat message; live mode as an unreliable-unordered stream, deltas ≤ 1 Hz, **grant with mandatory expiry** (15 min/1 h/8 h; no "forever"), recipient-visible countdown, sender one-tap stop; map render in browser/desktop (offline-capable tile source for air-gapped orgs — bundled region tiles or org tile server; never a hardcoded public tile URL, which would be an egress leak in air-gapped mode); `mrd.sticker/1` — packs as content-addressed bundles (BLAKE3 root = pack id) signed by the author's account key, fetched P2P from the sender via `mrd.file/1`, cached; pack install/trust UX (author key shown; org registry = an ordinary account publishing signed manifests, §5.3); custom pack creation CLI (`meridian sticker pack ./dir`).
Out: geofencing/location history (never — state it), animated sticker formats beyond webp/apng, any server-side sticker store.

## Deliverables
1. Both stream types + spec sections in `stream-types-v1.md`.
2. Privacy note `location-privacy.md`: precision options (exact / ~1 km fuzz), expiry enforcement point (sender-side stop *and* recipient-side TTL — belt and braces), and what a compromised peer (A4) gets (answer: whatever you granted, until expiry — no more).
3. Demo sticker pack signed by a "community author" key distinct from any org.

## Working output (demo script)
```
$ meridian location share mrd1:<bob>… --live --expires 15m
  — bob's desktop shows moving pin + 14:59 countdown; at 0:00 the stream closes itself
  — sender kills client mid-grant → recipient-side TTL still ends the share on time
$ meridian sticker pack ./my-pack && meridian sticker send <bob> my-pack/wave
  — bob: "install pack 'my-pack' by mrd1:kq3f… (unverified author)?" → installed, cached,
    subsequent sends render instantly without refetch
$ opacity audit: location deltas and pack bytes — ciphertext only, servers never in path
```

## Acceptance criteria
Expiry enforced on both ends within ±5 s; fuzzed precision provably quantized before encryption (unit test on plaintext coords); pack with a tampered chunk fails BLAKE3 verification and is not installed; air-gapped map renders with zero external egress; both features implemented without touching core session code (enforced by CODEOWNERS on the core crate).

## Risks / notes
Location is the most privacy-sensitive Tier-1 feature; the expiry-with-no-forever-option is a deliberate product constraint from the threat model (A4) — resist relaxing it.
