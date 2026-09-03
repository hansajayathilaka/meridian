<!-- Source: Phase-12 planning architect consult (T11). -->
> **Nav:** [ADR index](./README.md) · [release-binaries.md](../operations/release-binaries.md) ·
> precedent [ADR 0019](./0019-container-image-distribution.md) · [ADR 0022](./0022-release-binary-distribution.md) ·
> [ADR 0023](./0023-cli-tui-binary-distribution.md) (all three: deferred signing, named residual/trigger)

# ADR 0027: Desktop updater signing — Tauri updater-plugin signatures now, OS-trusted (Authenticode) signing still deferred

**Context.** ADR 0022/0023 deliberately deferred code signing for the rendezvous-server and CLI/TUI
release channels ("no tagged release, no known external consumer yet... publish a SHA-256 checksum, no
signature"). T11's own feature spec
([11-browser-desktop-clients.md](../architecture/features/11-browser-desktop-clients.md)) lists as an
explicit deliverable and acceptance criterion: "signed desktop release + updater with signature
verification (§9.4)" and "desktop updater rejects an unsigned/tampered update in test" — an **auto-apply**
path is a materially different risk than a passive checksum-verified download, so this crosses 0022/0023's
own reopening trigger for this one channel specifically. This ADR records that as a conscious, scoped
exception, not a silent reversal of the project's overall signing posture.

**Options — what gets signed:** (A) full OS-trusted code signing (an Authenticode cert for the Windows
MSI/installer, plus macOS notarization for a future build) *and* updater-level signing; (B) **updater-level
signing only — Tauri's built-in updater plugin, its own Ed25519/minisign-style scheme (a bundled public
key in `tauri.conf.json`, private key held by the release pipeline, a `.sig` sidecar per artifact,
verified by the app itself before applying an update) — no OS-trusted Authenticode/notarization cert
(chosen)**; (C) no signing at all, same as 0022/0023's original scope — T11's acceptance criterion goes
unmet as written.

**Trade-offs.** A is the correct end state but needs a purchased/EV code-signing certificate — a standing
cost and identity-verification process this single-maintainer, pre-1.0 project has no more budget for now
than it did for ADR 0019/0022's own residuals — and buys nothing for the specific property T11's
acceptance criterion actually names: "the updater rejects an unsigned/tampered update" is a property of
the *updater's own* verification, not of Windows SmartScreen/Authenticode. C fails T11's stated acceptance
bar outright, which the feature spec clearly intends to be met, not silently dropped. B satisfies the
acceptance criterion honestly and at near-zero cost — Tauri's updater plugin ships this scheme built in;
the only project cost is running `tauri signer generate` once and treating the resulting private key like
any other release secret in CI — while being explicit that installing the *first* copy of the app (the
MSI itself, before any updater is in the loop) still triggers an unsigned-publisher OS warning, the same
residual class as ADR 0022/0023's R1, not newly introduced here. **Decision: B.**

**Options — where the updater's signing private key lives:** (A) **a GitHub Actions repo secret
(`TAURI_SIGNING_PRIVATE_KEY` + passphrase), ephemeral per-run access via `secrets.*`, matching the
existing CI-secret posture (chosen)**; (B) a long-lived external HSM/KMS.

**Trade-offs.** B is real infrastructure this project has no operational capacity for, the same reasoning
ADR 0019 used to reject a self-hosted registry. A is the standing-credential trade-off ADR 0018/0019
already accept elsewhere in this repo for less security-sensitive material — here it is more sensitive (a
compromised key lets an attacker push a malicious auto-applied update to every installed copy), so it is
named as a heavier residual than 0019/0022's own, not conflated with them. **Decision: A**, with the
residual below stated explicitly rather than treated as free.

**Options — installer-level (Authenticode) signing:** (A) **defer, same trigger as ADR 0022/0023's R1
residual (chosen)**; (B) do it now.

**Trade-offs.** Unchanged from 0022/0023's own reasoning: no tagged release, no named external consumer
yet. **Decision: A** — deferred, same trigger (first tagged release, or the first point a third party is
told to download this installer); this ADR closes only the updater-signature gap T11's acceptance
criterion requires, not 0022/0023's broader deferral.

## Accepted residual risks

**R1 — the desktop MSI itself is still unsigned at the OS level** (Windows SmartScreen /
"unknown publisher" warning on first install). Identical in shape and trigger to
[ADR 0022's R1](./0022-release-binary-distribution.md#accepted-residual-risk) / 0023's carried-forward
residual — not newly accepted by this ADR, only reconfirmed as still open for the desktop channel too.

**R2 — the updater's minisign-style private key is a standing CI secret.** If compromised, an attacker
can push a malicious signed update that every installed copy would auto-apply and trust — a materially
higher-stakes compromise than 0019/0022's own standing-secret residuals, since those gate a passive
download/pull rather than an auto-applied update. **Trigger to reopen:** any real user base beyond the
maintainer(s)/testers, at which point key rotation plus a documented incident-response step (revoke the
old public key, ship a new one via a manually-verified out-of-band release) should land alongside
whatever ADR 0019/0022's own reopening does.

## Consequence

`apps/desktop`'s Tauri config wires `tauri-plugin-updater` with the bundled public key; a new (or
extended) release-pipeline step signs each desktop artifact with the CI-held private key; T11's
acceptance test drives an update with a tampered/missing signature and asserts rejection. This is the
minimal path that makes the feature spec's stated acceptance criterion true without inventing
signing infrastructure this project cannot sustain.
