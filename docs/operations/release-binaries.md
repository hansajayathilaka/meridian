# `meridian` (CLI/TUI client) native executables (Linux + Windows)

<!-- Source: this decision (executable-pipeline-windows-linux task); §4 added by task 12.16
     (desktop signed updater pipeline). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) ·
> [TUI client design](../architecture/tui-client.md) ·
> [ADR 0023](../adr/0023-cli-tui-binary-distribution.md) (why + trade-offs) ·
> superseded design: [ADR 0022](../adr/0022-release-binary-distribution.md) ·
> precedent [ADR 0019](../adr/0019-container-image-distribution.md) (the Docker image — a different,
> unrelated channel for the **server**, `meridian-rendezvous`; this page is about the **client**) ·
> [ADR 0027](../adr/0027-desktop-signed-updates.md) (§4 below — the **desktop** client's own channel,
> the one exception to this repo's "unsigned for now" posture)

## 1. What publishes it

[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml) builds the
`meridian` client binary — `meridian-cli` with its default features, so `tui` (the `meridian tui`
subcommand, [ADR 0020](../adr/0020-tui-packaging.md)) is included — for **Linux
(`x86_64-unknown-linux-gnu`)** and **Windows (`x86_64-pc-windows-msvc`)**, and publishes both to a
rolling GitHub Release tagged **`cli-latest`**. It fires on every push to `main` that touches
`meridian-cli`'s own dependency graph (`apps/**` other than `apps/rendezvous/**`, plus
`Cargo.toml`/`Cargo.lock`) — independent of, and unrelated to, the
[Docker image pipeline](./docker-image.md), which ships the server.

Why this binary and not the server, why `x86_64` only, why unsigned for now — see
[ADR 0023](../adr/0023-cli-tui-binary-distribution.md).

## 2. Downloading

Grab the latest build from the release page:
**`github.com/hansajayathilaka/meridian/releases/tag/cli-latest`**

Each asset is named `meridian-<os>-x86_64-<short-sha>.<ext>` (`.tar.gz` for Linux, `.zip` for
Windows) and ships alongside a `.sha256` file. Verify before running:

```bash
# Linux
sha256sum -c meridian-linux-x86_64-<sha>.tar.gz.sha256
tar xzf meridian-linux-x86_64-<sha>.tar.gz
cd meridian-linux-x86_64
./meridian tui
```

```powershell
# Windows (PowerShell)
Get-FileHash .\meridian-windows-x86_64-<sha>.zip -Algorithm SHA256
# compare against the .sha256 file's contents
Expand-Archive .\meridian-windows-x86_64-<sha>.zip
cd meridian-windows-x86_64
.\meridian.exe tui
```

The archive contains only the binary — no config file. `meridian tui` (and every other `meridian`
subcommand) creates and reads its own local store/config under `$MERIDIAN_HOME` on first run; see
[tui-client.md §5](../architecture/tui-client.md#5-local-store--configuration) for the schema.
`meridian --help` lists every subcommand (identity, account, contacts, chat, `tui`, …) — the TUI is
one entry point among several, not a separate program.

`cli-latest` is **floating** — it moves on every publish, same caveat as the Docker image's
`:latest` tag ([docker-image.md §4](./docker-image.md#4-tags)): pin the `<short-sha>` in the
filename if you need a specific, reproducible build rather than "whatever `main` most recently
built."

## 3. What this is *not*

- **Not signed.** No cosign/minisign signature, no build-provenance attestation — only a SHA-256
  checksum, which protects against corruption/truncation in transit, not against a compromised
  publish credential. See [ADR 0023's residual risk](../adr/0023-cli-tui-binary-distribution.md#accepted-residual-risk).
- **Not a versioned release.** There is no `v0.x.y` tag yet — `cli-latest` is a continuously-replaced
  build, marked as a GitHub *pre-release* so it reads correctly once real tagged releases exist.
- **Not macOS or `aarch64`.** Only Linux + Windows `x86_64` for now.
- **Not the server.** `meridian-rendezvous` (the signaling server an org self-hosts) has its own,
  separate distribution channel — [the Docker image](./docker-image.md). This page is the client
  only.

## 4. Desktop channel (`meridian-desktop`, ADR 0027 — signed updater)

The CLI/TUI channel above is **unsigned** (§3). The **desktop** client (`meridian-desktop`, the Tauri
v2 shell, [ADR 0010](../adr/0010-desktop-shell-tauri.md)) is the one deliberate exception: task
12.16 wires up [`tauri-plugin-updater`](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/updater)'s
own Ed25519/minisign-style signature scheme, per [ADR 0027](../adr/0027-desktop-signed-updates.md),
because an **auto-applied** update is a materially different risk than a passive checksum-verified
download — T11's own acceptance criterion ("desktop updater rejects an unsigned/tampered update in
test") requires it.

**What publishes it:** [`.github/workflows/release-desktop.yml`](../../.github/workflows/release-desktop.yml)
builds the `meridian-desktop` binary (Linux + Windows `x86_64`, same platform scope as the CLI
channel above and the same reasoning — see [ADR 0022](../adr/0022-release-binary-distribution.md#options--which-platforms)),
signs each packaged artifact with the CI-held private key, and publishes to a rolling
**`desktop-latest`** GitHub Release alongside a `latest.json` static-JSON update manifest. The app's
own bundled public key (`apps/desktop/tauri.conf.json`'s `plugins.updater.pubkey`) verifies every
downloaded artifact's signature client-side before applying it —
`apps/desktop/tests/updater_rejects_tampered.rs` is the acceptance test proving that verification
actually rejects a tampered/missing signature.

**Two residual risks are explicitly accepted, not silently left undocumented** (see
[ADR 0027](../adr/0027-desktop-signed-updates.md#accepted-residual-risks) for the full trade-off
writeups):

- **R1 — the desktop MSI/installer itself is still unsigned at the OS level** (Windows SmartScreen /
  "unknown publisher" warning on first install). Identical in shape and trigger to this page's own
  §3 residual and [ADR 0022's R1](../adr/0022-release-binary-distribution.md#accepted-residual-risk)
  — updater-plugin signing (this section) only covers *updates*, never the first install. Real
  platform installer bundling (`apps/desktop/tauri.conf.json`'s `bundle.active`, currently `false`
  since task 12.3) and any OS-trusted Authenticode/notarization signing remain deferred, same trigger
  as §3's residual: the first tagged release, or the first point a third party is told to download
  this installer.
- **R2 — the updater's minisign-style private key is a standing CI secret**
  (`TAURI_SIGNING_PRIVATE_KEY` + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, GitHub Actions repo secrets),
  a heavier-weight residual than this page's own §3/ADR 0019's standing-secret risk: if compromised,
  an attacker can push a malicious update that every installed copy would auto-apply and trust, not
  just a passive download an operator chooses to run. **Trigger to reopen:** any real user base
  beyond the maintainer(s)/testers — at which point key rotation plus a documented
  incident-response step (revoke the old public key, ship a new one via a manually-verified
  out-of-band release) should land.

**Provenance of the signing key itself:** as of this task, `TAURI_SIGNING_PRIVATE_KEY`/
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` are **not yet set** as real repo secrets, and no real production
signing keypair has been generated — `release-desktop.yml` references them by name only
(`${{ secrets.* }}`), so the signing step fails closed (no key configured) rather than silently
shipping unsigned releases under a channel name that implies otherwise. `TODO: confirm` — a human
operator with real repo-admin access must run `cargo tauri signer generate` for real, commit the
resulting **public** key into `apps/desktop/tauri.conf.json`'s `plugins.updater.pubkey` (replacing
the placeholder there), and set the **private** key + password as the two GitHub Actions secrets
above before this pipeline signs an actual release.
