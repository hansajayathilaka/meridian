# `meridian` (CLI/TUI client) native executables (Linux + Windows)

<!-- Source: this decision (executable-pipeline-windows-linux task). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) ·
> [TUI client design](../architecture/tui-client.md) ·
> [ADR 0023](../adr/0023-cli-tui-binary-distribution.md) (why + trade-offs) ·
> superseded design: [ADR 0022](../adr/0022-release-binary-distribution.md) ·
> precedent [ADR 0019](../adr/0019-container-image-distribution.md) (the Docker image — a different,
> unrelated channel for the **server**, `meridian-rendezvous`; this page is about the **client**)

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
