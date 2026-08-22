# `meridian-rendezvous` native executables (Linux + Windows)

<!-- Source: this decision (executable-pipeline-windows-linux task). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) ·
> [the Docker image](./docker-image.md) (companion channel, same trigger) ·
> [ADR 0022](../adr/0022-release-binary-distribution.md) (why + trade-offs) ·
> precedent [ADR 0019](../adr/0019-container-image-distribution.md)

## 1. What publishes it

[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml) builds
`meridian-rendezvous` for **Linux (`x86_64-unknown-linux-gnu`)** and **Windows
(`x86_64-pc-windows-msvc`)** and publishes both to a rolling GitHub Release tagged
**`rendezvous-latest`**, on the exact same trigger as
[`docker-publish.yml`](../../.github/workflows/docker-publish.yml) — every push to `main` touching
`apps/rendezvous/**`, `apps/proto/**`, `Cargo.toml`, or `Cargo.lock`. A Docker image publish and a
binary release therefore always happen together, from the same commit.

Both binaries are built with the `sqlite` feature (real, on-disk persistence — same as the
container image, see [docker-image.md §1a](./docker-image.md#1a-the-pre-merge-docker-build-gate)),
so they behave identically to the image, just without a container runtime.

Why a rolling release instead of one release per version, why `x86_64` only, why unsigned for
now — see [ADR 0022](../adr/0022-release-binary-distribution.md).

## 2. Downloading

Grab the latest build from the release page:
**`github.com/hansajayathilaka/meridian/releases/tag/rendezvous-latest`**

Each asset is named `meridian-rendezvous-<os>-x86_64-<short-sha>.<ext>` (`.tar.gz` for Linux,
`.zip` for Windows) and ships alongside a `.sha256` file. Verify before running:

```bash
# Linux
sha256sum -c meridian-rendezvous-linux-x86_64-<sha>.tar.gz.sha256
tar xzf meridian-rendezvous-linux-x86_64-<sha>.tar.gz
```

```powershell
# Windows (PowerShell)
Get-FileHash .\meridian-rendezvous-windows-x86_64-<sha>.zip -Algorithm SHA256
# compare against the .sha256 file's contents
Expand-Archive .\meridian-rendezvous-windows-x86_64-<sha>.zip
```

Each archive contains the executable (`meridian-rendezvous` / `meridian-rendezvous.exe`) plus
[`rendezvous.example.toml`](../../apps/rendezvous/rendezvous.example.toml) — copy that to
`rendezvous.toml`, edit it, and pass `--config rendezvous.toml`, or leave it as-is and drive
everything via `MERIDIAN_RENDEZVOUS_<SECTION>__<FIELD>` environment variables (same figment-based
merge as the container image, [ADR 0018](../adr/0018-rendezvous-config-loading.md)).

```bash
./meridian-rendezvous --config rendezvous.toml
```

`:latest`/`rendezvous-latest` is **floating** — it moves on every publish, same caveat as the
Docker image's `:latest` tag ([docker-image.md §4](./docker-image.md#4-tags)): pin the `<short-sha>`
in the filename if you need a specific, reproducible build rather than "whatever `main` most
recently built."

## 3. What this is *not*

- **Not signed.** No cosign/minisign signature, no build-provenance attestation — only a SHA-256
  checksum, which protects against corruption/truncation in transit, not against a compromised
  publish credential. Same accepted residual as the container image; see
  [ADR 0022's residual risk](../adr/0022-release-binary-distribution.md#accepted-residual-risk).
- **Not a versioned release.** There is no `v0.x.y` tag yet (`apps/rendezvous/Cargo.toml` is still
  `version = "0.0.0"`) — `rendezvous-latest` is a continuously-replaced build, marked as a
  GitHub *pre-release* so it reads correctly once real tagged releases exist alongside it.
- **Not macOS or `aarch64`.** Only Linux + Windows `x86_64`, per the task that requested this
  pipeline. See ADR 0022 for why those weren't included yet.
