<!-- Source: this decision (executable-pipeline-windows-linux task). -->
> **Nav:** [ADR index](./README.md) · [release-binaries.md](../operations/release-binaries.md) ·
> precedent [ADR 0019](./0019-container-image-distribution.md) (same trade-offs, container channel)

# ADR 0022: Native executable release channel for `meridian-rendezvous`

**Status:** **Superseded by [0023](./0023-cli-tui-binary-distribution.md).** The task that opened
this ADR was clarified, shortly after this landed, to want the **`meridian` CLI/TUI client**
binary, not the `meridian-rendezvous` **server** binary this ADR describes — the two are unrelated
distribution channels (client vs. server) that happened to get conflated in the original ask. The
platform/build/release-policy/signing *reasoning* below (Linux+Windows x86_64, native Windows build
+ nasm, rolling release, checksums-not-signatures) carries over unchanged to 0023; only the *subject*
(which binary, which trigger) changes. This ADR is kept for the record rather than deleted — nothing
in `release-binaries.yml` builds `meridian-rendezvous` anymore as of 0023.

**Context:** [ADR 0019](./0019-container-image-distribution.md) covers the `ghcr.io` container
image, but an operator who doesn't want Docker (a bare VM, a Windows host, an air-gapped box with no
container runtime) has had no way to get a `meridian-rendezvous` binary except building from source.
This ADR adds a second, independent distribution channel — native executables — built by a new
[`release-binaries.yml`](../../.github/workflows/release-binaries.yml) workflow on the **same
trigger** (path filters + push-to-`main`) as [`docker-publish.yml`](../../.github/workflows/docker-publish.yml),
so an image publish and a binary release always happen together.

**Options — which platforms:** (A) Linux only (matches the container image's `linux/amd64`); (B)
**Linux + Windows x86_64 (chosen)**; (C) Linux + Windows + macOS.
**Trade-offs:** the task that opened this ADR asked for Windows and Linux specifically. macOS (C)
would need a third runner and a code-signing/notarization story (unsigned `.app`/binaries trigger
Gatekeeper warnings) this project has no resourcing for yet, same class of deferral as ADR 0019's
signing residual — left for a future ADR if an operator actually asks. **Decision: B**, `x86_64`
only (no `aarch64` cross-build yet — `ring`'s asm build step and `sqlx`'s bundled-sqlite `cc` step
both add per-target friction that isn't worth taking on speculatively).

**Options — how to build Windows:** (A) cross-compile from the Linux runner (e.g. via `cross` +
mingw); (B) **build natively on `windows-latest` (chosen)**.
**Trade-offs:** the `sqlite` feature (this workflow builds with it, matching the container image so
the two channels stay behaviourally identical) pulls in `libsqlite3-sys`'s bundled C build via `cc`,
and the mTLS federation link ([task 2.4](../tasks/phase-2/2.4-s2s-mtls-link.md)) pulls in
`ring`'s x86_64 assembly build step — both are meaningfully more fragile to get right under a
Linux-hosted mingw cross toolchain than under MSVC on a native Windows runner, which already ships
the C++ build tools `cc` needs. The extra runner-cost is negligible at this project's CI volume.
**Decision: B** — `windows-latest`, MSVC target (`x86_64-pc-windows-msvc`), with
`ilammy/setup-nasm` added for `ring`'s asm step (not preinstalled on that runner image).

**Options — release policy:** (A) one immutable release per git tag only (no binaries until a
versioned release exists); (B) **a rolling `rendezvous-latest` release, updated on every qualifying
push to `main`, each asset filename carrying the short commit sha (chosen)**; (C) upload as
workflow-run artifacts only, no GitHub Release.
**Trade-offs:** A blocks this from shipping anything until this pre-1.0, currently-unversioned
project (`apps/rendezvous/Cargo.toml`'s `version = "0.0.0"`) cuts its first tag — an unknown, and
possibly distant, future event — for no benefit today. C is discoverable only to someone who already
knows to look at Actions run history, and workflow artifacts expire (repo default retention),
unlike a Release. B mirrors [ADR 0019](./0019-container-image-distribution.md)'s already-accepted
`:latest` + `:<short-sha>` split for the exact same reason: a convenient, always-current default
(`rendezvous-latest`) for someone who just wants "the current build," with the short sha in every
asset's filename and in the release notes giving anyone who needs it commit-level traceability, at
no extra publish cost. **Decision: B.** The release is marked `prerelease: true` — it is a
continuously-replaced build, not a versioned release — so it reads correctly once real tagged
releases exist alongside it.

**Options — signing / provenance:** (A) sign now (cosign / minisign); (B) **defer, publish a
SHA-256 checksum per asset, no signature (chosen)**; (C) ship nothing, not even a checksum.
**Trade-offs:** identical reasoning to [ADR 0019's signing residual](./0019-container-image-distribution.md#accepted-residual-risks)
— no tagged release, no known external consumer yet, and the maintainer already carries the
equivalent unsigned-artifact residual for the container image. A checksum (C's gap) at least lets a
downloader confirm a file wasn't corrupted or truncated in transit even without confirming who built
it, at zero pipeline cost. **Decision: B.**

## Accepted residual risk

> **R1 — Unsigned binaries, no build provenance**, same shape and same weight class as
> [ADR 0019's R1](./0019-container-image-distribution.md#accepted-residual-risks): a downloader has
> no cryptographic way to confirm a `rendezvous-latest` asset was actually built by this repo's CI
> from the commit its filename/release-notes sha implies, only that the bytes match the published
> `.sha256`. **Trigger to reopen:** the same trigger as ADR 0019's R1 — the first tagged release, or
> the first point a third party is told to download this binary for their own deployment. Whichever
> comes first should land both this ADR's signing (cosign/minisign, or reuse whatever ADR 0019's
> reopening lands for the image) and ADR 0019's, together, rather than solving it twice.

**Consequence:** [`release-binaries.yml`](../../.github/workflows/release-binaries.yml) builds and
publishes Linux + Windows `x86_64` binaries alongside the container image;
[`release-binaries.md`](../operations/release-binaries.md) documents the operator-facing download
and verification steps; this file plus the [ADR index](./README.md) row and cross-links from
[docker-image.md](../operations/docker-image.md) and
[operations/README.md](../operations/README.md) are the rest of this ADR's deliverable.

**No TUI surface.** This is a CI/release-infra change (Definition of Done gate 9) — it has no
in-app behavior for any client to render, so it has no stream-type renderer, palette command, or
pane, same as `docker-publish.yml`/`docker-image.md` before it.
