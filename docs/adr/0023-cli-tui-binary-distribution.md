<!-- Source: this decision (executable-pipeline-windows-linux task, corrected scope). -->
> **Nav:** [ADR index](./README.md) · [release-binaries.md](../operations/release-binaries.md) ·
> supersedes [ADR 0022](./0022-release-binary-distribution.md) · precedent
> [ADR 0019](./0019-container-image-distribution.md) (same trade-offs, container channel) ·
> [ADR 0020](./0020-tui-packaging.md) (what's actually inside this binary)

# ADR 0023: Native executable release channel for `meridian` (CLI/TUI client)

**Corrects [ADR 0022](./0022-release-binary-distribution.md):** that ADR built and published
`meridian-rendezvous` — the **server** — under the (mistaken) assumption that "an executable
pipeline" meant the same binary as the just-added Docker image. The actual ask is the **client**:
a `meridian` binary a person downloads and runs locally to get `meridian tui` (the interactive
ratatui client, [ADR 0020](./0020-tui-packaging.md)) working, with no `cargo build` required. This
ADR keeps 0022's platform/build/release-policy/signing reasoning (still sound, restated below only
where the subject change actually matters) and redirects the pipeline at `meridian-cli`.

**Options — which binary:** (A) `meridian-rendezvous` (0022's original choice); (B) **`meridian`
(`meridian-cli`, `tui` feature default-on per [ADR 0020](./0020-tui-packaging.md), chosen)**.
**Trade-offs:** A is a server operators run on infra they control — already covered by the Docker
image (ADR 0019) for the deployment shapes that matter, and not what was asked for. B is what a
person runs on their own laptop; it has never had a distribution channel other than "clone the repo
and `cargo build`," which is a real barrier for a non-Rust-developer who just wants to try the TUI.
**Decision: B.** `cargo build --release -p meridian-cli` (default features — `tui` is default-on,
so the resulting binary has `meridian tui`; **not** `--no-default-features`, which is the lean
demo/CI shape ADR 0020 condition 2 protects, not what a release binary should ship).

**Options — trigger:** (A) keep coupling to `docker-publish.yml`'s trigger, as 0022 did; (B)
**an independent trigger scoped to `meridian-cli`'s own dependency graph (chosen)**.
**Trade-offs:** the client and server are different binaries built from disjoint parts of the
workspace (`meridian-cli`'s release build does not link `meridian-rendezvous` at all — it's only a
dev-dependency, for tests) with no shared inputs worth coupling on; A was only ever correct under
0022's mistaken premise that this was "the same pipeline as the Docker image." **Decision: B** —
`release-binaries.yml`'s path filter is `apps/**` minus `apps/rendezvous/**` (meridian-cli's whole
transitive dependency graph: core, tui, identity, store, crypto, transport, signaling, proto,
envelope) plus `Cargo.toml`/`Cargo.lock`/the workflow file itself.

**Options — which platforms, how to build Windows, release policy, signing:** unchanged from
[ADR 0022](./0022-release-binary-distribution.md#options--which-platforms) — Linux + Windows
`x86_64` only, Windows built natively on `windows-latest` with `ilammy/setup-nasm` (ring's asm
build step, pulled in via `meridian-signaling`'s always-on `wss://` client — **not** feature-gated
behind `tui`, so this dependency holds even for a hypothetical `--no-default-features` build), a
rolling release updated on every qualifying push (renamed **`cli-latest`**, was `rendezvous-latest`)
with the short commit sha in each asset's filename, and a `.sha256` checksum with no signature yet.
See 0022 for the full trade-off writeups — they were never about which binary, so nothing there
needed re-litigating.

**Options — what to bundle in the archive:** (A) the binary alone; (B) **the binary alone (chosen)**
— no config file. **Trade-offs:** unlike the server (0022 bundled `rendezvous.example.toml`, a
required input to boot), `meridian`/`meridian tui` needs no config file to start — `config.toml`
(TUI) and any CLI-side config are created/discovered by the binary itself at
`$MERIDIAN_HOME` on first run ([tui-client.md §5](../architecture/tui-client.md#5-local-store--configuration),
[ADR 0021](./0021-client-local-store-config-formats.md)), so there is nothing meaningful to seed the
archive with. **Decision: A/B** (same option either way) — ship just `meridian` /
`meridian.exe` (+ its `.sha256`).

## Accepted residual risk

> **R1 — Unsigned binaries, no build provenance**, identical in shape and trigger-to-reopen to
> [ADR 0022's R1](./0022-release-binary-distribution.md#accepted-residual-risk) (see there for the
> full statement) — nothing about the residual itself changed by retargeting which binary ships.

**Consequence:** [`release-binaries.yml`](../../.github/workflows/release-binaries.yml) now builds
and publishes the `meridian` client binary (Linux + Windows `x86_64`) to the `cli-latest` rolling
release, decoupled from `docker-publish.yml`; [`release-binaries.md`](../operations/release-binaries.md)
is rewritten for a client audience (download, verify, `meridian tui`) rather than an operator one;
this file plus the [ADR index](./README.md) row and [ADR 0022](./0022-release-binary-distribution.md)'s
superseded-by note are the rest of this ADR's deliverable.

**No TUI surface.** Same as 0022 — this is CI/release-infra (Definition of Done gate 9), not an
in-app feature; it has no stream-type renderer, palette command, or pane of its own. (It is, notably,
the delivery mechanism *for* the TUI binary itself, which is not the same thing as a TUI surface for
this change.)
