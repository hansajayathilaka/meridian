# The `meridian-rendezvous` Docker image

<!-- Source: this decision (GitHub Container Registry publish pipeline). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment](./deployment.md) ·
> [rendezvous-protocol-v1 §5 (full config surface)](../api/rendezvous-protocol-v1.md#5-config-surface-the-92-subset) ·
> [ADR 0018 (figment config loading)](../adr/0018-rendezvous-config-loading.md) ·
> [ADR 0019 (image distribution + signing)](../adr/0019-container-image-distribution.md) ·
> [native executables (Linux + Windows)](./release-binaries.md) — companion channel, same trigger

## 1. What publishes it

[`.github/workflows/docker-publish.yml`](../../.github/workflows/docker-publish.yml) builds
[`apps/rendezvous/Dockerfile`](../../apps/rendezvous/Dockerfile) and pushes it to the **GitHub
Container Registry (`ghcr.io`)** as `ghcr.io/<owner>/meridian-rendezvous` **every time a PR merges
to `main`** that touches `apps/rendezvous/**`, `apps/proto/**`, `Cargo.toml`, or `Cargo.lock`. For
this repository that resolves to `ghcr.io/hansajayathilaka/meridian-rendezvous`. That path filter is
exhaustive by construction: the rendezvous server depends on nothing else in the workspace —
enforced by [`tools/lint-server-no-core.sh`](../../tools/lint-server-no-core.sh) — so a merge
touching any other crate cannot change the image and is skipped rather than publishing an identical
rebuild.

The `ghcr.io` channel, the `:latest` + `:<short-sha>` tag policy, and the decision to defer image
signing/provenance for now (with a named residual and reopening trigger) are ratified in
[ADR 0019](../adr/0019-container-image-distribution.md) — read it before assuming a pulled image is
anything more than "built by this repo's CI from *some* commit"; there is currently no cryptographic
way to confirm which one.

The job does **not** re-run the test suite itself; it relies on branch protection already having
required [`ci.yml`](../../.github/workflows/ci.yml) to pass before a PR can merge to `main`.
`TODO: confirm` branch protection is actually configured that way on this repo — if it isn't, this
pipeline will happily publish an image from an untested commit.

> **This TODO cannot be resolved from an agent session.** Whether a GitHub branch-protection rule
> or ruleset actually requires `ci.yml` to pass before merging to `main` is a repo **Settings**
> fact (Settings → Branches, or Settings → Rules → Rulesets), not something visible in the
> checked-out tree, and no tool available in this environment (no MCP server, no `gh` CLI access)
> can read it. **A human with access to `github.com/<owner>/meridian/settings/branches` (or
> `/rules`) needs to check this directly** and either confirm the requirement is set (ideally as a
> required status check named for the `ci.yml` workflow, covering every job task 3.12 added — see
> §1a below) or add it if it's missing. Task
> [3.12](../tasks/phase-3/3.12-ci-docker-build-gate.md) added a build-only Docker gate to `ci.yml`
> itself (§1a), which strengthens the pre-merge check *if and only if* branch protection actually
> gates the merge on it — that dependency is exactly what this TODO is about.

### 1a. The pre-merge Docker build gate

As of task [3.12](../tasks/phase-3/3.12-ci-docker-build-gate.md) (fixing review finding F12),
[`ci.yml`](../../.github/workflows/ci.yml)'s `docker-build` job builds this same
`apps/rendezvous/Dockerfile` — plus a `docker run` smoke test asserting the container binds,
answers `/healthz`, and actually drops root (PID 1 runs as the unprivileged `meridian` user, not
just a fresh `docker exec` session, which defaults to root regardless of the entrypoint) — on
**every pull request**, before merge. It never pushes and never receives a registry credential (no
`docker/login-action`, no `packages: write`), so it cannot become a second path that leaks the
`docker-publish.yml` publish credential. This closes the F12 gap in principle — a broken
Dockerfile or entrypoint now fails a PR check instead of only surfacing after
`docker-publish.yml` runs on `main` — but only actually blocks a merge if branch protection
requires this job (or all of `ci.yml`) to pass first, which is exactly the unresolved fact in the
callout above.

The image is built with the `sqlite` cargo feature, so accounts and prekey bundles persist across
container restarts (SQLite file, `create_if_missing` + self-migrating — no separate migration step).
Postgres isn't wired up: `apps/rendezvous/Cargo.toml` only implements a `sqlite` backend today, so
there's nothing for a Postgres container to talk to yet.

The container starts as root and immediately drops to an unprivileged `meridian` user via
[`docker-entrypoint.sh`](../../apps/rendezvous/docker-entrypoint.sh) — application code never runs
as root. That entrypoint's only job before dropping privileges is `chown -R meridian:meridian
/data`: a fresh Docker named volume (or a bind-mounted host directory) is created root-owned, and
without this step the `meridian` user can't write into it, which surfaces as SQLite failing to boot
with `open SQLite store: Backend("error returned from database: (code: 14) unable to open database
file")` — code 14 is `SQLITE_CANTOPEN`, and permissions are the usual cause once the path itself is
right.

## 2. One-time repo setup

**No repository secrets to configure.** `ghcr.io` authenticates with the workflow's built-in
`GITHUB_TOKEN`; `docker-publish.yml` grants it `packages: write` and logs in as `${{ github.actor }}`,
so there are no `DOCKERHUB_*` (or any other) secrets or variables to set. This is the main reason for
publishing to `ghcr.io` rather than Docker Hub — the registry is scoped to the repo, the credential
is short-lived and never leaves the runner, and there is nothing to rotate.

The only manual step is a one-time **visibility** choice, done *after* the first publish:

1. Merge a change touching the rendezvous inputs so the workflow runs once. It creates a package
   named `meridian-rendezvous` linked to this repo (the `org.opencontainers.image.source` label
   wires that link automatically).
2. Open the package at **`github.com/users/<owner>/packages/container/meridian-rendezvous`** →
   **Package settings**. A new ghcr package is **private** by default: either set its visibility to
   **Public** (so `docker pull` needs no auth — the usual choice for a self-hostable server image),
   or keep it private and grant pull access to the accounts/deploy hosts that need it (a
   read-scoped Personal Access Token or, for org repos, the package's "Manage Actions access").

Credentials are never in the repo (root `CLAUDE.md` — "no secrets in the repo") and the image
itself carries none either: [`rendezvous.example.toml`](../../apps/rendezvous/rendezvous.example.toml)
baked into the image at `/etc/meridian/rendezvous.toml` has an empty `[turn].secret` and `open`
admission — every real secret and every per-deployment setting is supplied at container-run time
(§3 below), never at build time.

## 3. Changing settings at runtime — no rebuild needed

The image bakes in only defaults. Every key in the [§5 config surface](../api/rendezvous-protocol-v1.md#5-config-surface-the-92-subset)
can be overridden by setting a `MERIDIAN_RENDEZVOUS_<SECTION>__<FIELD>` environment variable on
the container (merged via `figment`, [ADR 0018](../adr/0018-rendezvous-config-loading.md)) — the
same mechanism whether you run the binary directly or in this image. List values use TOML/JSON
bracket syntax; a set-but-unparseable value is a fatal boot error, never a silent fallback.

```bash
docker run -d \
  --name meridian-rendezvous \
  -p 8443:8443 \
  -e MERIDIAN_RENDEZVOUS_SERVER__DOMAIN=chat.example \
  -e MERIDIAN_RENDEZVOUS_SERVER__ADMISSION=invite \
  -e MERIDIAN_RENDEZVOUS_SERVER__INVITE_TOKENS='["tok-a","tok-b"]' \
  -e MERIDIAN_RENDEZVOUS_TURN__SECRET="$TURN_SHARED_SECRET" \
  -e MERIDIAN_RENDEZVOUS_TURN__REALM=turn.chat.example \
  -e MERIDIAN_RENDEZVOUS_TURN__URLS='["turn:turn.chat.example:3478?transport=udp","turn:turn.chat.example:3478?transport=tcp","turns:turn.chat.example:443?transport=tcp"]' \
  ghcr.io/hansajayathilaka/meridian-rendezvous:latest
```

Or in compose form — see [`infra/deploy/docker-compose.yml`](../../infra/deploy/docker-compose.yml),
which wires `MERIDIAN_RENDEZVOUS_SERVER__DOMAIN`/`MERIDIAN_RENDEZVOUS_TURN__SECRET`/`MERIDIAN_RENDEZVOUS_TURN__REALM`
through `environment:` and expects `MERIDIAN_RENDEZVOUS_IMAGE` (the `image:` for the `rendezvous`
service) to be set to the published `ghcr.io/<owner>/meridian-rendezvous` path, e.g.:

```bash
export MERIDIAN_RENDEZVOUS_IMAGE=ghcr.io/hansajayathilaka/meridian-rendezvous:latest
export TURN_SHARED_SECRET=...   # out of band, never committed
docker compose -f infra/deploy/docker-compose.yml up -d
```

If you'd rather mount a full `rendezvous.toml` than set individual env vars, bind-mount it over
`/etc/meridian/rendezvous.toml` (the `ENTRYPOINT` in the Dockerfile already points `--config`
there); env vars still override whatever that file sets, per the same merge order as running the
binary standalone.

## 4. Tags

| Tag | Meaning |
|---|---|
| `:latest` | The most recently published build off `main`. Floating — moves on every publish. |
| `:<7-char-git-sha>` | Immutable, pins to the exact commit. Use this in production so a rollback is "repoint to the previous sha," not "hope `:latest` didn't change." |

## 5. Architecture

Published for `linux/amd64` only today (the CI runner's native arch — no QEMU emulation, fastest
build). To also publish `linux/arm64` (Raspberry Pi / ARM home-server self-hosting), change
`platforms: linux/amd64` to `platforms: linux/amd64,linux/arm64` in
[`docker-publish.yml`](../../.github/workflows/docker-publish.yml); expect the build step to take
noticeably longer since `docker/build-push-action` cross-compiles the second platform under
emulation.

## 6. Running this on Dokploy

[`infra/deploy/dokploy.compose.yml`](../../infra/deploy/dokploy.compose.yml) +
[`infra/deploy/dokploy.env.example`](../../infra/deploy/dokploy.env.example) are a ready-to-deploy
pair for [Dokploy](https://dokploy.com)'s "Docker Compose" application type (or any plain
`docker compose` host — Dokploy has no special requirements here beyond what any compose deploy
needs). Point a Dokploy compose app at this repo/file, copy `dokploy.env.example` into its
Environment tab, fill in the four required values, and deploy:

| Var | Required? | What it is |
|---|---|---|
| `RENDEZVOUS_IMAGE` | yes | The image `docker-publish.yml` pushed, e.g. `ghcr.io/hansajayathilaka/meridian-rendezvous:latest` — or pin a `:<short-sha>` tag (§4) for a reproducible deploy. If you kept the ghcr package **private** (§2), the deploy host must first `docker login ghcr.io` with a read-scoped token. |
| `MERIDIAN_RENDEZVOUS_SERVER__DOMAIN` | yes | Your public signaling hostname, e.g. `chat.example.com`. |
| `TURN_SHARED_SECRET` | yes | A long random value. Shared verbatim between the `rendezvous` and `coturn` services in the compose file — that's the whole trust mechanism for ephemeral TURN credentials (§"TURN / coturn" in [deployment.md](./deployment.md)). Generate one with `openssl rand -hex 32` and never commit it. |
| `TURN_EXTERNAL_IP` | yes | This host's public IP. coturn runs on Docker's bridge network (see below), so without this it hands clients its private container IP as the relay candidate and every relayed call fails. |

Everything else in the env file has a working default and only needs changing if you want to.
Every var maps 1:1 onto a config key documented in §3 above — the compose file just plumbs each one
through `${VAR:-default}` interpolation so Dokploy's flat env-var UI is the single place you edit
config, with no image rebuild and no editing the compose file itself for routine changes.

Three things that don't reduce to "just set an env var," each called out in comments in the compose
file itself:

- **Exposing the domain.** The compose file publishes the rendezvous container's port 8443 to the
  host (`RENDEZVOUS_PORT`, default 8443) but does not terminate TLS — same as every other deploy of
  this image (§2: TLS termination is the proxy/VIP's job, ADR-8). In Dokploy, add a Domain for the
  `rendezvous` service pointing at container port 8443 with HTTPS enabled; Dokploy's built-in Traefik
  handles the certificate and wss:// termination from there. **Do not set `RENDEZVOUS_PORT=443`** —
  Dokploy's own Traefik already owns host port 443, so this container fails to bind it too and never
  starts. Keep `RENDEZVOUS_PORT` at a free, non-privileged port and let the Domain feature do the
  443 exposure instead.
- **Federation (s2s, off by default).** `dokploy.compose.yml` ships a *commented-out* federation
  block (both the `ports:` publish and the `MERIDIAN_RENDEZVOUS_FEDERATION__*` env vars) — federation
  stays disabled (`federation.enabled` defaults `false`) until you uncomment it and supply cert/key
  material, discovery config, and a policy. **If and when you do enable it, port 8444 must be
  published as raw TCP passthrough only** — a bare Docker port mapping
  (`"${MERIDIAN_FEDERATION_PORT:-8444}:8444"`), exactly like `RENDEZVOUS_PORT`/8443 above. **Do not**
  add a second Dokploy Domain for it and route it through Traefik the way 8443 is routed above — that
  would proxy-terminate the federation TLS, which [ADR 0017 C7](../adr/0017-federation-trust-boundary.md)
  forbids. The two ports are *not* symmetric even though the compose file plumbs them the same
  `${VAR:-default}` way: c2s's 8443 is safe to terminate at Traefik by design (ADR 0008) because c2s
  peer identity comes from the post-TLS `Auth` signature, not the TLS layer itself; s2s federation has
  no such second factor — the mTLS handshake itself *is* the identity check — so it must terminate
  **in-process**, in the rendezvous binary, every time. Terminating it at a proxy instead would let
  anything upstream of that proxy assert any peer identity it likes, undoing the trust boundary
  [ADR 0017](../adr/0017-federation-trust-boundary.md)'s C1–C4 build. See
  [deployment.md §9.2](./deployment.md#92-config-surface-deliberately-small) for the full federation
  config surface and the private-CA/discovery-mode interaction, and the commented block in
  `dokploy.compose.yml`/`dokploy.env.example` for the exact vars to uncomment.
- **coturn's TURNS/443 rung.** `turnserver.conf` (T05) treats `turns://` on port 443 as the
  hostile-egress fallback rung, but on a Dokploy host port 443 is normally already owned by
  Dokploy's own Traefik for HTTP(S) routing — binding coturn there too would conflict. The compose
  file ships with that rung disabled by default (plain `turn://` on 3478/udp+tcp only, which needs
  no TLS cert and works out of the box); enabling it needs a real TLS certificate for `TURN_DOMAIN`
  provisioned out of band (never baked into this repo) plus either a host/IP where coturn can own
  443 itself, or accepting that hostile-egress clients (networks that allow only outbound 443) won't
  be able to relay through this deployment. `TODO: confirm` whether that trade-off is acceptable for
  your deployment — it's a real capability loss, not a cosmetic one.

coturn runs on Docker's normal bridge network with explicit port publishing, not
`network_mode: host` — Dokploy (and some other compose hosts) injects its own `networks:` into
every service it runs for routing/service-discovery, and the Compose spec forbids combining that
with `network_mode` on the same service, so a compose bringing coturn up under Dokploy with host
networking fails outright (`service coturn declares mutually exclusive network_mode and networks`).
Two consequences of that:

- coturn's relay port range is bounded down to `TURN_RELAY_MIN_PORT`-`TURN_RELAY_MAX_PORT`
  (default 49152-49352, 200 ports) instead of its full 49152-65535 default, so it stays one short
  Docker port-publish range instead of ~16k individual mappings. Widen it if you expect enough
  concurrent relayed calls to exhaust that.
- `TURN_EXTERNAL_IP` (table above) is required, not optional — under host networking coturn would
  see the real host IP itself; under bridge networking it only sees its private container IP unless
  told otherwise.

Make sure host ports 3478/udp, 3478/tcp, and the relay range are free before deploying.

If coturn's logs show `ERROR: no-cli option is deprecated`, `ERROR: Unknown boolean value: # ...`,
or `WARNING: Bad configuration format: no-tlsv1` — that was
[`infra/coturn/turnserver.conf`](../../infra/coturn/turnserver.conf) carrying directives that
current coturn versions have renamed or dropped (`no-cli` and `no-tlsv1`/`no-tlsv1_1` are gone;
`cli` is already off by default and TLSv1.2+ is already the enforced minimum) plus a genuine parser
bug — a trailing `# comment` on the same line as `no-software-attribute` was being read as that
directive's value. Fixed; pull the latest `turnserver.conf` if you deployed before this note was
added. None of these were fatal on their own — coturn logs them and keeps going — so they weren't
why the container failed to start; if it still isn't starting, check the actual exit reason in
Dokploy's deploy logs (a bind failure on an already-used port is the other common cause, see the
`RENDEZVOUS_PORT=443` warning above — the same applies to coturn's 3478 ports and relay range).

**Seeing a fix land in `main` but the running container doesn't change after a redeploy?** Two
distinct causes, since `rendezvous` and `coturn` pick up new code differently:

- `rendezvous`'s fix is baked into the *image*. `docker compose up`, even with `--build`, does
  **not** re-pull an `image:`-referenced tag on its own — `--build` only rebuilds services with a
  `build:` context, which this one doesn't have — so a host that already pulled an old `:latest`
  once keeps reusing it on every subsequent deploy, silently, even after `docker-publish.yml`
  pushes a new one. `dokploy.compose.yml` now sets `pull_policy: always` on both services to force
  an actual re-pull every deploy; if you deployed before this was added, one manual `docker compose
  pull` (or a Dokploy "force rebuild"/cache-clear, if it offers one) clears the stale local image.
- `coturn`'s config is a **bind mount** of `turnserver.conf` straight from the git checkout, not
  baked into any image — pulling a fresh `coturn/coturn` image never changes it. If coturn's logs
  still show the exact old parser errors after a redeploy, the deploy is reading from a stale git
  checkout, not a stale image: confirm Dokploy actually pulled the latest commit on `main` (check
  its build log for the commit SHA it checked out) before assuming the fix didn't work.
