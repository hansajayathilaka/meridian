# The `meridian-rendezvous` Docker image

<!-- Source: this decision (Docker Hub publish pipeline). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment](./deployment.md) ·
> [rendezvous-protocol-v1 §5 (full config surface)](../api/rendezvous-protocol-v1.md#5-config-surface-the-92-subset) ·
> [ADR 0018 (figment config loading)](../adr/0018-rendezvous-config-loading.md)

## 1. What publishes it

[`.github/workflows/docker-publish.yml`](../../.github/workflows/docker-publish.yml) builds
[`apps/rendezvous/Dockerfile`](../../apps/rendezvous/Dockerfile) and pushes it to Docker Hub
**every time a PR merges to `main`** that touches `apps/rendezvous/**`, `apps/proto/**`,
`Cargo.toml`, or `Cargo.lock`. That path filter is exhaustive by construction: the rendezvous
server depends on nothing else in the workspace — enforced by
[`tools/lint-server-no-core.sh`](../../tools/lint-server-no-core.sh) — so a merge touching any
other crate cannot change the image and is skipped rather than publishing an identical rebuild.

The job does **not** re-run the test suite itself; it relies on branch protection already having
required [`ci.yml`](../../.github/workflows/ci.yml) to pass before a PR can merge to `main`.
`TODO: confirm` branch protection is actually configured that way on this repo — if it isn't, this
pipeline will happily publish an image from an untested commit.

## 2. One-time repo setup

Configure these under **Settings → Secrets and variables → Actions** before the workflow can run:

| Kind | Name | Value |
|---|---|---|
| Secret | `DOCKERHUB_USERNAME` | Your Docker Hub username. |
| Secret | `DOCKERHUB_TOKEN` | A Docker Hub **access token** (Docker Hub → Account Settings → Security → New Access Token) — never your account password. Scope it to this repo only if Docker Hub's org tier supports scoped tokens. |
| Variable | `DOCKERHUB_IMAGE_NAME` | The target repo, e.g. `yourdockerhubuser/meridian-rendezvous`. Not a secret — it's just a name — but it lives in repo config rather than the workflow file so it can change without a code review. |

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
  yourdockerhubuser/meridian-rendezvous:latest
```

Or in compose form — see [`infra/deploy/docker-compose.yml`](../../infra/deploy/docker-compose.yml),
which wires `MERIDIAN_RENDEZVOUS_SERVER__DOMAIN`/`MERIDIAN_RENDEZVOUS_TURN__SECRET`/`MERIDIAN_RENDEZVOUS_TURN__REALM`
through `environment:` and expects `MERIDIAN_RENDEZVOUS_IMAGE` (the `image:` for the `rendezvous`
service) to be set to whatever `DOCKERHUB_IMAGE_NAME` above resolved to, e.g.:

```bash
export MERIDIAN_RENDEZVOUS_IMAGE=yourdockerhubuser/meridian-rendezvous:latest
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
