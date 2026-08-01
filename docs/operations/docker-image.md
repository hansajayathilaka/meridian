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

## 6. Running this on Dokploy

[`infra/deploy/dokploy.compose.yml`](../../infra/deploy/dokploy.compose.yml) +
[`infra/deploy/dokploy.env.example`](../../infra/deploy/dokploy.env.example) are a ready-to-deploy
pair for [Dokploy](https://dokploy.com)'s "Docker Compose" application type (or any plain
`docker compose` host — Dokploy has no special requirements here beyond what any compose deploy
needs). Point a Dokploy compose app at this repo/file, copy `dokploy.env.example` into its
Environment tab, fill in the four required values, and deploy:

| Var | Required? | What it is |
|---|---|---|
| `RENDEZVOUS_IMAGE` | yes | The image `docker-publish.yml` pushed, e.g. `yourdockerhubuser/meridian-rendezvous:latest` — or pin a `:<short-sha>` tag (§4) for a reproducible deploy. |
| `MERIDIAN_RENDEZVOUS_SERVER__DOMAIN` | yes | Your public signaling hostname, e.g. `chat.example.com`. |
| `TURN_SHARED_SECRET` | yes | A long random value. Shared verbatim between the `rendezvous` and `coturn` services in the compose file — that's the whole trust mechanism for ephemeral TURN credentials (§"TURN / coturn" in [deployment.md](./deployment.md)). Generate one with `openssl rand -hex 32` and never commit it. |
| `TURN_EXTERNAL_IP` | yes | This host's public IP. coturn runs on Docker's bridge network (see below), so without this it hands clients its private container IP as the relay candidate and every relayed call fails. |

Everything else in the env file has a working default and only needs changing if you want to.
Every var maps 1:1 onto a config key documented in §3 above — the compose file just plumbs each one
through `${VAR:-default}` interpolation so Dokploy's flat env-var UI is the single place you edit
config, with no image rebuild and no editing the compose file itself for routine changes.

Two things that don't reduce to "just set an env var," both called out in comments in the compose
file itself:

- **Exposing the domain.** The compose file publishes the rendezvous container's port 8443 to the
  host (`RENDEZVOUS_PORT`, default 8443) but does not terminate TLS — same as every other deploy of
  this image (§2: TLS termination is the proxy/VIP's job, ADR-8). In Dokploy, add a Domain for the
  `rendezvous` service pointing at container port 8443 with HTTPS enabled; Dokploy's built-in Traefik
  handles the certificate and wss:// termination from there. **Do not set `RENDEZVOUS_PORT=443`** —
  Dokploy's own Traefik already owns host port 443, so this container fails to bind it too and never
  starts. Keep `RENDEZVOUS_PORT` at a free, non-privileged port and let the Domain feature do the
  443 exposure instead.
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
