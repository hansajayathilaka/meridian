# Deployment & Self-Hosting

<!-- Source: p2p-comms-design.md §9; feature spec tasks/T14 (Self-Hosting Ops Kit). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment topology](./diagrams/deployment-topology.mermaid) · [feature 14: ops kit](../architecture/features/14-selfhosting-ops-kit.md) · [deployment skill](../../.claude/skills/deployment/SKILL.md)

See the [deployment topology diagram](./diagrams/deployment-topology.mermaid) for the air-gapped
reference deployment. The full ops-kit feature spec (with runnable install demo) is
[feature 14](../architecture/features/14-selfhosting-ops-kit.md).

## 9. Self-hosting & operations

### 9.1 What an org deploys

Two containers plus a database: `meridian-rendezvous` (single Rust binary; Postgres or embedded SQLite for prekeys/device records/mailbox), `coturn`, and TLS certs. The federation map is not DB-persisted state — it's a static `federation_map.toml` config file (§9.2, §9.3). Reference deploys: docker-compose (small org) and a Helm chart (K8s). `meridian-rendezvous`'s image is built and pushed to the GitHub Container Registry (`ghcr.io/<owner>/meridian-rendezvous`) automatically on every merge to `main` — see [the image doc](./docker-image.md) for the CI pipeline, tagging scheme, and one-time package-visibility setup (no repo secrets required — ghcr authenticates with the built-in `GITHUB_TOKEN`). Resource envelope: rendezvous is WebSocket fan-in + blob routing — a 2-vCPU node comfortably serves thousands of users; TURN sizing is bandwidth-bound (relayed calls ≈ 100–300 kbps audio / 1–3 Mbps video per leg) and is the only component with real capacity planning.

### 9.2 Config surface (deliberately small)

Domain + certs; federation policy (`open | allowlist | closed`) and the static federation map (air-gapped) or SRV (connected); registration admission (open, invite-token, or OIDC-gated per §3.2); mailbox TTL/quota; TURN secret + bandwidth caps; connection policy defaults (`direct|prefer-relay|relay-only`); rate-limit knobs. Everything else is client-side. Every key is TOML in `rendezvous.toml` (generated from [`rendezvous.example.toml`](../../apps/rendezvous/rendezvous.example.toml)) and can be overridden per-deployment with `MERIDIAN_RENDEZVOUS_<SECTION>__<FIELD>` env vars (e.g. `MERIDIAN_RENDEZVOUS_TURN__SECRET`), merged via `figment` ([ADR 0018](../adr/0018-rendezvous-config-loading.md)) — see [rendezvous-protocol-v1 §5](../api/rendezvous-protocol-v1.md#5-config-surface-the-92-subset) — so secrets never need to be baked into the generated file or image. The CLI's local connection-policy store (`policy.json`) picks up the same convention for its org-pushed default: `MERIDIAN_POLICY__ORG_DEFAULT` works even with no `policy.json` present.

**Federation port.** `federation.bind` defaults to `127.0.0.1:8444` — deliberately adjacent to the
c2s WSS default (`8443`) so both listeners can run on the same host with no config edit and no
ambiguity about which port is which. **8444 is not an IANA-registered service port**; it is purely
this project's convention, and operators are free to override it (`federation.bind` /
`MERIDIAN_RENDEZVOUS_FEDERATION__BIND`). Per [ADR 0017 C7](../adr/0017-federation-trust-boundary.md),
whatever port is chosen must terminate mTLS **in-process** — never at a proxy/VIP the way c2s's
8443 is terminated today ([rendezvous-protocol-v1 §8](../api/rendezvous-protocol-v1.md#8-known-mvp-simplifications-t02));
if 8444 (or its override) is published through a reverse proxy or
load balancer, publish it as **raw TCP passthrough only**. See
[federation-protocol-v1.md §1](../api/federation-protocol-v1.md#1-transport--framing) for the wire
rationale.

**Private CA trust anchors require static discovery — regardless of how the CA was installed.**
[ADR 0017 (a)/C4](../adr/0017-federation-trust-boundary.md) requires that a private CA used as a
federation trust anchor MUST be paired with `federation.discovery = "static"` and a mandatory
`pinned_identity` per partner in `federation_map.toml`. This is true whether the CA is supplied via
`federation.ca_bundle_path` (which `Federation::validate` rejects outright when combined with
`discovery = "srv"`) **or installed directly into the host/container OS trust store** (e.g. via
`update-ca-certificates`) while leaving `ca_bundle_path` empty and running `discovery = "srv"` —
config validation has no way to see into the OS trust store, so this second path is **not rejected at
config load and produces no startup warning**. Under a private CA **shared by more than one org**,
that combination reopens ADR 0017 (a)'s Option-A impersonation hole: SRV-resolved endpoints never
carry a `pinned_identity`, so any org enrolled under the shared CA could present a cert whose SAN
matches a victim partner's domain and be accepted as that partner. (`demo/two-orgs`'s SRV profile does
exactly this — install a private CA into each container's OS trust store and run `discovery = "srv"`
— but is safe there only because the CA is single-purpose, ephemeral, and shared by two cooperative
demo orgs with nothing at stake; see that compose file's header comment. **Do not copy that pattern
into a production deployment that federates a private CA across independent, mutually-distrusting
orgs** — use `discovery = "static"` with a pinned identity per partner instead.)

### 9.3 Air-gapped operation

Fully supported by construction: internal DNS + private CA for client-server and federation mTLS; static federation map instead of SRV; internal STUN/TURN only (clients accept an org-pushed ICE-server list, and in air-gapped mode the public-STUN default is disabled); no APNs/FCM → Android foreground-service wake, iOS foreground-only (named limitation); client updates via the org's artifact mirror with our release signatures verified offline. Nothing in the protocol phones home; there is no license server, telemetry endpoint, or key registry outside the org.

### 9.3a TURN / coturn (T05)

`coturn` is the org relay. It authenticates clients with the **ephemeral shared-secret** mechanism (`use-auth-secret`), never static per-user passwords: `meridian-rendezvous` mints a per-session credential (`base64(HMAC-SHA1(secret, "<expiry>:<nonce>"))`) that coturn recomputes and time-boxes. Deploy checklist:

- **One shared secret.** Set coturn `static-auth-secret` **==** rendezvous `[turn].secret`, provisioned out of band (env/secret manager) — never committed. Reference config: [`infra/coturn/turnserver.conf`](../../infra/coturn/turnserver.conf); compose wiring: [`infra/deploy/docker-compose.yml`](../../infra/deploy/docker-compose.yml).
- **Realm is set on the command line, not in `turnserver.conf`.** Same file-parser quirk as the secret above (coturn's config-file parser consumes everything after a directive as its value), so `realm=` is commented out in the reference config and passed as `--realm=$TURN_DOMAIN` on coturn's `command:` in both compose files instead. There's no cryptographic requirement that this match rendezvous's `MERIDIAN_RENDEZVOUS_TURN__REALM` (a client authenticates against whatever realm coturn's own 401 challenge returns, not a pre-shared value) — but both compose files key it off the same `TURN_DOMAIN` var so it does anyway, avoiding operator confusion.
- **The candidate ladder** the client tries in order: `turn:HOST:3478?transport=udp` → `turn:HOST:3478?transport=tcp` → `turns:HOST:443?transport=tcp`. The **TLS-443** rung is the last resort for hostile egress that only permits outbound HTTPS; expose 443 (directly, or terminate TLS at a proxy and point clients there).
- **Content stays E2E.** coturn relays DTLS/DTLS-SRTP ciphertext and can *meter* flows (IPs, volume, timing) but never read them — the documented residual for relayed paths ([privacy & retention](../security/anonymity-and-retention.md)). Rotate the shared secret on suspected TURN compromise (§10).
- **Relay policy defaults** (`direct | prefer-relay | relay-only`) are the org-default level of the client knob (§5.4); users/contacts tighten it locally via `meridian config set policy`, or an org can push the default directly via `MERIDIAN_POLICY__ORG_DEFAULT` (no `policy.json` needed). `relay-only` concentrates flow metadata on the org TURN — often the *desired* audit point in an enterprise; surface it as a labeled choice.
- **Air-gapped:** internal TURN only; relax the `denied-peer-ip` RFC-1918 lines to the org's own ranges and disable external egress. With no relay at all, leave `[turn].secret` empty — the server answers `turn_unavailable` and clients use the host/STUN ladder.
- **Diagnostics:** `meridian doctor` reports which candidate classes work and where the path is blocked; the netns rig [`tools/netns-nat-matrix.sh`](../../tools/netns-nat-matrix.sh) (via `tools/testrig`) exercises the four NAT cells.

### 9.4 Observability without breaking E2EE

Exported (Prometheus): connection counts, envelope routing rates/latencies, mailbox depth/age, prekey pool levels (a real operational signal — depletion breaks first contact), federation link health, TURN allocations/bandwidth, TURN credential mint rate (`meridian_turn_credentials_minted_total` — relay demand). Never exported: envelope contents (opaque by construction), contact-graph materializations, message sizes at per-user granularity (bucketed only). Logs are metadata-minimizing by default (hashed account keys with a per-deploy salt, short retention) with an org override — we document, rather than hide, that an org *can* log its own routing metadata (A1/A7 is in the threat model precisely because of this): the design's promise is that even that org reads no content and forges no identity. Client distribution is the one trust channel ops must keep out of the admins' hands alone: reproducible builds, signatures verified by the updater, and (for the web client) an audited serving origin.

---

