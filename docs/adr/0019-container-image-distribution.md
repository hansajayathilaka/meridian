<!-- Source: this decision (task 3.19, review finding F16 remainder). -->
> **Nav:** [ADR index](./README.md) · [docker-image.md](../operations/docker-image.md) ·
> [deployment.md §9.1](../operations/deployment.md#91-what-an-org-deploys) ·
> precedent [ADR 0018](./0018-rendezvous-config-loading.md)

# ADR 0019: Container image distribution channel + signing

**Options — distribution channel:** (A) Docker Hub (the pipeline's original target); (B) **GitHub
Container Registry, `ghcr.io` (chosen; already landed)**; (C) a self-hosted registry.
**Trade-offs:** A needed a long-lived `DOCKERHUB_*` credential pair stored as a repo secret — a
standing credential with no expiry tied to no specific workflow run, exactly the class of secret
[ADR 0018](./0018-rendezvous-config-loading.md)'s neighboring config work was already trying to
shrink the project's surface of. B needs **no repo secret at all**: `docker-publish.yml`
authenticates to `ghcr.io` with the workflow's own ephemeral, run-scoped `GITHUB_TOKEN` (`packages:
write` permission, nothing else), and the resulting package is automatically linked to this
repository (visible in the repo's sidebar, provenance traceable via the `org.opencontainers.
image.source` OCI label the pipeline already sets). C would trade both of those advantages for
operational burden (uptime, storage, its own auth) this project has no resourcing for. **Decision:
B.** This was already implemented, out of band from this ADR, before this task — the ADR is
ratifying an already-made, already-shipped choice, not re-opening it. Migration mechanics (removing
`DOCKERHUB_*`, the one-time ghcr package-visibility step) are documented operationally in
[docker-image.md §1-2](../operations/docker-image.md), not repeated here.

**Options — tag policy:** (A) `:latest` only; (B) content-addressed digests only, no mutable tag;
(C) **`:latest` + short-sha, both mutable-`latest`-and-immutable-sha (chosen; already landed)**.
**Trade-offs:** A gives operators nothing to pin to for a reproducible deploy — every redeploy
silently picks up whatever `main` most recently built. B is maximally reproducible but unusable for
the `dokploy.compose.yml`/`docker-image.md` "point `RENDEZVOUS_IMAGE` at a tag and redeploy on every
push to update" operator workflow this project targets — a self-hosting team without their own CI
has no easy way to look up a fresh digest. C keeps the convenient default (`:latest`, what
`dokploy.env.example` ships) while giving anyone who wants reproducibility a `:<short-sha>` tag to
pin to instead, both produced by the same `docker/metadata-action` step on every publish at no extra
cost. **Decision: C**, already implemented (`docker-publish.yml`'s `meta` step, `type=raw,value=
latest` + `type=sha,format=short`).

**Options — signing / provenance:** (A) adopt image signing now (cosign keyless signing via GitHub
OIDC, plus SLSA build provenance attestations); (B) **defer, with a recorded residual and a named
reopening trigger (chosen)**; (C) never sign — treat it as permanently out of scope.
**Trade-offs:** A is the correct end state for a project whose entire pitch is not-trusting-the-
server-operator — an image an operator pulls and runs unverified is a supply-chain gap in exactly
the kind of deployment (self-hosted, air-gapped-capable, "an org runs its own rendezvous") this
project is built for. But it is genuinely new pipeline surface (cosign step, a verification story
for operators who'd need to actually check a signature, not just publish one) with no operator
consuming it yet — no tagged release exists, no third party has been told to `docker pull` this
image, and the (currently single-maintainer, pre-1.0) project has not yet defined a release
process a signature would be anchored to. Building the verification half of a supply-chain story
before there's a public consumer to protect is effort spent on a threat model this repo doesn't yet
have. C throws away real value for free — cosign-via-OIDC costs one workflow step and no secret
management (same ambient-credential model `ghcr.io` itself already uses) — and would require a
future ADR to reverse for no benefit gained by deferring instead. **Decision: B.**

## Accepted residual risks

> **R1 — Unsigned images, no build provenance.** Every image
> `ghcr.io/<owner>/meridian-rendezvous` publishes today — `:latest` and every `:<short-sha>` — is
> **unsigned**, with no build-provenance attestation. An operator (or `docker-publish.yml` itself,
> if the ghcr `GITHUB_TOKEN` scope were ever compromised) has no cryptographic way to confirm a
> pulled image was actually built by this repo's CI from the commit its tag implies, versus a
> would-be attacker able to push into the same package namespace. This is a real, live gap — not a
> hypothetical one — same weight class as the residuals already carried in
> [ADR 0017's Accepted residual risks](./0017-federation-trust-boundary.md#accepted-residual-risks).
> It sits below the binding, must-not-violate conditions this project already treats as normative
> (e.g. [ADR 0017's C1–C7](./0017-federation-trust-boundary.md)) because there is, as of this ADR,
> no external consumer yet trusting a pulled image over this one's own build.
>
> **Trigger to reopen:** before **either** (a) the first tagged release (a `v0.x.y`-style git tag,
> or any point this project starts publishing a versioned changelog an operator would reasonably
> pin to) **or** (b) any point a third party — anyone outside the maintainer(s) actively developing
> this repo — is told, in documentation or otherwise, to `docker pull` this image for their own
> deployment. Whichever of (a)/(b) comes first requires either landing cosign keyless signing
> (GitHub OIDC — no new secret, `packages: write` already granted) + SLSA provenance attestations
> in `docker-publish.yml`, wired into `docker-image.md`'s operator instructions as a verification
> step, or a superseding ADR that consciously re-accepts the residual with a new trigger. This is
> not `TODO: confirm` — the trade-off is deliberate — but it is a tracked, named debt, not a closed
> question.

**Consequence:** no code or pipeline changes land in this task — `docker-publish.yml`,
`dokploy.compose.yml`/`dokploy.env.example`, and `docker-image.md`'s existing content are all
already consistent with decisions A(B)/B(C) above (they were the reason this ADR could describe the
world as it now is rather than propose a migration). The one deliverable this ADR does carry
directly is itself, plus the [ADR index](./README.md) row and a cross-link from
[docker-image.md](../operations/docker-image.md) — signing's *implementation*, if/when the trigger
above fires, is a separate future task, not this one.
