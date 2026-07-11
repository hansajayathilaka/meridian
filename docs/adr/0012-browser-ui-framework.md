<!-- Source: REPO-01-languages-and-frameworks §6 ADR-R4. -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md)

# ADR 0012: Browser UI framework — SvelteKit (with React as the fallback)
**Options:** (A) **SvelteKit (chosen)**; (B) React; (C) SolidJS.
**Trade-offs:** the UI is a thin view over a WASM core doing all the real work, so bundle size and reactivity ergonomics matter more than ecosystem breadth. A yields the smallest bundles (relevant to the <4 MB WASM budget, T11) and clean reactivity; it's also a first-class Tauri frontend, so web + desktop share it. B has the largest talent pool and component ecosystem — the reason it's the named fallback if hiring or a component library forces it. C is technically excellent but a smaller ecosystem. **Decision: A**, shared between `clients/web` and `clients/desktop` via `shared-ui`. **Consequence:** the team commits to Svelte proficiency; the WASM boundary is framework-agnostic (plain TS API), so a later swap to React touches only the view layer.

