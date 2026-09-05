// Ambient module declaration so plain `tsc --noEmit` (this package's `check` script) can resolve
// `.svelte` imports (`./App.svelte`, and every `shared-ui` screen re-exported through its package
// root) — mirrors `shared-ui/src/shims-svelte.d.ts` (task 12.7) exactly, same reasoning: real
// per-component type-checking is `svelte-check`'s job, not plain `tsc`'s.
declare module "*.svelte" {
  import type { ComponentType, SvelteComponentTyped } from "svelte";
  const component: ComponentType<SvelteComponentTyped<Record<string, unknown>>>;
  export default component;
}
