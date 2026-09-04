// Ambient module declaration so plain `tsc --noEmit` (part of this package's `check` script) can
// resolve `.svelte` imports; `svelte-check` (the other half of `check`) does the real, full
// component type-check using the Svelte language tools.
declare module "*.svelte" {
  import type { ComponentType, SvelteComponentTyped } from "svelte";
  const component: ComponentType<SvelteComponentTyped<Record<string, unknown>>>;
  export default component;
}
