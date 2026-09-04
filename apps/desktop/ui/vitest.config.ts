import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// Plain TS adapter tests only — no Svelte components live in this package itself (12.6 scope: the
// adapter is a marshaling layer, not a UI; window UI is 12.15). The svelte plugin is still required
// here because `adapter.ts` imports `MeridianAdapterError` (a runtime value, not just a type) from
// the `shared-ui` package root, whose single `"."` export (`shared-ui/src/lib/index.ts`) transitively
// re-exports the 12.7 Svelte screens/components — Vite must be able to parse those `.svelte` files
// to build the import graph even though nothing here ever renders them. Mirrors
// `shared-ui/vitest.config.ts`'s identical setup/reasoning.
export default defineConfig({
  plugins: [svelte({ compilerOptions: { dev: true }, preprocess: vitePreprocess() })],
  resolve: {
    conditions: ["browser"],
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    globals: false,
  },
});
