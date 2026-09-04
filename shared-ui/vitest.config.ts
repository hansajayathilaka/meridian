import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// jsdom is required from 12.7 onward: screen-level component tests (`src/screens/**/*.test.ts`)
// render real `.svelte` files against `FakeMeridianClientAdapter` via `@testing-library/svelte`.
// The pre-existing plain-TS adapter tests (`src/lib/*.test.ts`, task 12.2) don't need a DOM but
// run fine under jsdom too, so one shared environment keeps this config simple.
export default defineConfig({
  plugins: [svelte({ compilerOptions: { dev: true }, preprocess: vitePreprocess() })],
  // Without this, Vite/Vitest transforms `.svelte` files in SSR mode under Node (no real DOM,
  // `onMount` compiled to a no-op) even though `test.environment` is `jsdom` — a well-known
  // vite-plugin-svelte + Vitest pitfall. Forcing the `browser` resolve condition makes
  // vite-plugin-svelte compile components as real client components against jsdom.
  resolve: {
    conditions: ["browser"],
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    globals: false,
  },
});
