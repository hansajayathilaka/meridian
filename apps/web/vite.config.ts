import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

// Task 12.14 Deliverable 2 — the real build config for `meridian-web`'s servable static bundle
// (`pnpm --filter meridian-web build`, this file + `svelte.config.js`'s `adapter-static` wiring).
// Kept deliberately small: SvelteKit's own `sveltekit()` plugin already wires routing/HMR/the
// `adapter-static` build target; nothing here reimplements any of that.
export default defineConfig({
  plugins: [sveltekit()],
  build: {
    target: "es2022",
    // Real gzip-size numbers in the build's own summary output — this is also where the <4 MB
    // gzipped-WASM budget (T11, the feature spec; hard-gated for real by task 12.20) starts being
    // measured against an actual `vite build` output rather than 12.10's smoke-build report. This
    // flag only makes `vite build` print the number; it does not enforce the budget itself.
    reportCompressedSize: true,
  },
  optimizeDeps: {
    // `meridian-wasm` is a `wasm-pack --target web` package: its glue JS does its own
    // `fetch`/`WebAssembly.instantiateStreaming` wiring (`adapter.ts`'s own `ensureWasmInit`, via
    // Vite's `?url` asset import) and is not meant to be pre-bundled/transformed by esbuild the way
    // a normal npm dependency is — excluding it here mirrors the standard wasm-bindgen +
    // Vite integration guidance and avoids `optimizeDeps` trying to scan/rewrite the compiled
    // `.wasm` binary itself.
    exclude: ["meridian-wasm"],
  },
});
