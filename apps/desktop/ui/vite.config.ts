import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

// Task 12.15 — the real build config for `meridian-desktop-ui`'s Tauri-embedded frontend bundle
// (`pnpm --dir apps/desktop/ui build`, invoked by `../tauri.conf.json`'s `beforeBuildCommand`, and
// in turn by `cargo tauri build`). Plain Vite + `@sveltejs/vite-plugin-svelte` — not SvelteKit's
// `sveltekit()` plugin (contrast `apps/web/vite.config.ts`, task 12.14): this shell has no routes
// to compile, no adapter-static target, nothing SvelteKit's own plugin would add value over.
//
// `strictPort`/fixed dev port 1420 mirrors the upstream `create-tauri-app` Svelte template
// convention (and is what `../tauri.conf.json`'s `build.devUrl` points at) — Tauri's own dev-mode
// WebView needs a stable, known dev-server URL to load rather than discovering one at random.
export default defineConfig({
  plugins: [svelte({ preprocess: vitePreprocess() })],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  // Tauri's own dev-mode WebView prints its own (often more actionable) reload/error output;
  // clearing the terminal on every Vite reload would erase that — same reasoning `create-tauri-app`
  // itself ships this exact `clearScreen: false` for.
  clearScreen: false,
});
