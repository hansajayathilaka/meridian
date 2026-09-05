import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// Real headless-browser harness for task 12.13's adapter integration test (Deliverable 2) — Vitest
// "browser mode" (`@vitest/browser`, Playwright provider) rather than a Node/jsdom polyfill: this is
// the first task where the store's real browser-platform behavior (genuine IndexedDB, genuine
// `crypto.subtle`, genuine `RTCPeerConnection`) actually matters end to end, and jsdom implements
// none of those for real. Chosen over a second `wasm-bindgen-test --chrome` Rust harness (12.5's/
// 12.11's/12.12's own tool) because this task's own test exercises `apps/web/src/lib/adapter.ts`
// itself — real TypeScript calling into the compiled `meridian-wasm` bindings — not Rust test code;
// `wasm-bindgen-test` has no way to load and drive a TS module.
//
// Points Playwright's Chromium launch at a real, already-present Chrome/Chromium binary via
// `executablePath`, so no second browser download is needed: `MERIDIAN_TEST_CHROME_PATH` (an escape
// hatch for whatever browser a given CI/session has staged — this task's own session had a
// version-matched Chrome-for-Testing + chromedriver pair pre-staged, the same one 12.5/12.11/12.12's
// own `wasm-pack test --chrome --headless` runs use), falling back to `PUPPETEER_EXECUTABLE_PATH`
// (the dev container's own existing convention, `.devcontainer/devcontainer.json`, pointing at its
// system `/usr/bin/chromium`) — the standing, non-ephemeral answer for anyone running this suite from
// the real dev container rather than this one-off session. Leave both unset and Playwright falls back
// to its own managed browser (requires `playwright install chromium` to have been run first).
const CHROME_EXECUTABLE =
  process.env.MERIDIAN_TEST_CHROME_PATH || process.env.PUPPETEER_EXECUTABLE_PATH || undefined;

export default defineConfig({
  // Required only because `shared-ui`'s single `"."` export transitively re-exports its Svelte
  // screens/components alongside `MeridianAdapterError` — see `apps/desktop/ui/vitest.config.ts`'s
  // identical setup/reasoning, mirrored here. No Svelte component lives in this package itself.
  plugins: [svelte({ compilerOptions: { dev: true }, preprocess: vitePreprocess() })],
  resolve: {
    conditions: ["browser"],
  },
  test: {
    include: ["src/**/*.test.ts"],
    globals: false,
    browser: {
      enabled: true,
      provider: "playwright",
      name: "chromium",
      headless: true,
      providerOptions: {
        launch: {
          executablePath: CHROME_EXECUTABLE,
          // Root/container environment (see this session's own dev-container setup) — Chromium's
          // setuid sandbox needs privileges not available here; `--no-sandbox` mirrors what every
          // other headless-Chromium harness in this repo already needs in the same environment.
          // `--disable-features=WebRtcHideLocalIpsWithMdns` turns off Chrome's default host-candidate
          // mDNS obfuscation (`<uuid>.local` candidates) for this same-tab loopback test only — mDNS
          // resolution needs real multicast UDP, unavailable in this sandboxed network namespace
          // (confirmed empirically: candidates gathered fine, but the data channel never opened until
          // this flag was added). This is a headless-test-harness-only knob, not a product/privacy
          // decision — real deployed browsers keep Chrome's default mDNS behavior; nothing in
          // `apps/wasm/src/transport.rs` depends on or assumes it either way.
          args: [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-features=WebRtcHideLocalIpsWithMdns",
          ],
        },
      },
    },
  },
});
