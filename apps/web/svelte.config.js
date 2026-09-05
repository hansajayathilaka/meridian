import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

// Task 12.14 — the real SvelteKit config wiring `src/routes/**` (Deliverable 1) into a servable
// static bundle (Deliverable 5, the feature spec's `meridian-web` deliverable). `adapter-static`
// (not the Node/Vercel/etc. adapters) because this client has no server component at all: every
// route only ever calls `MeridianClientAdapter` methods that run against the WASM core, IndexedDB,
// and WebRTC directly in the browser (`apps/web/CLAUDE.md`: "the web layer only calls [the WASM
// core]"). The rendezvous server the built bundle *talks to* over the network (`connect-src` below)
// is `meridian-rendezvous` — a wholly separate deployable, never something this bundle's own build
// depends on or embeds.
//
// `fallback: "index.html"` puts adapter-static into SPA mode: every route (including the
// peer-scoped `/chat/[peer]`, `/verify/[peer]`, `/files/[peer]` routes — see `src/routes/(app)/`)
// resolves entirely from client-side adapter state (which peer is selected, which account is open)
// that does not exist at build time, so none of them can be prerendered. `strict: false` is the
// documented adapter-static pairing for `fallback` mode: without it, the build fails on exactly the
// non-prerenderable routes `fallback` exists to serve.
/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      pages: "dist",
      assets: "dist",
      fallback: "index.html",
      precompress: false,
      strict: false,
    }),
    // The CSP baseline (task 12.14 Deliverable 3, `apps/web/CLAUDE.md`'s "leak nothing the
    // anonymity model forbids" rule enforced concretely: no unexpected third-party `connect-src`).
    // `mode: "hash"` — not `"nonce"` — is the only mode compatible with a fully static build: a
    // nonce must differ per HTTP response, which needs a server rendering per-request; a static
    // `fallback: "index.html"` file is served byte-identical to every client, so SvelteKit instead
    // computes a sha256 hash of its own (small, build-generated, never user-influenced) inline
    // bootstrap script at build time and bakes that exact hash into the emitted
    // `<meta http-equiv="Content-Security-Policy">` tag — real script-source allow-listing, not a
    // blanket `'unsafe-inline'` escape hatch. See `src/app.html` for confirmation no other inline
    // `<script>` exists for this hash to have to cover.
    csp: {
      mode: "hash",
      directives: {
        "default-src": ["self"],
        // `'wasm-unsafe-eval'` is the standard, minimal CSP keyword for allowing
        // `WebAssembly.instantiate`/`instantiateStreaming` without also granting `'unsafe-eval'`
        // (arbitrary `eval`/`Function` construction) — meridian-wasm (task 12.10/12.13) is the only
        // thing on this page that needs it. No inline scripts anywhere (enforced by the hash above,
        // not just a comment) and no third-party script origin.
        "script-src": ["self", "wasm-unsafe-eval"],
        // Svelte's compiled output does not emit `<style>` elements in a production build (styles
        // are extracted to external, hashed `.css` files loaded via `<link>`, already covered by
        // `'self'`) — `'unsafe-inline'` here is for the one legitimate inline `style="width: …%"`
        // attribute `FileTransfer.svelte` (shared-ui, task 12.9) binds per-transfer progress-bar
        // width to (a numeric percentage it computes itself, never unsanitized/attacker-controlled
        // text) — a nonce/hash cannot cover a value that changes per render, so this is the
        // deliberate, narrow trade-off (style-only, never script) every "dynamic inline style width"
        // UI pattern makes; CSP has no dynamic-value story that doesn't take a wider bypass than
        // this on the *style* axis specifically (attribute-only, no arbitrary CSS `url()` values
        // constructed from user input anywhere in this codebase — see `shared-ui/src/screens/`).
        "style-src": ["self", "unsafe-inline"],
        "img-src": ["self"],
        "font-src": ["self"],
        "media-src": ["self"],
        // Everything this bundle's own network calls actually need, and nothing else — the
        // concrete enforcement of "no unexpected third-party connect-src". `'self'` covers the
        // static asset origin (including the `meridian_wasm_bg.wasm` fetch, `adapter.ts`'s own
        // `ensureWasmInit`). The rest are this repo's own `demo/two-orgs`-style local deployment
        // defaults (`apps/rendezvous/rendezvous.example.toml`'s own default TURN listeners;
        // `apps/cli/src/main.rs`'s own `--rendezvous` default `ws://127.0.0.1:8443`) — a real
        // production deployment's actual rendezvous/TURN hostnames are a per-deployment fact this
        // build-time config cannot know in advance. TODO: confirm — no design doc names how a
        // production `apps/web` build is meant to inject its real rendezvous/TURN origins into this
        // list (env-at-build-time vs. a runtime-fetched allowlist); the deployment-guide prose task
        // (12.19) is the right place to resolve this, not invented here.
        //
        // `stun:`/`turn:`/`turns:` are bare scheme-sources (no host/port), not
        // `stun://127.0.0.1:3478`-shaped host-sources — confirmed empirically against a real
        // headless Chromium load of this exact built bundle (`dist/index.html`) against this task's
        // own two-orgs-style local rendezvous+TURN defaults: Chromium logs "the source list ...
        // contains an invalid source" and silently drops any `<scheme>:<host>:<port>` token (the
        // STUN/TURN URI's own wire syntax, RFC 7064/7065 — single colon, no `//` authority marker)
        // because that shape doesn't parse as either CSP grammar production (`scheme-source` is a
        // bare `scheme ":"`; `host-source` requires a `"//"` authority). A bare `stun:` (matching
        // any STUN URL regardless of host/port, the same way `data:`/`blob:` scheme-sources work
        // elsewhere) is the only CSP-grammar-valid way to allow WebRTC ICE-server connections at
        // all; it is admittedly less restrictive than a real host allow-list would be (this bundle
        // cannot know a deployment's real TURN hostname at build time either way — see the `TODO:
        // confirm` above), but a malformed, silently-dropped entry is strictly worse: it looks
        // restrictive in this file while doing nothing at runtime.
        "connect-src": ["self", "ws://127.0.0.1:8443", "wss://127.0.0.1:8443", "stun:", "turn:", "turns:"],
        "object-src": ["none"],
        "base-uri": ["none"],
        "form-action": ["none"],
        // `frame-ancestors` is listed here for documentation/forward-compat with a future
        // header-delivered CSP (e.g. if a server-rendered deployment target is ever added), but the
        // CSP spec itself forbids delivering `frame-ancestors` (and `report-uri`/`sandbox`) via a
        // `<meta>` tag — SvelteKit's own `csp.js` silently drops it from the generated meta tag for
        // exactly that reason. Confirmed empirically against this task's own `dist/index.html`
        // build output: not present in the emitted `<meta http-equiv="Content-Security-Policy">`.
        // A meta-tag-only CSP baseline structurally cannot cover clickjacking framing — that needs
        // an `X-Frame-Options`/header-delivered `frame-ancestors` from whatever actually serves this
        // static bundle (the deployment-guide prose task, 12.19, is where that belongs).
        "frame-ancestors": ["none"],
      },
    },
  },
};

export default config;
