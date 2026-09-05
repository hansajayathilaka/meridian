// Task 12.14 — this app has no server at all (`svelte.config.js`'s `adapter-static` +
// `fallback: "index.html"`): every route's real work is `MeridianClientAdapter` calls into the
// WASM core, IndexedDB, and WebRTC, none of which exist in SvelteKit's Node-side prerender step.
// `ssr = false` here (inherited by every child route, including `(app)/**`) is what tells SvelteKit
// not to attempt that — the standard SvelteKit pattern for a browser-only client, not a workaround.
export const ssr = false;
