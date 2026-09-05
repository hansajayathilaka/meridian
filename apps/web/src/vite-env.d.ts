/// <reference types="vite/client" />

// Vite's `?url` import suffix (used by `src/lib/adapter.ts`/`adapter.browser.test.ts` to resolve
// `meridian-wasm`'s compiled `.wasm` binary to a dev-server-served URL, see `adapter.ts`'s own
// `ensureWasmInit` doc comment) has no built-in ambient declaration for `.wasm` specifically —
// Vite's own `client.d.ts` only covers its default asset extension list, which does not include
// `.wasm`. This is a plain build-tooling type declaration, not a WASM-boundary concern.
declare module "*.wasm?url" {
  const url: string;
  export default url;
}
