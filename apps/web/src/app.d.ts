// SvelteKit ambient types. See https://svelte.dev/docs/kit/types#app.d.ts
// Deliberately empty — this app has no server (`svelte.config.js`'s `adapter-static` +
// `fallback: "index.html"`), so there is no `App.Locals`/`App.Platform` shape to declare; every
// per-request server concept SvelteKit's own template comments below name is inapplicable here.
declare global {
  namespace App {
    // interface Error {}
    // interface Locals {}
    // interface PageData {}
    // interface PageState {}
    // interface Platform {}
  }
}

export {};
