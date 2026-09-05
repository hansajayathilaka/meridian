// Real `lint` script (task 12.14 Deliverable 4 — replaces the scaffold's `echo 'TODO: eslint'`).
// No repo-wide eslint config exists yet (shared-ui's/apps/desktop/ui's own `lint` scripts are still
// the same TODO placeholder) — this is scoped to `apps/web` only, not a repo-wide change this
// task's own scope doesn't cover.
import js from "@eslint/js";
import importPlugin from "eslint-plugin-import";
import svelte from "eslint-plugin-svelte";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/", ".svelte-kit/", "node_modules/", "src/lib/__screenshots__/"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
  },
  {
    files: ["**/*.svelte"],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
      },
    },
  },
  {
    plugins: { import: importPlugin },
    rules: {
      // The screen `.svelte` files are the "no bespoke crypto/wire types in TS" invariant's own
      // enforcement point (`apps/web/CLAUDE.md`) — `no-unused-vars` stays on everywhere so an
      // accidentally-unused import/adapter field can't hide a silently-dropped error path.
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      // Registered (not omitted) so `adapter.ts`/`adapter.browser.test.ts`'s own pre-existing
      // `// eslint-disable-next-line import/no-unresolved` comments (task 12.13, for the
      // `meridian-wasm/meridian_wasm_bg.wasm?url` specifier — a real, Vite-resolved import with no
      // static `.d.ts` declaration an import resolver could statically verify) name a real rule
      // rather than erroring as "Definition for rule ... was not found". Left `off` rather than
      // configured-and-enabled: this workspace's `$lib`/`$app` SvelteKit aliases and pnpm-workspace
      // packages (`shared-ui`) would need a dedicated resolver (`eslint-import-resolver-typescript`
      // or equivalent) to avoid a wall of false positives across every route file — out of this
      // task's scope to stand up; TypeScript itself (`svelte-check`, this package's own `check`
      // script) already catches genuine unresolved-import errors with full path/alias awareness.
      "import/no-unresolved": "off",
    },
  },
  {
    files: ["**/*.svelte"],
    rules: {
      // This app uses plain string `href`/`goto()` targets throughout its route tree and app-shell
      // chrome (`src/lib/PeerNav.svelte`), not
      // SvelteKit's newer typed `resolve()` navigation helper (`@sveltejs/kit` 2.70's opt-in typed-
      // routing API) — adopting `resolve()` everywhere is a separate, larger routing-ergonomics
      // change this task did not set out to make. Every navigation target here is a literal,
      // reviewed string built from this app's own known route tree (`/`, `/contacts`, `/requests`,
      // `/chat/[peer]`, `/verify/[peer]`, `/files/[peer]`) or a `MeridianId` run through
      // `encodeURIComponent` (never unescaped user-controlled markup/HTML) — never a build-time-
      // unverifiable string.
      "svelte/no-navigation-without-resolve": "off",
    },
  },
);
