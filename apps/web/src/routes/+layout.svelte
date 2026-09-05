<!--
  Root layout — deliberately minimal. `(app)/+layout.svelte` owns the protected app chrome
  (sidebar/nav/sign-out); this file only provides the page shell every route (onboarding included)
  shares, so there is nothing account-gated here.
-->
<div class="app-root">
  <slot />
</div>

<style>
  :global(html, body) {
    margin: 0;
    height: 100%;
    font-family:
      system-ui,
      -apple-system,
      "Segoe UI",
      sans-serif;
  }
  .app-root {
    height: 100%;
    min-height: 100vh;
  }
</style>
