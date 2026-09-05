/**
 * Entry point Tauri's WebView actually loads (`../index.html`'s `<script type="module">`). Mounts
 * `App.svelte` — the one place this shell's own view-state/adapter wiring lives — onto `#app`. No
 * protocol/adapter logic belongs here; see `App.svelte`'s own doc comment.
 */
import App from "./App.svelte";

const target = document.getElementById("app");
if (!target) {
  throw new Error("meridian-desktop: #app mount target is missing from index.html");
}

const app = new App({ target });

export default app;
