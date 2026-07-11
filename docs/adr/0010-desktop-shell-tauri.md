<!-- Source: REPO-01-languages-and-frameworks §6 ADR-R2. -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md)

# ADR 0010: Desktop shell — Tauri v2 (not Electron, not native-per-OS)
**Options:** (A) Electron; (B) **Tauri v2 (chosen)**; (C) native per-OS (WinUI/AppKit/GTK).
**Trade-offs:** A ships a Chromium+Node runtime (~100 MB, high RAM) and would run the core in a separate Node process, forcing an IPC boundary around crypto — more surface, worse footprint. C gives the best per-OS polish but triples UI work and shares nothing with the browser client. B runs the Rust core *in-process* (no IPC around secrets), yields ~3–5 MB bundles, and lets desktop reuse the browser's Svelte UI. *Currency-checked:* Tauri v2 desktop is stable and production-grade (2.9.x, late 2025). **Decision: B.** **Consequence:** three WebView engines (WebView2/WKWebView/WebKitGTK) = "write once, test three"; mitigated by keeping platform-specific UI code near zero and the logic in Rust.

