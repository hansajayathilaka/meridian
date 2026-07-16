<!-- Source: REPO-01-languages-and-frameworks. Monorepo, languages, frameworks. Note: the
     prompt's "Tech stack" bullet was empty; this file is the authoritative stack definition. -->
> **Nav:** [docs index](../INDEX.md) · [system design](./system-design.md) · [build/target topology](./diagrams/build-target-topology.mermaid) · [stack ADRs 0009–0013](../adr/README.md)

# Meridian — Monorepo, Languages & Frameworks

Companion to `p2p-comms-design.md` (§6, ADR-6), `DOC-04-api-contracts.md`, and diagram D02. This document commits the concrete stack: what language each component is written in, which frameworks/runtimes, how the monorepo is laid out, and how one Rust core reaches five platforms. Framework-currency claims are dated (early-mid 2026) because two of them — pure-Rust WebRTC maturity and Tauri's mobile story — are load-bearing and move fast; they were verified, not assumed.

## 0. The one non-negotiable that dictates everything

**A single shared core in Rust, everything else a thin shim.** Identity, crypto, ratchets, sessions, the stream registry, wire framing, and the signaling client are written once, in Rust, and compiled to every target: native static/dylib for desktop/mobile/CLI/server, and WASM for the browser. This is the only way to guarantee that a browser, a phone, and a headless server agree *byte-for-byte* on identity strings, safety numbers, and envelope formats — the conformance-vector property (DOC-05 §1). Any design that reimplements crypto per platform fails that guarantee and is rejected on sight.

Rust specifically because: memory safety in an adversarial-input parser (every byte off the wire is hostile), a mature crypto ecosystem (RustCrypto, libsignal, OpenMLS, vodozemac), first-class WASM and FFI stories (wasm-bindgen, UniFFI), and a pure-Rust WebRTC data-channel stack (webrtc-rs) that runs identically headless and in a browser via the same protocol.

## 1. Language & framework decisions by component

| Component | Language | Framework / runtime | Why (and currency note) |
|---|---|---|---|
| **Shared core** (`meridian-core` + sub-crates) | Rust | tokio async runtime; RustCrypto/libsignal for primitives | one codebase, five targets; adversarial-input safety |
| **Crypto** | Rust | X3DH + header-encrypted Double Ratchet, composed in `meridian-crypto` from audited RustCrypto primitives (see ADR-R3 / [ADR 0015](../adr/0015-ratchet-composition.md)); OpenMLS for groups (Phase 3); ML-KEM via `ml-kem`/`pqcrypto` for the PQXDH slot | never bespoke; audited primitives only |
| **P2P data channels + ICE/SCTP/DTLS/SRTP** | Rust | **webrtc-rs** | pure-Rust, identical wire behavior headless↔browser. *Currency:* data channels / ICE / SCTP / DTLS / SRTP are production-usable; full media 3A (echo cancel, noise suppression, NetEQ) is **not** ported — so media takes a different path (next row) |
| **Real-time media** (audio/video/screenshare capture+processing) | Rust FFI over C++ | **libwebrtc** (mobile & desktop) / **libdatachannel** as a lighter alt for data-only paths | webrtc-rs lacks audio 3A; libwebrtc gives hardware codecs, AEC/AGC/NS, and platform capture. Confined behind the `Transport` trait so the core never depends on it directly |
| **Terminal client** | Rust | **ratatui** (TUI) + `--json` headless mode; webrtc-rs transport; `cpal` for optional voice | WebRTC is a protocol, not a browser feature — CLI speaks it natively (design §6) |
| **Browser client** | Rust→WASM core + TypeScript UI | core via **wasm-bindgen**; UI in **SvelteKit** (or React — ADR-R4); browser-native `RTCPeerConnection` as the Transport impl | browser forbids custom transports, hence the trait; Svelte for small bundles |
| **Desktop client** (Win/mac/Linux) | Rust + TypeScript | **Tauri v2** (WebView2/WKWebView/WebKitGTK shell, Rust core in-process) | ~3–5 MB bundles vs Electron's ~100 MB; core runs in-process, no IPC to a separate backend. *Currency:* Tauri v2 stable (2.9.x line, late 2025), desktop is production-grade |
| **Android client** | Kotlin | **Jetpack Compose** UI over **UniFFI**-generated Kotlin bindings; libwebrtc; ConnectionService; StrongBox Keystore; FCM wake | native shell needed for CallKit-equivalent, background, hardware keystore — *not* Tauri (next note) |
| **iOS client** | Swift | **SwiftUI** over **UniFFI**-generated Swift bindings; libwebrtc; CallKit; Secure Enclave; APNs wake | same reasoning as Android |
| **Rendezvous server** | Rust | **axum** (HTTP/WSS) + **tokio**; **sqlx** over SQLite (default) / Postgres (flag) | near-stateless, small-team-operable; shares `meridian-proto` types with clients so envelopes can't drift |
| **Relay (TURN)** | — (operated, not written) | **coturn** (or **eturnal**) | never reinvent NAT traversal infra; org-operated (ADR-8) |
| **Deploy/orchestration** | YAML/HCL | docker-compose + **Helm**; systemd units for bare-metal air-gap | small-team ops (T14) |
| **Dev task runner / meta-build** | — | **`just`** + a Rust **`xtask`** crate | thin glue over each ecosystem's native tool (ADR-R1) |

### Why Tauri for desktop but NOT mobile
Tauri v2 mobile is real and shippable, but the Tauri team is explicit that v2 is a *foundation*, not "mobile as a first-class citizen": not all desktop plugins exist on mobile, and pure-WebView wrapper apps risk App Store Review 4.2 rejection. A communication app needs deep native surface — CallKit/ConnectionService for lock-screen call UI, background execution, hardware-backed keystores (Secure Enclave/StrongBox), and platform push. That surface is exactly where a WebView shell is weakest. So: **Tauri desktop (share the web UI codebase, run the core in-process); native SwiftUI/Compose on mobile (share the core via UniFFI, not the UI).** The core is shared everywhere; only the *UI layer* forks at the mobile boundary. This is the deliberate seam in D02.

## 2. Monorepo tooling decision (summary; full rationale in ADR-R1)

**Chosen: native-per-language toolchains, glued by a thin task runner — no heavyweight meta-build system.**
- Rust: one **Cargo workspace** (the spine — every crate a workspace member, shared lockfile).
- JS/TS: **pnpm workspaces** for web + desktop UI + shared UI.
- Android: **Gradle**; iOS: **Swift Package Manager / Xcode**.
- Orchestration: **`just`** recipes + a Rust `xtask` crate for anything needing real logic (codegen, vector generation, release packaging). CI calls the same recipes so "works on my machine" == "works in CI."

Rejected: Bazel/Buck2 (hermetic and scalable but a full-time tax for a 2–5 person team, and it fights Cargo's ergonomics); Nx (JS-first, Rust support second-class); moon (good polyglot option — kept as the **escape hatch** if cross-language build caching becomes a real pain point later, layered on top without restructuring).

## 3. Monorepo layout

```
meridian/
├── Cargo.toml                     # workspace root: [workspace] members + shared deps
├── Cargo.lock                     # single locked graph for all Rust crates
├── rust-toolchain.toml            # pinned toolchain + targets (wasm32, aarch64-apple-ios, …)
├── Justfile                       # task runner entrypoint (build, test, codegen, release)
├── pnpm-workspace.yaml            # JS/TS workspaces: clients/web, clients/desktop, shared-ui
├── package.json                   # root pnpm scripts
├── .github/workflows/             # CI (maps to DOC-05 triggers)
│   ├── ci-rust.yml   ci-js.yml   ci-android.yml   ci-ios.yml
│   ├── conformance.yml            # cross-impl vectors must match byte-for-byte
│   ├── adversarial.yml            # mitm-sim, opacity-audit, ghost-device on every commit
│   └── release.yml                # signed artifacts, reproducible builds
│
├── crates/                        # ── the Rust workspace (D02 realized) ──
│   ├── meridian-proto/            # CBOR wire types, envelope/bundle/ctrl schemas (DOC-01)
│   │                              #   single source of truth shared by clients AND server
│   ├── meridian-identity/         # T01: mrd1 IDs, Ed25519 sign/verify, QR, test vectors
│   ├── meridian-store/            # T01: SecretStore trait + encrypted local store
│   ├── meridian-crypto/           # T03: X3DH, Double Ratchet, safety-number fingerprint
│   ├── meridian-trust/            # T08: TOFU→verified state machine, contact store
│   ├── meridian-transport/        # T04: Transport trait + webrtc-rs impl; libwebrtc shim seam
│   ├── meridian-session/          # T04: session state machine, ICE, fp-binding, stream registry
│   ├── meridian-streams/          # T03/T09/T15/T16: chat, file, location, sticker, tunnel, fs
│   ├── meridian-signaling/        # T02: WSS client, envelope routing, mailbox drain, federation-aware addressing
│   ├── meridian-core/             # facade: the stable public API (DOC-04); re-exports the above
│   ├── meridian-cli/              # T06 headline: terminal client (bin)
│   ├── meridian-ffi/              # UniFFI crate → Kotlin + Swift bindings (cdylib/staticlib)
│   └── meridian-wasm/             # wasm-bindgen crate → browser core (cdylib → wasm32)
│
├── server/
│   ├── meridian-rendezvous/       # T02/T06/T07: axum + tokio + sqlx server (bin, workspace member)
│   ├── migrations/                # sqlx migrations (DOC-02 schema)
│   └── deploy/                    # T14: docker-compose, Helm chart, coturn configs, air-gap bundle
│
├── clients/
│   ├── web/                       # T11: SvelteKit SPA; imports meridian-wasm; browser Transport shim
│   ├── desktop/                   # T11: Tauri v2 app; imports shared-ui; core in-process
│   ├── android/                   # T12: Gradle project, Compose UI, consumes bindings/kotlin
│   └── ios/                       # T12: Xcode/SPM project, SwiftUI, consumes bindings/swift
│
├── shared-ui/                     # TS: components + view-models shared by web & desktop (pnpm pkg)
│
├── bindings/                      # generated code (checked in, regenerated by `just codegen`)
│   ├── kotlin/   swift/   typescript/
│
├── test-vectors/                  # conformance fixtures (identity-v1.json, safety-numbers-v1.json)
├── harnesses/                     # DOC-05: mitm-sim, opacity-audit, netns NAT rig, soak drivers
├── tools/xtask/                   # Rust dev-tooling crate (codegen orchestration, vector gen, packaging)
└── docs/                          # design.md, tasks/, techdocs/ (this whole doc tree)
```

### Crate dependency direction (must stay acyclic)
```
proto ── identity ── store
   │        │          │
   └──── crypto ── trust
             │        │
          session ── transport
             │
          streams ── signaling
             │          │
             └──► core ◄┘
                   │
     ┌─────────────┼─────────────┐
    cli          ffi            wasm         rendezvous (depends only on proto + crypto + signaling server-side)
```
`meridian-core` is the only crate the shims (`cli`, `ffi`, `wasm`, and Tauri's Rust side) depend on. The server depends on `meridian-proto` (shared wire types) and its own server-side crypto/signaling logic — it deliberately does **not** depend on `meridian-core` (it must never hold session/ratchet code paths; enforced by CODEOWNERS + a dependency-lint in CI, reinforcing the §2.3 "cannot" list).

## 4. One core, five targets — the build/binding matrix

| Target | Toolchain path | Core delivered as | UI layer | Transport impl |
|---|---|---|---|---|
| **Terminal** | `cargo build -p meridian-cli` | linked in-process | ratatui / stdout-json | webrtc-rs |
| **Browser** | `wasm-pack`/`trunk` on `meridian-wasm` → `bindings/typescript` | `.wasm` + JS glue | SvelteKit | browser `RTCPeerConnection` |
| **Desktop** | `cargo tauri build` (embeds core in the Tauri Rust process) | linked in-process | Tauri + shared-ui (Svelte) | webrtc-rs (data) / libwebrtc (media) |
| **Android** | `cargo ndk` → `.so` per ABI; UniFFI → `bindings/kotlin`; Gradle assembles | `.so` + Kotlin bindings | Jetpack Compose | libwebrtc (Android) |
| **iOS** | `cargo build --target aarch64-apple-ios`; UniFFI → `bindings/swift`; Xcode links `.a`/xcframework | static lib + Swift bindings | SwiftUI | libwebrtc (iOS) |
| **Server** | `cargo build -p meridian-rendezvous` | standalone binary | — (headless) | — |

Codegen is a single `just codegen` step (driven by `tools/xtask`): runs UniFFI to emit Kotlin+Swift, wasm-bindgen/tsify to emit the TS `.d.ts` for the WASM surface, and regenerates the CBOR type mirrors. Generated code is checked in so the mobile/IDE builds don't require the full Rust toolchain for a UI-only change — but a CI job re-runs codegen and fails if the checked-in output drifts (no stale bindings).

## 5. Dependency inventory (the actual libraries, tied to design decisions)

**Core / crypto:** `tokio`, `serde` + `ciborium` (CBOR, DOC-01), `ed25519-dalek` + `x25519-dalek` (identity/DH), `hkdf` + `hmac` + `sha2`/`sha2-512` (KDF, safety numbers), `chacha20poly1305` + `aes-gcm` (AEAD), `blake3` (file merkle, content addressing — T09/T15), `zeroize` (key hygiene). Ratchet + X3DH: hand-wired in `meridian-crypto` over the primitives above (ADR-R3 / [ADR 0015](../adr/0015-ratchet-composition.md); vodozemac's public API couldn't be seeded from an external X3DH root key). Groups (Phase 3): **openmls**. PQ slot (Phase 2): **ml-kem**.
**Transport:** `webrtc` (webrtc-rs) for data/ICE/SCTP; `libwebrtc` via a `-sys` binding crate for media; `stun`/`turn` client bits come with webrtc-rs.
**Signaling / server:** `axum`, `tokio-tungstenite` (WSS), `sqlx` (SQLite+Postgres), `rustls` (client & s2s mTLS), `governor` (rate limits), `tower-http` (middleware), `hickory-resolver` (DNS SRV federation discovery).
**Storage / keystore:** `keyring` (OS keystores), `age`/`scrypt` (headless keyfile), `rusqlite`/`sqlx` client-side encrypted store.
**Bindings/UI:** `uniffi`, `wasm-bindgen` + `tsify`; SvelteKit + Vite (web/desktop UI); Tauri v2; Jetpack Compose; SwiftUI.
**Dev/CI:** `cargo-nextest` (fast test runs), `cargo-deny` (license/advisory gate — matters for the libsignal AGPL question, ADR-R3), `cargo-ndk`, `wasm-pack`, `just`, `insta` (snapshot tests for wire formats).

Version pinning policy: exact pins in `Cargo.lock` and `pnpm-lock.yaml`; the wire-critical crates (`ciborium`, `ed25519-dalek`, ratchet lib) are pinned with a written upgrade-review requirement — a bump there can change bytes on the wire and must pass the conformance vectors before merge.

## 6. Architectural Decision Records (repo/stack forks)

### ADR-R1: Monorepo tooling — native toolchains + thin task runner
**Options:** (A) Bazel/Buck2; (B) Nx; (C) moon; (D) **Cargo workspace + pnpm + Gradle + SPM, glued by `just`/`xtask` (chosen)**.
**Trade-offs:** A is hermetic and scales to huge polyglot repos but imposes a heavy, full-time build-engineering tax and fights Cargo's native ergonomics — wrong for a 2–5 person team. B is excellent for JS but treats Rust as a second-class plugin, and Rust *is* our spine. C (moon) is a genuinely good polyglot task runner with real caching; it's the closest competitor. D uses each ecosystem's idiomatic tool (nothing exotic for a new hire to learn), keeps the Rust workspace pristine, and adds only a thin recipe layer. **Decision: D**, with **moon as a documented escape hatch** — if cross-language incremental caching becomes a measured bottleneck, moon layers on top without restructuring. **Consequence:** no free cross-language build graph; acceptable at this scale, revisited if CI wall-clock exceeds a set budget.

### ADR-R2: Desktop shell — Tauri v2 (not Electron, not native-per-OS)
**Options:** (A) Electron; (B) **Tauri v2 (chosen)**; (C) native per-OS (WinUI/AppKit/GTK).
**Trade-offs:** A ships a Chromium+Node runtime (~100 MB, high RAM) and would run the core in a separate Node process, forcing an IPC boundary around crypto — more surface, worse footprint. C gives the best per-OS polish but triples UI work and shares nothing with the browser client. B runs the Rust core *in-process* (no IPC around secrets), yields ~3–5 MB bundles, and lets desktop reuse the browser's Svelte UI. *Currency-checked:* Tauri v2 desktop is stable and production-grade (2.9.x, late 2025). **Decision: B.** **Consequence:** three WebView engines (WebView2/WKWebView/WebKitGTK) = "write once, test three"; mitigated by keeping platform-specific UI code near zero and the logic in Rust.

### ADR-R3: Ratchet library — libsignal vs. assembled primitives
**Options:** (A) **libsignal-client** (Signal's own Rust lib: X3DH + Double Ratchet, battle-tested); (B) **vodozemac** (Matrix's audited Rust ratchet) + hand-wired X3DH; (C) assemble from RustCrypto primitives ourselves.
**Trade-offs:** A is the most battle-tested implementation on earth but carries **AGPL-3.0** licensing and an API oriented to Signal's own app, which complicates embedding in a differently-licensed, self-hostable product — rejected on license grounds, unchanged below. B is Apache-2.0, audited, WASM-friendly, and closer to a library (built for reuse); it was the default pick pending a Phase-0 spike. C means the ratchet's protocol glue is hand-assembled rather than delegated to an audited implementation — a higher review burden, mitigated by keeping every underlying primitive (X25519, Ed25519, HKDF, HMAC, SHA-256, XChaCha20-Poly1305) audited RustCrypto code and adding conformance vectors + FS/PCS harnesses. **Decision: B for the X3DH-layer license/embeddability rationale (unchanged); C for the Double Ratchet itself** — the `ratchet-header-enc` spike (run against real code in T03, not documentation) found vodozemac 0.10's `Session` can only be constructed through Olm's own handshake, cannot be seeded from an externally-computed X3DH root key or the frozen `v:1` bundle, and exposes neither header encryption nor raw message keys, none of which are fixable without adopting Olm's identity/bundle model wholesale. See [ADR 0011](../adr/0011-ratchet-library.md) (X3DH layer, license rationale) and [ADR 0015](../adr/0015-ratchet-composition.md) (ratchet composition, the superseding decision) for the full record. `cargo-deny` gates the license decision in CI. **Consequence:** the ratchet sits behind `meridian-crypto`'s API so the rest of the tree is insulated; migrating back to vodozemac (or another library) remains open if it later exposes a compatible API.

### ADR-R4: Browser UI framework — SvelteKit (with React as the fallback)
**Options:** (A) **SvelteKit (chosen)**; (B) React; (C) SolidJS.
**Trade-offs:** the UI is a thin view over a WASM core doing all the real work, so bundle size and reactivity ergonomics matter more than ecosystem breadth. A yields the smallest bundles (relevant to the <4 MB WASM budget, T11) and clean reactivity; it's also a first-class Tauri frontend, so web + desktop share it. B has the largest talent pool and component ecosystem — the reason it's the named fallback if hiring or a component library forces it. C is technically excellent but a smaller ecosystem. **Decision: A**, shared between `clients/web` and `clients/desktop` via `shared-ui`. **Consequence:** the team commits to Svelte proficiency; the WASM boundary is framework-agnostic (plain TS API), so a later swap to React touches only the view layer.

### ADR-R5: Server web framework — axum
**Options:** (A) **axum (chosen)**; (B) actix-web; (C) Go rewrite.
**Trade-offs:** C would abandon the shared-`meridian-proto` guarantee (server and clients agreeing on wire types by *compiling the same crate*) — a real safety loss for a marginal ops gain. A and B are both strong Rust choices; axum's tower middleware ecosystem fits the rate-limiting/mTLS/observability needs cleanly and it shares tokio with the rest of the tree. **Decision: A.** **Consequence:** the whole backend is Rust; the small team maintains one language server-to-client.

## 7. What a new engineer runs on day one

```
git clone … && cd meridian
just setup            # installs toolchains: rustup targets, pnpm, cargo-nextest/-ndk/-deny, just
just build            # cargo workspace + pnpm build + codegen — all clients' cores
just test             # nextest + adversarial harnesses + conformance vectors
just cli              # drops you into meridian-cli against a local dev rendezvous
just dev-desktop      # Tauri dev with HMR, core in-process
just dev-web          # SvelteKit + WASM core, hot reload
just two-orgs         # brings up the demo/two-orgs federation stack (T06)
```
Every one of those recipes is exactly what CI runs. The design contract, the task acceptance demos (T01–T16), and the developer's local loop are the same commands — which is the whole point of gluing the polyglot repo with one task runner rather than a pile of per-directory READMEs.

## 8. Open stack questions (carried forward)
1. **libwebrtc build maintenance** is the long-term ops tax (§6, T12 risk) — decide in the Phase-0/1 spike whether to vendor prebuilt libwebrtc, use a maintained `-sys` crate, or (data-only paths) stay on webrtc-rs + libdatachannel and defer full media.
2. ~~**libsignal vs vodozemac** (ADR-R3)~~ — resolved: X3DH layer stays hand-wired over RustCrypto
   primitives (license/embeddability rationale unchanged); the Double Ratchet itself is composed
   in-house rather than delegated to vodozemac, per the `ratchet-header-enc` spike and
   [ADR 0015](../adr/0015-ratchet-composition.md). `cargo-deny` still gates the license decision.
3. **Checked-in vs generated bindings** — start checked-in (mobile/UI builds stay lightweight); revisit if merge noise from generated diffs becomes annoying (then generate in CI and stop tracking).
4. **moon adoption trigger** — define the CI wall-clock budget now so the escape-hatch decision (ADR-R1) is data-driven later.
