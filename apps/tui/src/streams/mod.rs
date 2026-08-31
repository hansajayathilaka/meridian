//! Additive TUI surfaces for stream types registered against `meridian-core`'s stream-type registry
//! (`docs/architecture/tui-client.md §8`, Definition of Done gate 9) — one submodule per stream
//! type, mirroring `apps/streams`'s own per-type module layout (`apps/streams/src/file.rs`, …).
//!
//! **Nothing here edits this crate's core.** Every item in these submodules is reached exclusively
//! through `crate::surface`'s three registration points (a [`crate::surface::MessageRenderer`], a
//! [`crate::surface::PaletteCommand`], and/or a [`crate::surface::ExtensionPane`]) — no new
//! `crate::app::Screen` variant, no event-loop dispatch, no layout-engine change. See each
//! submodule's own doc for the exact registrations it offers and — critically — for the one real,
//! structural gap this crate's registry mechanism (task 4.18) still has: there is no `pub` hook on
//! `crate::app::App` that lets an external registration reach a *live* `App`'s own
//! `crate::surface::SurfaceRegistry` without editing `crate::app::register_builtin_commands` (a
//! private function) directly. Every submodule here stops short of that edit, per task 10.11's own
//! explicit instruction to flag such a gap rather than paper over it with a core change — see
//! [`file`]'s module doc for the full writeup.

pub mod file;
