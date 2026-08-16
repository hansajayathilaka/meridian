//! Individual screen implementations (task 4.16+). Each module owns one [`crate::app::Screen`]
//! variant's own sub-state, `update`-equivalent (`handle_key`/`handle_worker`), and `render`
//! function — `app.rs`'s `App::update`/`App::render` only dispatch to them. Adding a new screen
//! means adding a `Screen` variant plus a module here; it never means editing another screen's
//! file (docs/architecture/tui-client.md §2/§8's extension-contract shape, applied within this
//! crate to its own screens).

pub mod chat;
pub mod contact_detail;
pub mod contacts;
pub mod onboarding;
pub mod requests;
pub mod unlock;
pub mod verify;
