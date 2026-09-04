//! The transport seam between [`crate::client::SignalingClient`] and the underlying WebSocket
//! connection (task 12.4).
//!
//! `SignalingClient` used to hardcode `tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>`
//! as its own field type — a shape with no `wasm32-unknown-unknown` story at all (`tokio-tungstenite`
//! pulls in real TCP sockets via `mio`, unavailable on that target). This module introduces a small
//! internal [`WsConnection`] trait so the client speaks one interface regardless of target:
//! [`native::NativeWsConnection`] wraps the existing `tokio-tungstenite` stream **unchanged** — same
//! handshake, same wire bytes, same error strings — while [`wasm::WasmWsConnection`] wraps the
//! browser's own native `WebSocket` object via `web-sys` (event closures bridged through
//! `wasm-bindgen` + a `futures-channel::mpsc` queue — see that module's own doc comment).
//!
//! **Not** one of the two frozen `core-api-contracts.md` traits (`Transport`/`SecretStore`, see
//! `docs/api/core-api-contracts.md`) — this is an internal implementation seam local to this crate,
//! never exposed outside it (`pub(crate)` throughout), so it raises no stability-policy question and
//! needs no ADR (per the architect consult recorded in `docs/tasks/phase-12/README.md` point 3).
//! Only one of the two impls below is ever compiled into a given build (`cfg(target_arch =
//! "wasm32")` is mutually exclusive with its negation) — there is never a runtime choice between
//! them, so [`WsStream`] is a plain per-target type alias, not a `dyn` trait object; the trait exists
//! purely so `client.rs` can be written once against a single interface instead of `cfg`-forking
//! every call site.

use crate::error::Result;

/// One inbound WebSocket event, covering exactly the subset of message kinds
/// [`crate::client::SignalingClient::recv_frame`] has ever handled: binary frames carry a wire
/// [`meridian_proto::Frame`], text is always a protocol violation (this protocol is binary-only),
/// ping/pong are transparently absorbed, close ends the stream. `Other` is a forward-compatible
/// catch-all for any event kind neither side of this seam needs to distinguish (e.g.
/// `tungstenite::Message`'s own raw `Frame` variant, never produced by ordinary reads) — treated
/// identically to ping/pong (ignored, keep reading).
// `Ping`/`Pong` are only ever constructed by the native impl (`tungstenite::Message::Ping`/`Pong`
// frames it reads directly off the wire); the browser `WebSocket` API auto-answers ping/pong at
// the protocol level and never surfaces either to JS, so `wasm::decode_message_event` never
// produces them — correctly dead on that target only, not a bug.
#[derive(Debug)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) enum WsEvent {
    Binary(Vec<u8>),
    Text,
    Ping,
    Pong,
    Close,
    Other,
}

/// The transport seam itself. `&mut self` throughout (mirrors `SignalingClient`'s own
/// exclusive-ownership usage) — no impl here is ever shared or cloned.
pub(crate) trait WsConnection {
    /// Send one binary WebSocket frame. Every wire frame this client ever sends is binary
    /// (`client.rs::send`) — there is no text-frame send path to abstract.
    async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()>;

    /// Await the next inbound event, or `None` once the stream is exhausted (mirrors
    /// `futures_util::Stream::next`'s own `Option` shape, which the native impl wraps directly).
    async fn next_event(&mut self) -> Option<Result<WsEvent>>;

    /// Close the connection cleanly.
    async fn close(&mut self) -> Result<()>;
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    use crate::error::{Result, SignalError};

    use super::{WsConnection, WsEvent};

    /// Wraps the existing `tokio-tungstenite` stream **unchanged** — byte-identical
    /// handshake/wire behavior to the pre-seam code, just moved behind [`WsConnection`] instead of
    /// being `SignalingClient`'s own field type directly.
    pub(crate) struct NativeWsConnection {
        inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
    }

    impl NativeWsConnection {
        pub(crate) fn new(inner: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
            Self { inner }
        }
    }

    impl WsConnection for NativeWsConnection {
        async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
            self.inner
                .send(Message::Binary(bytes))
                .await
                .map_err(|e| SignalError::Ws(e.to_string()))
        }

        async fn next_event(&mut self) -> Option<Result<WsEvent>> {
            match self.inner.next().await {
                None => None,
                Some(Err(e)) => Some(Err(SignalError::Ws(e.to_string()))),
                Some(Ok(msg)) => Some(Ok(match msg {
                    Message::Binary(bytes) => WsEvent::Binary(bytes),
                    Message::Text(_) => WsEvent::Text,
                    Message::Ping(_) => WsEvent::Ping,
                    Message::Pong(_) => WsEvent::Pong,
                    Message::Close(_) => WsEvent::Close,
                    // `tungstenite::Message` is non-exhaustive (e.g. its raw `Frame` variant,
                    // never produced by an ordinary `.next()` read) — treat anything else exactly
                    // like a ping/pong: ignorable, keep reading.
                    _ => WsEvent::Other,
                })),
            }
        }

        async fn close(&mut self) -> Result<()> {
            self.inner
                .close(None)
                .await
                .map_err(|e| SignalError::Ws(e.to_string()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
    use futures_channel::oneshot;
    use futures_util::StreamExt;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::JsValue;
    use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

    use crate::error::{Result, SignalError};

    use super::{WsConnection, WsEvent};

    fn js_err(prefix: &str, v: &JsValue) -> SignalError {
        let detail = v
            .as_string()
            .or_else(|| js_sys::Error::from(v.clone()).message().as_string())
            .unwrap_or_else(|| format!("{v:?}"));
        SignalError::Ws(format!("{prefix}: {detail}"))
    }

    /// Wraps the browser's own native `WebSocket` object (via `web-sys`), bridging its
    /// callback-based event model (`onopen`/`onmessage`/`onerror`/`onclose`) onto the same
    /// pull-based [`WsConnection::next_event`] interface [`super::native::NativeWsConnection`]
    /// exposes, via an internal `futures_channel::mpsc` queue fed from the JS closures.
    ///
    /// The closures are stored on this struct (`_on_message`/`_on_error`/`_on_close`) purely to
    /// keep them alive for the lifetime of the connection — `web_sys::WebSocket` only holds a raw
    /// JS reference to each callback, not the closure's Rust-side allocation; dropping the
    /// `Closure` before the socket is done would leave the JS side calling into freed memory.
    pub(crate) struct WasmWsConnection {
        socket: WebSocket,
        events: UnboundedReceiver<Result<WsEvent>>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(ErrorEvent)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
    }

    // `web_sys::WebSocket`/`wasm_bindgen::closure::Closure` wrap a `JsValue`, which `wasm-bindgen`
    // deliberately does not mark `Send` — a `JsValue` is only ever valid on the single wasm
    // instance/JS thread that created it, a real hazard when a build enables the `atomics` target
    // feature (a multi-threaded wasm module backed by `SharedArrayBuffer` + real Web Workers).
    //
    // This workspace's wasm32 target is plain `wasm32-unknown-unknown` (`rust-toolchain.toml`, no
    // `+atomics`), which has **no thread-spawning capability at all** — `std::thread::spawn` is not
    // just discouraged but unavailable on this exact target/feature combination, so there is no
    // code path by which a `WasmWsConnection` could ever actually cross a real OS thread boundary.
    // `meridian_core::session::SignalRelay: Send` (native-only requirement, unrelated to this seam)
    // is otherwise unsatisfiable by any wasm32 `SignalingClient`-backed relay — this `unsafe impl`
    // asserts a bound that is vacuously true on the one target it's compiled for, the same
    // pattern crates like `send_wrapper` package up generically for exactly this shape of problem
    // (not pulled in as a dependency here — the reasoning is self-contained and narrow enough to
    // state directly). Confined entirely to this `pub(crate)` wasm32-only type — the native impl
    // and the native `Send` bound on `SignalRelay` are completely untouched.
    //
    // (review, task 12.4) Compile-time tripwire: this soundness argument depends entirely on the
    // single-threaded, no-thread-spawning `wasm32-unknown-unknown` target this workspace actually
    // builds for today (no `+atomics` anywhere — see above). If this workspace ever turns on the
    // `atomics`/`bulk-memory` target features for a genuinely multi-threaded wasm build, a
    // `JsValue`-backed type really can cross threads and this `unsafe impl` becomes unsound; gate
    // it so that future switch fails to compile here instead of silently shipping unsound code.
    #[cfg(not(target_feature = "atomics"))]
    unsafe impl Send for WasmWsConnection {}

    impl WasmWsConnection {
        /// Open a new browser `WebSocket` to `url` and resolve once it either reaches `OPEN` or
        /// fails — mirrors `tokio_tungstenite::connect_async`'s own "resolves once the connection
        /// is usable" contract, so `client.rs`'s `connect`/`connect_owned` bodies need only branch
        /// on which constructor to call, not on a differently-shaped result.
        pub(crate) async fn connect(url: &str) -> Result<Self> {
            let socket =
                WebSocket::new(url).map_err(|e| js_err("failed to construct WebSocket", &e))?;
            socket.set_binary_type(BinaryType::Arraybuffer);

            let (open_tx, open_rx) = oneshot::channel::<std::result::Result<(), String>>();
            let (events_tx, events_rx) = unbounded::<Result<WsEvent>>();

            // `onopen` only ever fires the very first time the socket reaches OPEN — feed it into
            // the one-shot `connect()` result, not the ongoing `events` queue.
            let open_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(open_tx)));
            let on_open = {
                let open_tx = open_tx.clone();
                Closure::<dyn FnMut()>::new(move || {
                    if let Some(tx) = open_tx.borrow_mut().take() {
                        let _ = tx.send(Ok(()));
                    }
                })
            };
            socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));

            let events_tx_msg: UnboundedSender<Result<WsEvent>> = events_tx.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
                let event = decode_message_event(&ev);
                let _ = events_tx_msg.unbounded_send(event);
            });
            socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let events_tx_err = events_tx.clone();
            let open_tx_err = open_tx.clone();
            let on_error = Closure::<dyn FnMut(ErrorEvent)>::new(move |ev: ErrorEvent| {
                let msg = ev.message();
                let msg = if msg.is_empty() {
                    "websocket error event".to_string()
                } else {
                    msg
                };
                if let Some(tx) = open_tx_err.borrow_mut().take() {
                    let _ = tx.send(Err(msg.clone()));
                } else {
                    let _ = events_tx_err.unbounded_send(Err(SignalError::Ws(msg)));
                }
            });
            socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            let events_tx_close = events_tx.clone();
            let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |_ev: CloseEvent| {
                let _ = events_tx_close.unbounded_send(Ok(WsEvent::Close));
            });
            socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));

            match open_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(msg)) => return Err(SignalError::Ws(msg)),
                Err(_) => return Err(SignalError::Ws("connect: socket dropped".into())),
            }

            Ok(Self {
                socket,
                events: events_rx,
                _on_message: on_message,
                _on_error: on_error,
                _on_close: on_close,
            })
        }
    }

    fn decode_message_event(ev: &MessageEvent) -> Result<WsEvent> {
        let data = ev.data();
        if let Ok(buf) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
            let bytes = js_sys::Uint8Array::new(&buf).to_vec();
            return Ok(WsEvent::Binary(bytes));
        }
        if data.as_string().is_some() {
            // This protocol is binary-only (`client.rs::send` never emits a text frame); a peer
            // sending text is exactly as much a protocol violation here as
            // `Message::Text` was on the native path.
            return Ok(WsEvent::Text);
        }
        // Anything else (e.g. a `Blob`, if `binary_type` were ever misconfigured) is treated like
        // the native impl's non-exhaustive catch-all: ignorable, keep reading.
        Ok(WsEvent::Other)
    }

    impl WsConnection for WasmWsConnection {
        async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
            self.socket
                .send_with_u8_array(&bytes)
                .map_err(|e| js_err("send failed", &e))
        }

        async fn next_event(&mut self) -> Option<Result<WsEvent>> {
            self.events.next().await
        }

        async fn close(&mut self) -> Result<()> {
            self.socket.close().map_err(|e| js_err("close failed", &e))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::NativeWsConnection;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type WsStream = NativeWsConnection;

#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::WasmWsConnection;
#[cfg(target_arch = "wasm32")]
pub(crate) type WsStream = WasmWsConnection;
