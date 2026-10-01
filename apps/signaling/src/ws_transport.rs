//! WebSocket transport seam (task 12.4): the only place `meridian-signaling` names a concrete
//! WebSocket implementation.
//!
//! `SignalingClient` used to hardcode `tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>`,
//! which has no `wasm32-unknown-unknown` story (it pulls in `mio`, which does not build there). This
//! module introduces a small **internal** trait, [`WsConnection`], over the three things the client
//! actually does with a socket — connect, send one binary frame, receive the next meaningful frame —
//! plus close, and two `cfg`-selected implementations:
//!
//! - **native** — [`NativeWs`], a thin wrapper over the existing `tokio-tungstenite` stream. The
//!   handshake, TLS (`rustls` + native roots), and per-message behavior are exactly what
//!   `SignalingClient` did inline before this seam existed; no wire change, no conformance-vector
//!   change.
//! - **wasm32 (`wasm32-unknown-unknown`)** — [`BrowserWs`], the browser's own `WebSocket` via
//!   `web-sys`. The browser owns TLS and certificate validation there (so no `rustls`, no
//!   `install_crypto_provider` work), and binary frames use `binaryType = "arraybuffer"`.
//!
//! This is **not** one of the two frozen `core-api-contracts.md` traits (`Transport` /
//! `SecretStore`): it is `pub(crate)`, never exposed, and `SignalingClient`'s public API is unchanged.
//! The two implementations are selected by a `cfg` type alias ([`PlatformWs`]), not `dyn`, so the
//! native client keeps its exact auto-trait (`Send`) properties; the browser socket is `!Send`, which
//! is fine on a single-threaded wasm32 executor.

use crate::error::Result;

/// The `cfg` that selects the browser implementation (and drops `tokio-tungstenite`/`rustls`).
/// Mirrors `meridian-core`'s timer seam (12.1): `wasm32-unknown-unknown` only, so
/// `wasm32-wasip*` keeps the native path.
macro_rules! cfg_browser {
    ($($item:item)*) => { $( #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] $item )* };
}
macro_rules! cfg_native {
    ($($item:item)*) => { $( #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] $item )* };
}

/// What the client needs to know about the next frame from the peer. Control frames that carry no
/// protocol meaning (ping/pong, and any frame kind the protocol does not use) are consumed inside
/// the implementation, never surfaced.
#[derive(Debug)]
pub(crate) enum Incoming {
    /// A binary frame — the only kind the rendezvous protocol uses.
    Binary(Vec<u8>),
    /// A text frame — a protocol violation; the caller decides how to fail.
    Text,
    /// The peer closed the connection (close frame / close event).
    Close,
}

/// A connected, message-oriented WebSocket. Internal seam; see the module docs.
///
/// `async fn` in a `pub(crate)` trait is deliberate: it is only ever used through the concrete
/// [`PlatformWs`] alias, never `dyn`, so no `Send` bound is imposed on the browser implementation.
pub(crate) trait WsConnection: Sized {
    /// Open a connection to `url` (`ws://` or `wss://`).
    async fn connect(url: &str) -> Result<Self>;

    /// Send one binary frame.
    async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()>;

    /// The next meaningful incoming frame, or `None` once the stream has ended.
    async fn recv(&mut self) -> Result<Option<Incoming>>;

    /// Close the connection.
    async fn close(&mut self) -> Result<()>;
}

/// Receive-side admission policy for the browser implementation (task 12.4 review).
///
/// The browser's `message` callback runs whenever the page's event loop turns, independent of
/// whether the async client is polling `recv`, so the channel between them must be bounded or a
/// hostile server could push frames at an idle client until the tab runs out of memory. (The native
/// path is bounded by tungstenite's own limits plus TCP backpressure.) This is the policy, kept pure
/// and platform-independent so it is unit-tested natively even though only the browser build uses it.
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    allow(dead_code)
)]
mod recv_budget {
    /// Largest single message accepted: 1 MiB. Signaling frames are small control/bundle/route
    /// frames (a bundle is ~100 one-time prekeys; bulk file data never rides the rendezvous, only the
    /// P2P channel), and 1 MiB matches the only in-repo frame cap precedent
    /// (`meridian-rendezvous` `federation::link::MAX_FRAME_LEN`). Far below tungstenite's 64 MiB
    /// default. `TODO: confirm` against the server's real largest routed envelope when the browser
    /// integration test lands.
    pub(crate) const MAX_MESSAGE_BYTES: usize = 1 << 20;
    /// Most bytes allowed queued-but-unread at once: 4 MiB (a few maximum-size frames).
    pub(crate) const MAX_QUEUED_BYTES: usize = 4 << 20;
    /// Most messages allowed queued-but-unread at once. Bounds the per-message overhead of a flood of
    /// tiny frames, which the byte budget alone would not.
    pub(crate) const MAX_QUEUED_MESSAGES: usize = 256;

    const _: () = assert!(MAX_QUEUED_BYTES >= MAX_MESSAGE_BYTES);

    /// Why a message was refused. Either is terminal for the connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Overflow {
        /// A single message exceeded [`MAX_MESSAGE_BYTES`].
        MessageTooLarge,
        /// Admitting it would exceed the queued bytes or queued message budget.
        QueueFull,
    }

    /// Running total of queued-but-unread messages. `try_admit` on the producer side (the browser
    /// callback), `release` on the consumer side (`recv`) with the same length.
    #[derive(Debug, Default)]
    pub(crate) struct RecvBudget {
        bytes: usize,
        msgs: usize,
    }

    impl RecvBudget {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Account for a message of `len` bytes about to be queued. On `Err` nothing is counted.
        pub(crate) fn try_admit(&mut self, len: usize) -> Result<(), Overflow> {
            if len > MAX_MESSAGE_BYTES {
                return Err(Overflow::MessageTooLarge);
            }
            let new_bytes = self.bytes.saturating_add(len);
            if new_bytes > MAX_QUEUED_BYTES || self.msgs >= MAX_QUEUED_MESSAGES {
                return Err(Overflow::QueueFull);
            }
            self.bytes = new_bytes;
            self.msgs += 1;
            Ok(())
        }

        /// A previously admitted message of `len` bytes has been dequeued.
        pub(crate) fn release(&mut self, len: usize) {
            self.bytes = self.bytes.saturating_sub(len);
            self.msgs = self.msgs.saturating_sub(1);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn single_message_cap_under_at_over() {
            let mut b = RecvBudget::new();
            assert_eq!(b.try_admit(MAX_MESSAGE_BYTES - 1), Ok(()));
            b.release(MAX_MESSAGE_BYTES - 1);
            assert_eq!(b.try_admit(MAX_MESSAGE_BYTES), Ok(()));
            b.release(MAX_MESSAGE_BYTES);
            assert_eq!(
                b.try_admit(MAX_MESSAGE_BYTES + 1),
                Err(Overflow::MessageTooLarge)
            );
            // usize::MAX must not overflow the accounting.
            assert_eq!(b.try_admit(usize::MAX), Err(Overflow::MessageTooLarge));
        }

        #[test]
        fn rejection_counts_nothing() {
            let mut b = RecvBudget::new();
            assert!(b.try_admit(MAX_MESSAGE_BYTES + 1).is_err());
            assert_eq!((b.bytes, b.msgs), (0, 0));
        }

        #[test]
        fn byte_budget_fills_rejects_then_release_readmits() {
            let mut b = RecvBudget::new();
            let n = MAX_QUEUED_BYTES / MAX_MESSAGE_BYTES;
            for _ in 0..n {
                assert_eq!(b.try_admit(MAX_MESSAGE_BYTES), Ok(()));
            }
            assert_eq!(b.try_admit(1), Err(Overflow::QueueFull));
            assert_eq!(b.bytes, MAX_QUEUED_BYTES);
            b.release(MAX_MESSAGE_BYTES);
            assert_eq!(b.try_admit(MAX_MESSAGE_BYTES), Ok(()));
            assert_eq!(b.try_admit(1), Err(Overflow::QueueFull));
            // A zero-byte frame still fits the byte budget; only the message-count budget bounds it.
            assert_eq!(b.try_admit(0), Ok(()));
        }

        #[test]
        fn message_count_budget_bounds_tiny_frame_floods() {
            let mut b = RecvBudget::new();
            for _ in 0..MAX_QUEUED_MESSAGES {
                assert_eq!(b.try_admit(1), Ok(()));
            }
            assert_eq!(b.try_admit(1), Err(Overflow::QueueFull));
            assert_eq!(b.try_admit(0), Err(Overflow::QueueFull));
            b.release(1);
            assert_eq!(b.try_admit(1), Ok(()));
        }

        #[test]
        fn release_saturates_and_never_underflows() {
            let mut b = RecvBudget::new();
            b.release(10);
            assert_eq!((b.bytes, b.msgs), (0, 0));
            assert_eq!(b.try_admit(5), Ok(()));
            b.release(500);
            assert_eq!((b.bytes, b.msgs), (0, 0));
        }
    }
}

cfg_native! {
    pub(crate) type PlatformWs = native::NativeWs;
}
cfg_browser! {
    pub(crate) type PlatformWs = browser::BrowserWs;
}

cfg_native! {
    mod native {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpStream;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

        use super::{Incoming, WsConnection};
        use crate::error::{Result, SignalError};

        /// The native implementation: the unchanged `tokio-tungstenite` stream.
        pub(crate) struct NativeWs {
            ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        }

        impl NativeWs {
            /// Wrap an already-established stream (the `test-support` TLS-config connect path
            /// builds its own connector, then hands the resulting stream here).
            #[cfg(feature = "test-support")]
            pub(crate) fn from_stream(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
                Self { ws }
            }
        }

        impl WsConnection for NativeWs {
            async fn connect(url: &str) -> Result<Self> {
                let (ws, _resp) = connect_async(url)
                    .await
                    .map_err(|e| SignalError::Ws(e.to_string()))?;
                Ok(Self { ws })
            }

            async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
                self.ws
                    .send(Message::Binary(bytes))
                    .await
                    .map_err(|e| SignalError::Ws(e.to_string()))
            }

            async fn recv(&mut self) -> Result<Option<Incoming>> {
                while let Some(msg) = self.ws.next().await {
                    let msg = msg.map_err(|e| SignalError::Ws(e.to_string()))?;
                    match msg {
                        Message::Binary(bytes) => return Ok(Some(Incoming::Binary(bytes))),
                        Message::Ping(_) | Message::Pong(_) => continue,
                        Message::Close(_) => return Ok(Some(Incoming::Close)),
                        Message::Text(_) => return Ok(Some(Incoming::Text)),
                        _ => continue,
                    }
                }
                Ok(None)
            }

            async fn close(&mut self) -> Result<()> {
                self.ws
                    .close(None)
                    .await
                    .map_err(|e| SignalError::Ws(e.to_string()))
            }
        }
    }
}

cfg_browser! {
    mod browser {
        use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
        use send_wrapper::SendWrapper;
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

        use std::sync::{Arc, Mutex, MutexGuard};

        use super::recv_budget::{Overflow, RecvBudget};
        use super::{Incoming, WsConnection};
        use crate::error::{Result, SignalError};

        /// What the browser's event callbacks forward to the awaiting task.
        enum BrowserEvent {
            Open,
            /// A binary frame; its length is what was admitted into the budget.
            Binary(Vec<u8>),
            /// A text frame (a protocol violation); carries only the length admitted.
            Text(usize),
            Error,
            Close,
        }

        type SharedBudget = Arc<Mutex<RecvBudget>>;

        fn lock(b: &SharedBudget) -> MutexGuard<'_, RecvBudget> {
            // Single-threaded on wasm32; a poisoned lock cannot carry a broken invariant here.
            b.lock().unwrap_or_else(|p| p.into_inner())
        }

        /// The browser implementation: a `web_sys::WebSocket` whose event callbacks feed a channel
        /// the async methods drain. The channel is unbounded as a type but **bounded by policy**:
        /// the `message` callback admits each frame through `RecvBudget` (per-message cap, queued
        /// bytes cap, queued message cap) and on overflow closes the socket and queues a terminal
        /// `Error` — see `recv_budget`.
        ///
        /// **`Send` (decision, flagged for ratification — see
        /// `docs/tasks/phase-12/12.4-signaling-ws-transport-seam.md#outcome`).** `meridian-core`'s
        /// `SignalRelay: Send` (and its `async_trait` futures) must be implementable over a
        /// `SignalingClient` on every target, and the browser's JS handles (`WebSocket`, `Closure`)
        /// are `!Send`. Rather than relax core's trait on wasm32, the JS-handle half is held in a
        /// [`SendWrapper`]: `Send` unconditionally, but any access from a thread other than the one
        /// that created it **panics** (and drop from another thread leaks instead of running). On
        /// `wasm32-unknown-unknown` there is one thread, so that never fires; if the crate is ever
        /// built with wasm threads the wrapper stays sound (it fails loudly) rather than becoming
        /// silent UB as a bare `unsafe impl Send` would. The channel receiver stays outside the
        /// wrapper so no `!Send` reference is held across an `.await`.
        ///
        /// The browser deliberately exposes no error detail to script (an `error` event carries
        /// nothing; the close code is the most it ever offers), so errors here are generic strings.
        /// Raw `JsValue` exceptions are never formatted into errors: a `SyntaxError` from
        /// `WebSocket::new` can embed the URL, which a caller may not want in a log line.
        /// TLS, certificate validation and the `Origin` header are the browser's, not ours.
        pub(crate) struct BrowserWs {
            rx: UnboundedReceiver<BrowserEvent>,
            /// Set once a `Close` has been surfaced, so a later `recv` reports end-of-stream
            /// instead of waiting forever on a channel that its own callbacks keep open.
            closed: bool,
            budget: SharedBudget,
            js: SendWrapper<JsHandles>,
        }

        /// The `!Send` browser objects. The callbacks must outlive the socket's use of them; they
        /// are dropped (after the handlers are detached, see `Drop`) with the connection.
        struct JsHandles {
            ws: WebSocket,
            _on_open: Closure<dyn FnMut(Event)>,
            _on_message: Closure<dyn FnMut(MessageEvent)>,
            _on_error: Closure<dyn FnMut(Event)>,
            _on_close: Closure<dyn FnMut(CloseEvent)>,
        }

        /// A coarse, fixed error: the `JsValue` exception is deliberately discarded (see
        /// [`BrowserWs`]'s docs on URL leakage).
        fn js_err(what: &'static str) -> SignalError {
            SignalError::Ws(format!("{what} failed"))
        }

        impl BrowserWs {
            /// Create the socket and wire its callbacks. Synchronous on purpose: every `!Send` local
            /// (`WebSocket`, `Closure`s) is moved into the `SendWrapper` and dropped from scope before
            /// `connect` first awaits, so none is held across an `.await` (the future stays `Send`).
            fn open_socket(url: &str) -> Result<Self> {
                let ws = WebSocket::new(url).map_err(|_| js_err("websocket open"))?;
                // Frames are binary; ask for an ArrayBuffer rather than the default Blob (whose
                // read-out is async).
                ws.set_binary_type(BinaryType::Arraybuffer);

                let (tx, rx) = unbounded_channel::<BrowserEvent>();
                let budget: SharedBudget = Arc::new(Mutex::new(RecvBudget::new()));
                let on_open = forward(&tx, |_: Event| Some(BrowserEvent::Open));
                let on_error = forward(&tx, |_: Event| Some(BrowserEvent::Error));
                let on_close = forward(&tx, |_: CloseEvent| Some(BrowserEvent::Close));
                let on_message = {
                    let tx = tx.clone();
                    let budget = Arc::clone(&budget);
                    let ws = ws.clone();
                    let mut tripped = false;
                    Closure::wrap(Box::new(move |e: MessageEvent| {
                        if tripped {
                            // Already failed closed; drop everything until the close lands.
                            return;
                        }
                        let data = e.data();
                        // Size is read BEFORE copying out of the JS heap, so an oversize frame is
                        // never duplicated into WASM memory.
                        let (len, binary) = if let Some(buf) = data.dyn_ref::<js_sys::ArrayBuffer>()
                        {
                            (buf.byte_length() as usize, true)
                        } else if let Some(text) = data.dyn_ref::<js_sys::JsString>() {
                            (text.length() as usize, false)
                        } else {
                            // Any other kind: ignored, like the native path ignores frame kinds
                            // the protocol does not use.
                            return;
                        };
                        let admitted = lock(&budget).try_admit(len);
                        if let Err(Overflow::MessageTooLarge | Overflow::QueueFull) = admitted {
                            // Fail closed: stop accepting, close the socket, and queue one terminal
                            // error (it bypasses the budget: it is a single small value).
                            tripped = true;
                            let _ = tx.send(BrowserEvent::Error);
                            let _ = ws.close();
                            return;
                        }
                        let ev = if binary {
                            let buf = data.unchecked_into::<js_sys::ArrayBuffer>();
                            BrowserEvent::Binary(js_sys::Uint8Array::new(&buf).to_vec())
                        } else {
                            BrowserEvent::Text(len)
                        };
                        let _ = tx.send(ev);
                    }) as Box<dyn FnMut(MessageEvent)>)
                };
                ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
                ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
                ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
                ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

                let conn = Self {
                    rx,
                    closed: false,
                    budget,
                    js: SendWrapper::new(JsHandles {
                        ws,
                        _on_open: on_open,
                        _on_message: on_message,
                        _on_error: on_error,
                        _on_close: on_close,
                    }),
                };
                Ok(conn)
            }
        }

        impl WsConnection for BrowserWs {
            async fn connect(url: &str) -> Result<Self> {
                let mut conn = Self::open_socket(url)?;

                // Resolve once the socket is open; an `error`/`close` before that is a failed
                // connect. (The browser fires `error` and then `close`; either ends it.)
                loop {
                    match conn.rx.recv().await {
                        Some(BrowserEvent::Open) => return Ok(conn),
                        Some(BrowserEvent::Error) | Some(BrowserEvent::Close) | None => {
                            return Err(SignalError::Ws("websocket connection failed".into()))
                        }
                        // Cannot arrive before `open`; ignore defensively.
                        Some(BrowserEvent::Binary(_)) | Some(BrowserEvent::Text(_)) => continue,
                    }
                }
            }

            /// Note: unlike the native sink (which awaits flush), this does **not** apply
            /// `bufferedAmount` backpressure — `WebSocket.send` queues in the browser and returns
            /// immediately. Fine for signaling's small request/response frames; a bulk sender over
            /// this seam would need to poll `bufferedAmount` itself.
            async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<()> {
                if self.js.ws.ready_state() != WebSocket::OPEN {
                    // `send()` on a closing/closed socket silently drops data in browsers; make it
                    // an error like the native sink does.
                    return Err(SignalError::Ws("websocket not open".into()));
                }
                self.js
                    .ws
                    .send_with_u8_array(&bytes)
                    .map_err(|_| js_err("websocket send"))
            }

            async fn recv(&mut self) -> Result<Option<Incoming>> {
                loop {
                    if self.closed {
                        return Ok(None);
                    }
                    match self.rx.recv().await {
                        Some(BrowserEvent::Binary(bytes)) => {
                            lock(&self.budget).release(bytes.len());
                            return Ok(Some(Incoming::Binary(bytes)));
                        }
                        Some(BrowserEvent::Text(len)) => {
                            lock(&self.budget).release(len);
                            return Ok(Some(Incoming::Text));
                        }
                        Some(BrowserEvent::Close) => {
                            self.closed = true;
                            return Ok(Some(Incoming::Close));
                        }
                        Some(BrowserEvent::Error) => {
                            return Err(SignalError::Ws("websocket error".into()))
                        }
                        // `open` cannot recur after connect; skip defensively.
                        Some(BrowserEvent::Open) => continue,
                        None => return Ok(None),
                    }
                }
            }

            async fn close(&mut self) -> Result<()> {
                // Initiates the closing handshake; the browser completes it in the background
                // (the `Drop` impl detaches our callbacks but does not abort it).
                self.js.ws.close().map_err(|_| js_err("websocket close"))
            }
        }

        impl Drop for JsHandles {
            fn drop(&mut self) {
                // Detach the handlers before the `Closure`s are freed so a late browser event
                // cannot call into a dropped closure, then ask the socket to close (a no-op if
                // it already has).
                self.ws.set_onopen(None);
                self.ws.set_onmessage(None);
                self.ws.set_onerror(None);
                self.ws.set_onclose(None);
                let _ = self.ws.close();
            }
        }

        /// Build a callback that maps a browser event to a [`BrowserEvent`] (or drops it) and
        /// forwards it to the channel. A send error just means the connection was dropped.
        fn forward<E: wasm_bindgen::convert::FromWasmAbi + 'static>(
            tx: &UnboundedSender<BrowserEvent>,
            map: impl Fn(E) -> Option<BrowserEvent> + 'static,
        ) -> Closure<dyn FnMut(E)> {
            let tx = tx.clone();
            Closure::wrap(Box::new(move |e: E| {
                if let Some(ev) = map(e) {
                    let _ = tx.send(ev);
                }
            }) as Box<dyn FnMut(E)>)
        }
    }
}

// Compile-time `Send` regression guard (wasm32 only; run by `cargo check --target
// wasm32-unknown-unknown`): `meridian-core`'s `SignalRelay: Send` needs `SignalingClient` and its
// connect/recv futures to stay `Send` even though the browser JS handles are not (`SendWrapper`).
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[allow(dead_code)]
fn _assert_send(store: &dyn meridian_identity::SecretStore, handle: &meridian_identity::KeyHandle) {
    fn is_send<T: Send>() {}
    fn is_send_val<T: Send>(_: T) {}
    is_send::<PlatformWs>();
    is_send::<crate::SignalingClient>();
    is_send_val(PlatformWs::connect(""));
    is_send_val(crate::SignalingClient::connect(
        "", store, handle, [0; 32], None, 1,
    ));
    let mut ws: Option<PlatformWs> = None;
    if let Some(ws) = ws.as_mut() {
        is_send_val(ws.recv());
        is_send_val(ws.send_binary(Vec::new()));
    }
}
