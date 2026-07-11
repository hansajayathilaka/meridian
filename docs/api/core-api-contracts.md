<!-- Source: DOC-04-api-contracts. Stable library interfaces. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [core modules diagram](../architecture/diagrams/core-modules.mermaid)

# Core API Contracts — `meridian-core` (Rust, surfaces via UniFFI + WASM)

Companion to D02. These are the *stable* interfaces platform shims and UI layers code against. Signatures are illustrative Rust; UniFFI generates Kotlin/Swift, wasm-bindgen generates TS. Freezing these early is what makes the interop matrix (T11) and conformance vectors (T01/T08) meaningful.

## Traits the platform MUST implement

```rust
/// The single reason the same core runs everywhere (D02). Browser impl wraps
/// RTCPeerConnection; native impls wrap webrtc-rs/libdatachannel/libwebrtc.
pub trait Transport: Send + Sync {
    async fn new_session(&self, cfg: IceConfig) -> Result<SessionHandle>;
    async fn add_data_channel(&self, s: &SessionHandle, cfg: ChannelCfg) -> Result<ChannelId>;
    async fn add_transceiver(&self, s: &SessionHandle, kind: MediaKind) -> Result<TrackId>;
    fn local_description(&self, s: &SessionHandle) -> Result<Sdp>;
    async fn set_remote_description(&self, s: &SessionHandle, sdp: Sdp) -> Result<()>;
    async fn add_ice_candidate(&self, s: &SessionHandle, c: IceCandidate) -> Result<()>;
    fn dtls_fingerprint(&self, s: &SessionHandle) -> Result<Fingerprint>; // for §4.6 binding
    async fn ice_restart(&self, s: &SessionHandle) -> Result<()>;
}

pub trait SecretStore: Send + Sync {           // OS keystore / enclave / wrapped keyfile
    fn store(&self, label: &str, secret: &[u8]) -> Result<KeyHandle>;
    fn use_key(&self, h: &KeyHandle, op: SignOrDh, input: &[u8]) -> Result<Vec<u8>>;
    fn nonextractable(&self) -> bool;           // surfaced in diagnostics
}
```

## Identity (T01 — frozen wire behavior)

```rust
fn generate_account(store: &dyn SecretStore) -> Result<AccountId>;
fn parse_id(s: &str) -> Result<Identity>;         // validates checksum/canonical form
fn to_id_string(pk: &PublicKey, hint: &str) -> String;
fn same_principal(a: &Identity, b: &Identity) -> bool;   // key-only, ignores hint
fn sign(store: &dyn SecretStore, h: &KeyHandle, msg: &[u8]) -> Result<Signature>;
fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool;
fn safety_number(local: &PublicKey, remote: &PublicKey) -> SafetyNumber; // order-independent
```

## Sessions & messaging (T03/T04)

```rust
async fn open_session(peer: &Identity) -> Result<Session>;   // fetch+verify bundle, X3DH, dial
async fn send_chat(sess: &Session, body: ChatMsg) -> Result<Eid>;
fn on_envelope(cb: impl Fn(DecryptedContent));               // verified + decrypted
fn trust_state(peer: &PublicKey) -> TrustState;
fn mark_verified(peer: &PublicKey) -> Result<()>;            // after safety-number compare
// Key/device change surfaces here; UI MUST honor block-on-verified (D06, DOC verification-ux)
```

## Stream registry — the extension point (T04, D12)

```rust
pub trait StreamType {
    fn name(&self) -> &'static str;             // e.g. "mrd.file/1"
    fn channel_cfg(&self) -> ChannelCfg;        // reliability/ordering or Rtp
    fn on_open(&self, sid: StreamId, params: Cbor, policy: &PolicyCtx) -> OpenDecision;
    fn on_frame(&self, sid: StreamId, frame: Bytes);
}
fn register_stream_type(t: Arc<dyn StreamType>);   // T09/T15/T16 use ONLY this — no core edits
async fn open_stream(sess: &Session, ty: &str, params: Cbor) -> Result<StreamId>;
```

## Stability policy
Traits above are **semver-stable from Phase 1**. Additive stream types never change them (enforced: CODEOWNERS on the core crate, D12). Envelope/bundle *wire* changes go through the `v` bump + capability negotiation in DOC-01 §7, never a silent break.
