use meridian_proto::ErrBody;

/// Errors from the client signaling module.
#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("websocket error: {0}")]
    Ws(String),
    #[error("wire codec error: {0}")]
    Codec(#[from] meridian_proto::CodecError),
    #[error("connection closed before {0}")]
    ClosedEarly(&'static str),
    #[error("unexpected frame op {got:?} (expected {expected})")]
    Unexpected {
        got: meridian_proto::Op,
        expected: &'static str,
    },
    /// The server returned a structured error frame.
    #[error("server error [{}]: {}", .0.code, .0.msg)]
    Server(ErrBody),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("secret store error: {0}")]
    Store(String),
    #[error("failed to gather randomness: {0}")]
    Rng(String),
    /// The security-critical check of T02: a fetched bundle did not verify under the requested
    /// key. This is a HARD failure — never a downgrade (system-design §3.3 step 4).
    #[error("bundle signature does not match requested identity — refusing to proceed ({0})")]
    BundleVerification(&'static str),
}

impl From<meridian_store::StoreError> for SignalError {
    fn from(e: meridian_store::StoreError) -> Self {
        SignalError::Store(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SignalError>;
