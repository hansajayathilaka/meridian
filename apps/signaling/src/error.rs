use meridian_proto::{error_codes, ErrBody};

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

    /// (2.9) A federated request was refused by the *hinted* org's own admission policy — `closed`,
    /// or an `allowlist` that does not include the requester (`fed_denied`, task 2.6). The wire
    /// deliberately collapses `closed`/`allowlist` (and, upstream of this, `not_found` at the
    /// policy layer) into this single code, so a denial can never be used to probe which policy
    /// mode — or which accounts — a partner org runs (2.6's rejection-reason decision, inherited
    /// here per this task's own risk note). This is diagnosable ("that org's policy refused this
    /// request") without inventing a precision the wire does not carry.
    ///
    /// A **policy** outcome — structurally distinct from [`SignalError::BundleVerification`] and
    /// never a security warning (ADR 0001 "hint is advisory";
    /// docs/security/verification-ux.md's canonical copy is reserved for actual key-substitution).
    #[error("federation denied: {hint} is not accepting this request ({detail})")]
    FedDenied { hint: String, detail: String },

    /// (2.9) The hinted org could not be reached at all — discovery/dial/protocol failure at the
    /// s2s boundary (`fed_unreachable`, tasks 2.7/2.8). A **connectivity** outcome, orthogonal to
    /// [`SignalError::FedDenied`]'s policy outcome and to [`SignalError::BundleVerification`]'s
    /// security check — the three are never conflated in copy or in type.
    #[error("{hint} is unreachable at hint ({detail})")]
    FedUnreachable { hint: String, detail: String },

    /// (2.9) The hinted org was reached and answered, but does not hold this account
    /// (`not_found_at_hint`, task 2.7) — the **stale-hint** case (ADR 0001: the hint is advisory
    /// routing information, never a trust input). Whether the target never registered at `hint` or
    /// (as in the acceptance scenario — the peer re-registered at a different org) re-registered
    /// elsewhere is indistinguishable from a single wire response; the copy names that ambiguity
    /// honestly rather than inventing precision the wire doesn't carry.
    ///
    /// This degrades **reachability only**. It is never, under any circumstance, a security
    /// warning, and it is structurally distinct from [`SignalError::BundleVerification`] —
    /// conflating "unreachable at hint" with "key substitution detected" is exactly the failure
    /// mode this variant (and this task) exists to prevent
    /// (docs/security/verification-ux.md's canonical copy is reserved for the latter).
    #[error("unreachable at hint {hint}: no such account there ({detail})")]
    NotFoundAtHint { hint: String, detail: String },
}

impl From<meridian_store::StoreError> for SignalError {
    fn from(e: meridian_store::StoreError) -> Self {
        SignalError::Store(e.to_string())
    }
}

/// (2.9) Reclassify a generic [`SignalError::Server`] into one of the federation-specific outcomes
/// above when the wire `code` identifies it as such, carrying `hint` — the domain **the caller
/// itself supplied** to the request, never anything server-internal — for diagnosable copy. Any
/// other error (including a code this function doesn't recognize) passes through unchanged; this
/// never touches [`SignalError::BundleVerification`], keeping the reachability/policy axis
/// structurally separate from the security-verification axis.
pub(crate) fn classify_federation_error(e: SignalError, hint: Option<&str>) -> SignalError {
    let SignalError::Server(body) = e else {
        return e;
    };
    let hint = hint.unwrap_or("(no hint)").to_string();
    if body.code == error_codes::FED_DENIED {
        SignalError::FedDenied {
            hint,
            detail: body.msg,
        }
    } else if body.code == error_codes::FED_UNREACHABLE {
        SignalError::FedUnreachable {
            hint,
            detail: body.msg,
        }
    } else if body.code == error_codes::NOT_FOUND_AT_HINT {
        SignalError::NotFoundAtHint {
            hint,
            detail: body.msg,
        }
    } else {
        SignalError::Server(body)
    }
}

pub type Result<T> = std::result::Result<T, SignalError>;
