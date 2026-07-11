//! Errors for identity encode/parse/sign.

use thiserror::Error;

/// Why a hint (`@domain`) is not in canonical form. Kept specific so the CLI can tell a user
/// *what* is wrong, and so property tests can assert the exact rejection.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HintError {
    #[error("hint is empty")]
    Empty,
    #[error("hint is too long ({0} > 253 bytes)")]
    TooLong(usize),
    #[error("hint contains a non-ASCII character (IDNs must be punycode/`xn--`-encoded first)")]
    NonAscii,
    #[error("hint contains an uppercase character (canonical form is lowercase)")]
    NonCanonicalCase,
    #[error("hint contains a forbidden character (whitespace, '/', or '@')")]
    ForbiddenChar,
    #[error("hint has an empty label (leading/trailing dot or '..')")]
    EmptyLabel,
    #[error("hint label is longer than 63 characters")]
    LabelTooLong,
    #[error("hint label starts or ends with '-'")]
    LabelHyphenEdge,
    #[error("hint label contains a character outside [a-z0-9-]")]
    LabelBadChar,
}

/// Why an `mrd1:…` identity string failed to parse. Distinct variants because the acceptance
/// criteria hinge on *which* corruption is detected (checksum vs. case vs. structure).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdError {
    #[error("missing 'mrd1:' scheme prefix")]
    MissingScheme,
    #[error("malformed identity: expected exactly one '@' separating key and hint")]
    MalformedStructure,
    #[error("key part is not canonical lowercase base32")]
    NonCanonicalCase,
    #[error("key part is not valid base32")]
    BadBase32,
    #[error("key part has wrong length after decoding (expected {expected} bytes, got {got})")]
    BadLength { expected: usize, got: usize },
    #[error("unknown multicodec prefix (not ed25519-pub)")]
    UnknownMulticodec,
    #[error("checksum mismatch — the ID is corrupt or mistyped")]
    ChecksumMismatch,
    #[error("invalid hint: {0}")]
    BadHint(#[from] HintError),
    #[error("public key is not a valid Ed25519 point")]
    BadPublicKey,
}
