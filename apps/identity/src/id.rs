//! The frozen `mrd1:…@domain` identity string: encode, parse, validate.
//!
//! Wire-frozen spec: `../../docs/api/identity-format.md`. Do not change any constant in this file
//! without a versioned migration — these bytes end up on business cards and QR codes.

use std::sync::OnceLock;

use data_encoding::{Encoding, Specification};

use crate::error::{HintError, IdError};

/// Scheme prefix. The trailing `1` is the format version, mirroring bech32/`did:key` practice.
pub const SCHEME: &str = "mrd1:";

/// Multicodec prefix for an Ed25519 public key, as an unsigned-varint: `0xed 0x01`. This is the
/// standard `ed25519-pub` code (0xed) LEB128-encoded, identical to `did:key`'s `z6Mk…` payload.
/// **Frozen.**
pub const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Length of the Ed25519 public key. **Frozen.**
pub const PUBKEY_LEN: usize = 32;

/// Length of the CRC32C (Castagnoli) checksum appended to the key part. **Frozen.**
pub const CHECKSUM_LEN: usize = 4;

/// Total decoded length of the base32 key part: prefix ‖ pubkey ‖ checksum.
pub const KEY_PART_LEN: usize = MULTICODEC_ED25519_PUB.len() + PUBKEY_LEN + CHECKSUM_LEN;

/// Maximum hint length in bytes (DNS name limit).
const MAX_HINT_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Lowercase, unpadded RFC 4648 base32 — the canonical alphabet for the key part. Built once;
/// decoding is case-sensitive, so uppercase input is rejected as non-canonical.
fn base32() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = Specification::new();
        spec.symbols.push_str(
            &data_encoding::BASE32_NOPAD
                .specification()
                .symbols
                .to_lowercase(),
        );
        spec.encoding()
            .expect("lowercase base32 spec is valid by construction")
    })
}

/// CRC32C over `data`, as 4 big-endian bytes. **Byte order frozen.**
fn checksum(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    crc32c::crc32c(data).to_be_bytes()
}

/// Encode the key part (everything between `mrd1:` and `@`) for a 32-byte public key.
pub fn encode_key_part(pubkey: &[u8; PUBKEY_LEN]) -> String {
    let mut buf = Vec::with_capacity(KEY_PART_LEN);
    buf.extend_from_slice(&MULTICODEC_ED25519_PUB);
    buf.extend_from_slice(pubkey);
    let crc = checksum(&buf); // over prefix ‖ pubkey
    buf.extend_from_slice(&crc);
    base32().encode(&buf)
}

/// Decode and verify a key part, returning the 32-byte public key. Checks canonical case, base32
/// validity, length, multicodec prefix, and checksum — in that order.
pub fn decode_key_part(key_part: &str) -> Result<[u8; PUBKEY_LEN], IdError> {
    if key_part.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(IdError::NonCanonicalCase);
    }
    let bytes = base32()
        .decode(key_part.as_bytes())
        .map_err(|_| IdError::BadBase32)?;
    if bytes.len() != KEY_PART_LEN {
        return Err(IdError::BadLength {
            expected: KEY_PART_LEN,
            got: bytes.len(),
        });
    }
    let (prefix, rest) = bytes.split_at(MULTICODEC_ED25519_PUB.len());
    if prefix != MULTICODEC_ED25519_PUB {
        return Err(IdError::UnknownMulticodec);
    }
    let (pubkey, crc) = rest.split_at(PUBKEY_LEN);
    if checksum(&bytes[..MULTICODEC_ED25519_PUB.len() + PUBKEY_LEN]) != crc {
        return Err(IdError::ChecksumMismatch);
    }
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(pubkey);
    Ok(out)
}

/// Validate a hint (`@domain`) against the canonical form: ASCII, lowercase, LDH labels, no
/// leading/trailing/double dots. Non-ASCII is rejected outright — this is the homoglyph defense
/// (a Cyrillic look-alike domain fails here; IDNs must be punycode-encoded by the caller first).
pub fn validate_hint(hint: &str) -> Result<(), HintError> {
    if hint.is_empty() {
        return Err(HintError::Empty);
    }
    if hint.len() > MAX_HINT_LEN {
        return Err(HintError::TooLong(hint.len()));
    }
    if !hint.is_ascii() {
        return Err(HintError::NonAscii);
    }
    for &b in hint.as_bytes() {
        if b.is_ascii_uppercase() {
            return Err(HintError::NonCanonicalCase);
        }
        if b == b'/' || b == b'@' || (b as char).is_ascii_whitespace() {
            return Err(HintError::ForbiddenChar);
        }
    }
    for label in hint.split('.') {
        if label.is_empty() {
            return Err(HintError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(HintError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(HintError::LabelHyphenEdge);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(HintError::LabelBadChar);
        }
    }
    Ok(())
}

/// A parsed identity: the *key* (the principal) plus an *advisory* routing hint. Two identities
/// with the same key are the same principal regardless of hint (system-design §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pubkey: [u8; PUBKEY_LEN],
    hint: String,
}

impl Identity {
    /// Build from a validated public key and hint. Returns [`IdError::BadHint`] on a bad hint.
    pub fn new(pubkey: [u8; PUBKEY_LEN], hint: impl Into<String>) -> Result<Self, IdError> {
        let hint = hint.into();
        validate_hint(&hint)?;
        Ok(Self { pubkey, hint })
    }

    /// The raw 32-byte Ed25519 public key — the actual identity.
    pub fn pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.pubkey
    }

    /// The advisory routing hint (`@domain`).
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// Canonical `mrd1:…@domain` string.
    pub fn to_id_string(&self) -> String {
        format!("{}{}@{}", SCHEME, encode_key_part(&self.pubkey), self.hint)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_id_string())
    }
}

/// Encode a public key + hint into a canonical identity string. Fails only if the hint is not
/// canonical.
pub fn to_id_string(pubkey: &[u8; PUBKEY_LEN], hint: &str) -> Result<String, IdError> {
    validate_hint(hint)?;
    Ok(format!("{}{}@{}", SCHEME, encode_key_part(pubkey), hint))
}

/// Parse and fully validate an `mrd1:…@domain` string (checksum + canonical form + hint).
pub fn parse_id(s: &str) -> Result<Identity, IdError> {
    let body = s.strip_prefix(SCHEME).ok_or(IdError::MissingScheme)?;
    // The key part is base32 (no '@'); the hint is LDH (no '@'). Exactly one '@' must separate
    // them.
    let mut parts = body.splitn(2, '@');
    let key_part = parts.next().ok_or(IdError::MalformedStructure)?;
    let hint = parts.next().ok_or(IdError::MalformedStructure)?;
    if key_part.is_empty() || hint.contains('@') {
        return Err(IdError::MalformedStructure);
    }
    let pubkey = decode_key_part(key_part)?;
    validate_hint(hint)?;
    Ok(Identity {
        pubkey,
        hint: hint.to_string(),
    })
}

/// Whether two identities are the *same principal* — key-only comparison, hint ignored
/// (system-design §3.1; wire-protocol §1).
pub fn same_principal(a: &Identity, b: &Identity) -> bool {
    a.pubkey == b.pubkey
}
