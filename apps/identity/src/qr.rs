//! QR encode/decode of identity strings.
//!
//! The QR payload is exactly the canonical `mrd1:…@domain` string (system-design §3.1: "QR codes
//! carry the same payload plus an optional display name" — the display name is a local petname,
//! never authoritative, so it is out of the frozen payload here). Encoding renders a scannable
//! code for the terminal; decoding recovers the string, which callers then run through
//! [`crate::parse_id`] — a QR is a transport, not a trust anchor.

use image::{ImageBuffer, Luma};
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

/// Errors from QR encode/decode.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("could not build QR code: {0}")]
    Encode(String),
    #[error("no QR code found in image")]
    NotFound,
    #[error("could not decode QR code: {0}")]
    Decode(String),
}

/// Render `id` as a compact Unicode QR code for terminal display (`meridian id show --qr`).
pub fn render_terminal(id: &str) -> Result<String, QrError> {
    let code = QrCode::new(id.as_bytes()).map_err(|e| QrError::Encode(e.to_string()))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// Render `id` as a grayscale bitmap (one byte per pixel; 0 = black module). Useful for writing a
/// PNG or for the encode→decode conformance round-trip.
pub fn render_luma(id: &str) -> Result<ImageBuffer<Luma<u8>, Vec<u8>>, QrError> {
    let code = QrCode::new(id.as_bytes()).map_err(|e| QrError::Encode(e.to_string()))?;
    Ok(code
        .render::<Luma<u8>>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build())
}

/// Decode the identity string carried by a grayscale QR bitmap.
pub fn decode_luma(img: &ImageBuffer<Luma<u8>, Vec<u8>>) -> Result<String, QrError> {
    let mut prepared = rqrr::PreparedImage::prepare(img.clone());
    let grids = prepared.detect_grids();
    let grid = grids.first().ok_or(QrError::NotFound)?;
    let (_meta, content) = grid.decode().map_err(|e| QrError::Decode(e.to_string()))?;
    Ok(content)
}
