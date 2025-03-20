//! Segment encoding/decoding implementations with compression-optimized
//! routines.
//!
//! This module handles the compressed encoding and decoding of integer segments
//! using bitmap encoding optimized for specific data patterns. The codec
//! implements several efficiency techniques:
//!
//! - **Delta-offset optimization**: Offsets are delta-encoded for space savings
//! - **LEB128 variable-length encoding**: Minimizes space for numeric values
//!
//! ## Safety Considerations
//!
//! The decoder implements multiple safety checks to handle potentially
//! malicious or corrupt inputs:
//!
//! - Validates allocation sizes to prevent excessive memory usage when decoding
//! - Handles integer overflow with checked arithmetic
//! - Properly handles truncated or incomplete data
//! - Enforces semantic constraints on segment relationships
//!
//! ## Format
//!
//! Each segment is encoded as:
//!
//! 1. Offset value (LEB128-encoded, delta compressed after first segment)
//! 2. Bitmap length (LEB128-encoded)
//! 3. Bitmap bytes (1 bit per value)

use super::segment;

mod decoder;
mod encoder;

/// Trait for types that can be encoded to bytes.
pub trait Encodable {
    /// Encodes an instance into a byte vector.
    fn encode(&self) -> Vec<u8>;
}

/// Trait for types that can be decoded from bytes.
pub trait Decodable: Sized {
    /// Decodes an instance from bytes.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Detailed errors that can occur during segment decoding.
/// These errors provide specific diagnostics for compression format issues.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Error decoding LEB128-encoded value
    #[error("error decoding LEB128 value: {0}")]
    Leb128(#[from] crate::leb128::Error),

    /// I/O error during decoding
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),

    /// Buffer ended unexpectedly during decoding
    #[error("unexpected end of data")]
    UnexpectedEndOfData,

    /// Error adding decoded values to a segment
    #[error("error decoding segment values: {0}")]
    Segment(#[from] segment::SegmentError),

    /// Error adding decoded segments to a collection (i.e. overlapping segments)
    #[error("error decoding segment values: {0}")]
    Segments(#[from] crate::idpack::segments::SegmentsError),

    /// Numeric overflow during decoding calculations
    #[error("arithmetic overflow")]
    ArithmeticOverflow,

    /// Total allocation size exceeds safety limit
    #[error("byte allocation limit exceeded: {0}")]
    ByteAllocationLimit(u64),
}
