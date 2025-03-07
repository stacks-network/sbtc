//! # LEB128 Variable-Length Integer Encoding
//!
//! This module implements Little Endian Base 128 (LEB128) encoding for maximum
//! compression of integer values. LEB128 is a variable-length encoding that uses
//! fewer bytes for smaller values, making it ideal for delta encoding and offsets.
//!
//! ## Compression Benefits
//!
//! - **Small Values (0-127)**: Encoded in just 1 byte
//! - **Medium Values (128-16383)**: Encoded in 2 bytes
//! - **Large Values**: Additional bytes only as needed
//!
//! This encoding is critical for the segmentation system's compression efficiency
//! as it minimizes bytes used for small differences between segments, sequence
//! lengths, and offsets - all common in optimized integer encodings.
//!
//! ## Encoding Format
//!
//! Each byte uses:
//! - Lower 7 bits for value data
//! - High bit (0x80) as continuation flag
//!
//! For example, decimal 300 encodes as: [0xAC, 0x02]
//! - 0xAC = 10101100: High bit set (more bytes follow) + bits 0-6 of value
//! - 0x02 = 00000010: High bit clear (final byte) + bits 7-13 of value

use std::io::Cursor;

/// Errors that can occur during LEB128 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The LEB128 sequence was incomplete or invalid.
    #[error("LEB128 decoding error")]
    Leb128Decode,

    /// Attempted to decode from an empty input.
    #[error("empty input")]
    EmptyInput,

    /// Value exceeds 64 bits (u64 maximum).
    #[error("value too large; max 64 bits")]
    ValueTooLarge { max_bits: usize, actual_bits: usize },
}

/// Utility for LEB128 encoding/decoding operations.
///
/// Provides maximum compression efficiency for integer values by using
/// a variable number of bytes depending on the magnitude of the value.
#[derive(Debug, Clone)]
pub struct Leb128;

#[allow(clippy::len_without_is_empty)]
impl Leb128 {
    /// Encodes a u64 into LEB128 format, appending to the provided buffer.
    ///
    /// This encoding achieves optimal compression by using fewer bytes for
    /// smaller values, which are common in delta encodings and sparse sequences.
    ///
    /// ## Parameters
    /// * `value` - The integer to encode
    /// * `bytes` - The buffer to append the encoded bytes to
    pub fn encode_into(value: u64, bytes: &mut Vec<u8>) {
        let mut value = value;
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;

            if value != 0 {
                byte |= 0x80;
            }

            bytes.push(byte);

            if value == 0 {
                break;
            }
        }
    }

    /// Decodes a LEB128-encoded value from bytes.
    ///
    /// Parses a variable-length integer and returns both the decoded value
    /// and the number of bytes consumed from the input.
    ///
    /// ## Parameters
    /// * `bytes` - The LEB128-encoded input
    ///
    /// ## Returns
    /// * `Ok((value, bytes_read))` - The decoded value and consumed bytes
    /// * `Err(Error)` - If decoding fails
    pub fn try_decode(bytes: &[u8]) -> Result<(u64, usize), Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyInput);
        }

        let mut result: u64 = 0;
        let mut position = 0;

        for (i, &byte) in bytes.iter().enumerate() {
            let value = (byte & 0x7f) as u64;
            result |= value << (i * 7);
            position += 1;

            if (byte & 0x80) == 0 {
                return Ok((result, position));
            }

            if i >= 9 {
                // Max 64 bits / 7 bits per byte rounded up
                return Err(Error::ValueTooLarge {
                    max_bits: 64,
                    actual_bits: 7 * (i + 1),
                });
            }
        }

        Err(Error::Leb128Decode)
    }

    /// Calculates the size in bytes that a value would occupy when LEB128 encoded.
    ///
    /// This is critical for size estimation during segment encoding decisions,
    /// allowing the segmentation system to choose optimal compression strategies
    /// without actually performing the encoding.
    ///
    /// ## Parameters
    /// * `value` - The integer value to measure
    ///
    /// ## Returns
    /// The number of bytes required to encode the value
    pub fn calculate_size(value: u64) -> usize {
        let mut value = value;
        let mut size = 0;
        while value >= 0x80 {
            size += 1;
            value >>= 7;
        }
        size += 1;
        size
    }
}

/// Trait for reading LEB128-encoded values from a data source.
///
/// This abstraction allows different sources to efficiently decode LEB128
/// values while managing their own state and position tracking.
pub trait ReadLeb128 {
    /// Reads a LEB128-encoded value from the source.
    ///
    /// ## Returns
    /// * `Ok(value)` - The decoded integer value
    /// * `Err(Error)` - If decoding fails
    fn read_leb128(&mut self) -> Result<u64, Error>;
}

/// Implementation for reading LEB128 values from a byte cursor.
///
/// Efficiently reads LEB128-encoded integers from a cursor while advancing
/// the position, enabling sequential decoding of multiple values.
impl ReadLeb128 for Cursor<&[u8]> {
    fn read_leb128(&mut self) -> Result<u64, Error> {
        // Get position before read
        let start_pos = self.position() as usize;

        // Create a slice from the current position
        let remaining_bytes = &self.get_ref()[start_pos..];

        // Try to decode a LEB128 value
        let (value, bytes_read) = Leb128::try_decode(remaining_bytes)?;

        // Advance cursor position
        self.set_position((start_pos + bytes_read) as u64);

        Ok(value)
    }
}
