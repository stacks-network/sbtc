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
//! - **Large Values**: Additional bytes only as needed (up to 10 bytes for u64)
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

/// Maximum number of bytes required to encode a u64 in LEB128 format.
/// For u64 (64 bits), we need at most 10 bytes because each byte provides 7 bits,
/// with 9 bytes covering 63 bits and the 10th byte providing the final bit.
const MAX_BYTES: usize = 10;

/// Number of value bits stored in each LEB128 byte.
/// LEB128 encoding uses 7 bits per byte for actual data, with the 8th bit
/// serving as a continuation flag.
const BITS_PER_BYTE: u32 = 7;

/// Bit mask to extract the lower 7 bits (value data) from a LEB128 byte.
/// Each byte uses bits 0-6 for data and bit 7 for continuation.
const LOWER_BITS_MASK: u8 = 0x7F;

/// Flag bit indicating that more bytes follow in the LEB128 sequence.
/// When this bit is set in a byte, it means the value continues in the next byte.
/// When clear, it indicates the final byte of the encoded sequence.
const CONTINUATION_FLAG: u8 = 0x80;

/// Represents the threshold where a value needs more than one byte in
/// Values from 0-127 (0x7F) fit in a single byte, while values ≥128 (0x80)
/// require multiple bytes. Used in calculation of encoded byte length without
/// performing actual encoding.
const MULTI_BYTE_THRESHOLD: u64 = 0x80;

/// Errors that can occur during LEB128 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The LEB128 sequence was incomplete (ended with continuation bit).
    #[error("incomplete LEB128 sequence")]
    IncompleteSequence,

    /// The LEB128 sequence had an invalid continuation pattern.
    #[error("invalid LEB128 continuation pattern")]
    InvalidContinuation,

    /// Attempted to decode from an empty input.
    #[error("empty input")]
    EmptyInput,

    /// Value exceeds 64 bits (u64 maximum).
    #[error("attempted to decode a value exceeding {} bits", u64::BITS)]
    ValueOutOfBounds,

    /// Attempted to access an index outside the bounds of the input.
    #[error("attempted to access an index outside the bounds of the input")]
    IndexOutOfBounds,

    /// Generic LEB128 decoding error (fallback).
    #[error("unexpected LEB128 decoding error")]
    UnexpectedDecodeError,
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
    pub fn encode_into(mut value: u64, bytes: &mut Vec<u8>) {
        loop {
            let mut byte = (value & LOWER_BITS_MASK as u64) as u8;
            // NOTE: this will never actually fail as we're only shifting by 7 bits
            // and `checked_shr` will only ever fail if the shift is >= the bit
            // width of the value (64 bits in this case).
            value = value.checked_shr(BITS_PER_BYTE).unwrap_or(0);

            if value != 0 {
                byte |= CONTINUATION_FLAG;
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
        let mut shift = 0;

        while position < bytes.len() {
            let byte = bytes[position];
            let value = (byte & LOWER_BITS_MASK) as u64;

            // Special handling for 10th byte (maximum for u64)
            if position == (MAX_BYTES - 1) {
                // Check for value out of bounds (bits 1-6 should be zero)
                if value > 0x01 {
                    return Err(Error::ValueOutOfBounds);
                }

                // Check for invalid continuation bit (should not be set in 10th byte)
                if (byte & CONTINUATION_FLAG) != 0 {
                    return Err(Error::InvalidContinuation);
                }
            }

            // Shift and add value to result
            // NOTE: this will never actually fail as we're only ever shifting by
            // BITS_PER_BYTE * (MAX_BYTES - 1) = 63 bits. We've also just checked
            // that the value is within bounds for the final byte.
            match value.checked_shl(shift) {
                Some(shifted) => result |= shifted,
                None => return Err(Error::ValueOutOfBounds),
            }

            position += 1;
            shift += BITS_PER_BYTE;

            // No continuation bit - we're done
            if byte & CONTINUATION_FLAG == 0 {
                return Ok((result, position));
            }

            if position == bytes.len() {
                return Err(Error::IncompleteSequence);
            }
        }

        // We shouldn't get here
        Err(Error::UnexpectedDecodeError)
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
    pub fn calculate_size(mut value: u64) -> usize {
        let mut size = 0;
        while value >= MULTI_BYTE_THRESHOLD {
            size += 1;
            value = value.checked_shr(BITS_PER_BYTE).unwrap_or(0);
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
        // Safely convert u64 position to usize, preventing truncation on 32-bit platforms
        let start_pos: usize = self
            .position()
            .try_into()
            .map_err(|_| Error::IndexOutOfBounds)?;

        let buffer = self.get_ref();

        // Are we at or past the end of the buffer?
        if start_pos >= buffer.len() {
            return Err(Error::IndexOutOfBounds);
        }

        // Get the remaining buffer from current position
        let remaining_buffer = &buffer[start_pos..];

        // Directly decode using try_decode which handles finding the end of the sequence
        let (value, bytes_read) = Leb128::try_decode(remaining_buffer)?;

        // Update cursor position
        self.set_position((start_pos + bytes_read) as u64);

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Tests precise byte patterns for specific values
    ///
    /// Documents the expected encoding format and verifies correct byte sequences
    /// for values of different magnitudes.
    #[test_case(300, &[172, 2], 2 ; "medium value")]
    #[test_case(127, &[127], 1 ; "small value")]
    #[test_case(0xFFFFFFFFFFFFFFFF, &[255, 255, 255, 255, 255, 255, 255, 255, 255, 1], 10 ; "large value")]
    fn test_leb128_encode(value: u64, expected_bytes: &[u8], expected_len: usize) {
        let mut bytes = Vec::new();
        Leb128::encode_into(value, &mut bytes);
        assert_eq!(bytes.as_slice(), expected_bytes);
        assert_eq!(bytes.len(), expected_len);
    }

    /// Tests decoding of specific byte patterns
    ///
    /// Verifies correct value extraction and byte consumption tracking.
    /// Includes error handling for empty inputs.
    #[test_case(&[172, 2] => Ok((300, 2)) ; "medium value")]
    #[test_case(&[127] => Ok((127, 1)) ; "small value")]
    #[test_case(&[255, 255, 255, 255, 255, 255, 255, 255, 255, 1] => Ok((0xFFFFFFFFFFFFFFFF, 10)) ; "large value")]
    #[test_case(&[] => Err(Error::EmptyInput) ; "empty input")]
    #[test_case(&[0x7F, 0x00] => Ok((127, 1)) ; "value with trailing bytes")]
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01] => Ok((u64::MAX, 10)); "exactly u64::MAX")]
    fn test_leb128_decode(bytes: &[u8]) -> Result<(u64, usize), Error> {
        Leb128::try_decode(bytes)
    }

    /// Tests boundary conditions and unique encoding patterns
    ///
    /// Verifies important edge cases that property tests might miss:
    /// - Multi-byte boundary values
    /// - Powers of two near byte transitions
    /// - Unusual bit patterns
    #[test_case(&[0x80, 0x80, 0x01] => Ok((16384, 3)) ; "three byte value")]
    #[test_case(&[0xFF, 0xFF, 0x03] => Ok((65535, 3)) ; "max two bytes as three")]
    #[test_case(&[0x80, 0x80, 0x80, 0x80, 0x10] => Ok((1 << 32, 5)) ; "five byte power of two")] // 4294967296
    #[test_case(&[0x80, 0x80, 0x80, 0x80, 0x20] => Ok((1 << 33, 5)) ; "five byte power of two plus one")] // 8589934592
    fn test_leb128_decode_edge_cases(bytes: &[u8]) -> Result<(u64, usize), Error> {
        Leb128::try_decode(bytes)
    }

    /// Tests error handling for malformed inputs
    ///
    /// Ensures robustness against truncated byte sequences and proper error
    /// response for invalid inputs.
    #[test_case(&[0x80] => Err(Error::IncompleteSequence); "incomplete byte sequence")]
    #[test_case(&[0x80, 0x80] => Err(Error::IncompleteSequence); "truncated multi-byte")]
    #[test_case(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xFF] => Err(Error::InvalidContinuation) ; "too many continuation bytes")]
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01] => Err(Error::ValueOutOfBounds) ; "exceeds u64 (11 bytes)")]
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01] => Err(Error::ValueOutOfBounds) ; "exceeds u64 (12 bytes)")]
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02] => Err(Error::ValueOutOfBounds); "exceeds u64 (bit 65 set)")]
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x81] => Err(Error::InvalidContinuation); "continuation at 10th byte")]
    fn test_leb128_decode_invalid(bytes: &[u8]) -> Result<(u64, usize), Error> {
        Leb128::try_decode(bytes)
    }

    /// Tests position advancement in cursor reading
    #[test]
    fn test_cursor_position_tracking() {
        // Create buffer with multiple LEB128 values
        let buffer = [
            0x01, // Value 1: small (1 byte)
            0x80, 0x01, // Value 2: medium (2 bytes)
            0xFF, 0x01, // Value 3: slightly larger (2 bytes)
            0x80,
        ];

        let mut cursor = Cursor::new(&buffer[..]);

        // Read first value
        let val1 = cursor.read_leb128().unwrap();
        assert_eq!(val1, 1);
        assert_eq!(cursor.position(), 1);

        // Read second value
        let val2 = cursor.read_leb128().unwrap();
        assert_eq!(val2, 128);
        assert_eq!(cursor.position(), 3);

        // Read third value
        let val3 = cursor.read_leb128().unwrap();
        assert_eq!(val3, 255);
        assert_eq!(cursor.position(), 5);

        // Attempt to read the last "garbage byte" (should error)
        match cursor.read_leb128() {
            Err(Error::IncompleteSequence) => {} // Expected
            other => panic!("expected IncompleteSequence error, got {:?}", other),
        }
        assert_eq!(cursor.position(), 5);
        cursor.set_position(cursor.position() + 1); // Skip past the invalid byte
        assert_eq!(cursor.position(), 6);
        // Attempt read at end (should error)
        match cursor.read_leb128() {
            Err(Error::IndexOutOfBounds) => {} // Expected
            other => panic!("expected IndexOutOfBounds error, got {:?}", other),
        }

        // Position should remain unchanged after error
        assert_eq!(cursor.position(), 6);
    }

    /// Tests read operations with extremely large position values
    #[test]
    fn test_large_cursor_positions() {
        // Test with position that requires careful handling to avoid overflow
        // We'll create a slice with one valid element at the end
        let buffer = [0x42]; // Single byte value
        let mut cursor = Cursor::new(&buffer[..]);

        // Test close to u32::MAX on 32-bit platforms and larger on 64-bit
        let large_but_valid_pos = (usize::MAX / 2) as u64;

        // This position exceeds buffer length, should return IndexOutOfBounds
        cursor.set_position(large_but_valid_pos);
        match cursor.read_leb128() {
            Err(Error::IndexOutOfBounds) => {} // Expected
            other => panic!("Expected IndexOutOfBounds error, got {:?}", other),
        }
    }

    #[test_case(0 => Ok(127); "zero")]
    #[test_case(1 => Err(Error::IndexOutOfBounds); "just past end")]
    #[test_case(u64::MAX - 10 => Err(Error::IndexOutOfBounds); "potential overflow")]
    fn test_safe_cursor_bounds_handling(pos: u64) -> Result<u64, Error> {
        let buffer = [0x7F]; // Single value (127)
        let mut cursor = Cursor::new(&buffer[..]);

        cursor.set_position(pos);
        cursor.read_leb128()
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Constants for proptest strategies
    const MAX_PROPTEST_ITERATIONS: u32 = 10000;

    // Value range constants for stratified testing. We use separate tests
    // for these ranges as proptest uses pseudo-random sampling and otherwise
    // may not get enough coverage for the different value ranges.
    const VALUE_MAX_1_BYTE: u64 = (1 << 7) - 1; // 127
    const VALUE_MAX_2_BYTES: u64 = (1 << 14) - 1; // 16,383
    const VALUE_MAX_3_BYTES: u64 = (1 << 21) - 1; // 2,097,151
    const VALUE_MAX_4_BYTES: u64 = (1 << 28) - 1; // 268,435,455
    const VALUE_MAX_5_BYTES: u64 = (1 << 35) - 1; // 34,359,738,367
    const VALUE_MAX_6_BYTES: u64 = (1 << 42) - 1; // 4,398,046,511,103
    const VALUE_MAX_7_BYTES: u64 = (1 << 49) - 1; // 562,949,953,421,311
    const VALUE_MAX_8_BYTES: u64 = (1 << 56) - 1; // 72,057,594,037,927,935
    const VALUE_MAX_9_BYTES: u64 = (1 << 63) - 1; // 9,223,372,036,854,775,807
    const VALUE_MAX_10_BYTES: u64 = u64::MAX; // 18,446,744,073,709,551,615

    /// Returns maximum value encodable in n bytes
    /// Used to identify size boundaries for encoding decisions
    const fn max_value_for_bytes(n: u32) -> u64 {
        if n >= 10 {
            // For 10 bytes (max u64), return u64::MAX
            return u64::MAX;
        }

        (1u64 << (BITS_PER_BYTE * n)) - 1
    }

    /// Helper function for property-based testing of LEB128 encoding
    ///
    /// Performs comprehensive validation of a single value:
    /// - Verifies the value encodes to exactly the expected number of bytes
    /// - Confirms that size calculation matches actual encoded size
    /// - Ensures perfect round-trip encoding/decoding
    ///
    /// This function is central to validating both the correctness and
    /// compression efficiency of the LEB128 implementation across the
    /// full range of possible values.
    ///
    /// ## Parameters
    /// * `value` - The integer value to test
    /// * `expected_len` - The expected encoded size in bytes
    fn test_value(value: u64, expected_len: usize) -> Result<(), TestCaseError> {
        let mut bytes = Vec::new();
        Leb128::encode_into(value, &mut bytes);

        prop_assert_eq!(
            bytes.len(),
            expected_len,
            "Value {} should encode to {} bytes",
            value,
            expected_len
        );
        prop_assert_eq!(Leb128::calculate_size(value), expected_len);

        let (decoded, read_byte_count) = Leb128::try_decode(&bytes).unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(read_byte_count, expected_len);

        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(MAX_PROPTEST_ITERATIONS))]

        /// Tests that 1-byte values round-trip correctly
        #[test]
        fn test_1_byte_values(value in 0..=VALUE_MAX_1_BYTE) {
            test_value(value, 1).unwrap();
        }

        /// Tests that 2-byte values round-trip correctly
        #[test]
        fn test_2_byte_values(value in (VALUE_MAX_1_BYTE+1)..=VALUE_MAX_2_BYTES) {
            test_value(value, 2).unwrap();
        }

        /// Tests that 3-byte values round-trip correctly
        #[test]
        fn test_3_byte_values(value in VALUE_MAX_2_BYTES+1..=VALUE_MAX_3_BYTES) {
            test_value(value, 3).unwrap();
        }

        /// Tests that 4-byte values round-trip correctly
        #[test]
        fn test_4_byte_values(value in VALUE_MAX_3_BYTES+1..=VALUE_MAX_4_BYTES) {
            test_value(value, 4).unwrap();
        }

        /// Tests that 5-byte values round-trip correctly
        #[test]
        fn test_5_byte_values(value in VALUE_MAX_4_BYTES+1..=VALUE_MAX_5_BYTES) {
            test_value(value, 5).unwrap();
        }

        /// Tests that 6-byte values round-trip correctly
        #[test]
        fn test_6_byte_values(value in VALUE_MAX_5_BYTES+1..=VALUE_MAX_6_BYTES) {
            test_value(value, 6).unwrap();
        }

        /// Tests that 7-byte values round-trip correctly
        #[test]
        fn test_7_byte_values(value in VALUE_MAX_6_BYTES+1..=VALUE_MAX_7_BYTES) {
            test_value(value, 7).unwrap();
        }

        /// Tests that 8-byte values round-trip correctly
        #[test]
        fn test_8_byte_values(value in VALUE_MAX_7_BYTES+1..=VALUE_MAX_8_BYTES) {
            test_value(value, 8).unwrap();
        }

        /// Tests that 9-byte values round-trip correctly
        #[test]
        fn test_9_byte_values(value in VALUE_MAX_8_BYTES+1..=VALUE_MAX_9_BYTES) {
            test_value(value, 9).unwrap();
        }

        /// Tests that 10-byte values round-trip correctly
        #[test]
        fn test_10_byte_values(value in VALUE_MAX_9_BYTES+1..=VALUE_MAX_10_BYTES) {
            test_value(value, 10).unwrap();
        }

        /// Tests bit-level encoding structure
        ///
        /// Verifies the internal structure of encoded values:
        /// - Correct continuation bit usage
        /// - Proper bit positioning in payload
        /// - Value reconstruction from encoded bytes
        #[test]
        fn test_bit_encoding_structure(value: u64) {
            let mut bytes = Vec::new();
            Leb128::encode_into(value, &mut bytes);

            // Encoding should never be empty, not even for 0.
            prop_assert!(!bytes.is_empty(), "encoding should not be empty");

            // Encoding size should never exceed 10 bytes (for u64 maximum)
            prop_assert!(bytes.len() <= 10,
                "encoding should be at most 10 bytes for u64");

            // Explicitly verify continuation bits. All bytes except the last
            // should have continuation bit set
            for &byte in bytes.iter().take(bytes.len() - 1) {
                prop_assert!(
                    byte & CONTINUATION_FLAG != 0,
                    "non-final byte missing continuation flag"
                );
            }
            // Last byte should not have continuation bit set
            prop_assert!(
                bytes.last().unwrap() & CONTINUATION_FLAG == 0,
                "final byte should not have continuation flag set"
            );

            // Reconstruct value manually to verify encoding integrity
            let mut reconstructed = 0u64;
            for (i, &byte) in bytes.iter().enumerate() {
                reconstructed |= ((byte & LOWER_BITS_MASK) as u64) << (i * 7);
            }

            prop_assert_eq!(reconstructed, value,
                "manual reconstruction from bytes failed");
        }

        /// Tests sequential reading of multiple values
        ///
        /// Validates cursor-based reading essential for decoding segments:
        /// - Position tracking between values
        /// - Sequential value extraction
        /// - Handling of heterogeneous value sizes
        #[test]
        fn test_cursor_reading(values in proptest::collection::vec(any::<u64>(), 1..100)) {
            let mut encoded = Vec::new();

            // Encode multiple values sequentially
            for &value in &values {
                Leb128::encode_into(value, &mut encoded);
            }

            // Read back using cursor
            let mut cursor = Cursor::new(encoded.as_slice());
            let mut decoded = Vec::new();

            while cursor.position() < encoded.len() as u64 {
                let value = cursor.read_leb128().unwrap();
                decoded.push(value);
            }

            // Verify all values were decoded correctly
            prop_assert_eq!(values, decoded);
            prop_assert_eq!(cursor.position(), encoded.len() as u64);
        }

        /// Tests encoding at byte size transitions
        ///
        /// Verifies correct byte count at each size boundary:
        /// - Maximum values for each byte count
        /// - Minimum values requiring additional bytes
        /// - Consistent encoding across all boundaries
        #[test]
        fn test_all_compression_boundaries(bytes in 1u32..=MAX_BYTES as u32) {
            // Get boundary values
            let max_value = max_value_for_bytes(bytes);

            // Test maximum value for this byte size
            let mut encoded = Vec::new();
            Leb128::encode_into(max_value, &mut encoded);
            prop_assert_eq!(encoded.len(), bytes as usize);

            // Test minimum value requiring next byte size
            if (bytes as usize) < MAX_BYTES {
                let min_next_value = max_value + 1;
                let mut encoded = Vec::new();
                Leb128::encode_into(min_next_value, &mut encoded);
                prop_assert_eq!(encoded.len(), bytes as usize + 1);
            }
        }
    }
}
