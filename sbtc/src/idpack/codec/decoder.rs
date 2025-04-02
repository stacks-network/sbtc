//! Segment decoding implementation with compression-optimized routines.
//!
//! This module handles the decoding of compressed integer segments using
//! bitmap encoding optimized for specific data patterns. The decoder implements
//! several efficiency techniques:
//!
//! - **Delta-offset optimization**: Offsets are delta-encoded for space savings
//! - **LEB128 variable-length encoding**: Minimizes space for numeric values
//! - **Robust error handling**: Guards against malformed input without panicking
//!
//! ## Safety Considerations
//!
//! The decoder implements multiple safety checks to handle potentially
//! malicious inputs:
//!
//! - Validates allocation sizes to prevent excessive memory usage
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

use std::io::{Cursor, Read};

use crate::idpack::{Segment, Segments};
use crate::leb128::ReadLeb128;

use super::{Decodable, DecodeError};

/// Implements decoding from bytes into a collection of optimally encoded
/// segments.
///
/// Handles empty input gracefully by returning an empty segments collection.
/// For non-empty input, processes each segment sequentially with delta-offset
/// decoding between segments.
impl Decodable for Segments {
    /// Decodes a byte array into a Segments collection.
    ///
    /// This function processes the entire byte array sequentially, decoding
    /// each segment and ensuring proper semantic relationships between them.
    ///
    /// ## Parameters
    ///
    /// * `bytes` - A slice of the encoded bytes to decode
    ///
    /// ## Returns
    ///
    /// * `Ok(Segments)` - Successfully decoded segments
    /// * `Err(DecodeError)` - If any error occurs during decoding
    ///
    /// ## Implementation Notes
    /// - Returns empty segments for empty input (valid edge case)
    /// - Ensures complete consumption of input bytes
    /// - Maintains offset ordering constraints between segments
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut segments = Segments::default();

        if bytes.is_empty() {
            return Ok(segments);
        }

        let mut cursor = Cursor::new(bytes);

        let mut prev_max_value = 0; // Tracks previous segment's max value for delta decoding

        // Process segments until we've consumed all input bytes
        while cursor.position() < bytes.len() as u64 {
            // Read next segment with position-aware offset handling
            let segment = read_segment_into(&mut cursor, prev_max_value)?;

            // Update state for next segment
            prev_max_value = segment.max(); // Use max value for delta encoding
            segments.try_push(segment)?;
        }

        // Ensure we've consumed exactly the right amount of data
        if cursor.position() as usize != bytes.len() {
            return Err(DecodeError::UnexpectedEndOfData);
        }

        Ok(segments)
    }
}

/// Reads a single segment from the cursor with delta-offset optimization.
///
/// This function decodes a single segment from the current cursor position,
/// applying delta-offset decoding relative to the provided previous maximum
/// value. It handles the complete segment decoding process:
/// 1. Reading and decoding the offset value
/// 2. Reading the payload length and validating allocation size
/// 3. Reading and processing the bitmap payload
///
/// ## Parameters
/// * `cursor` - Mutable cursor positioned at the start of a segment
/// * `prev_max_value` - Previous segment's maximum value (0 for first segment)
///
/// ## Returns
/// * `Ok(Segment)` - Successfully decoded segment
/// * `Err(DecodeError)` - If any error occurs during decoding
///
/// ## Errors
/// * `ArithmeticOverflow` - If offset calculation would overflow
/// * `ByteAllocationLimit` - If payload length exceeds allocation limits
/// * `IO` - For any I/O errors during reading
/// * `Leb128Error` - For LEB128 decoding errors
pub fn read_segment_into(
    cursor: &mut Cursor<&[u8]>,
    prev_max_value: u64,
) -> Result<Segment, DecodeError> {
    // Read LEB128-encoded offset value
    let offset = cursor
        .read_leb128()?
        .checked_add(prev_max_value)
        .ok_or(DecodeError::ArithmeticOverflow)?;

    // Read the payload length
    let payload_length = cursor.read_leb128()?;

    // Safety check to prevent excessive allocation
    if payload_length > crate::idpack::ALLOC_BYTES_LIMIT as u64 {
        return Err(DecodeError::ByteAllocationLimit(payload_length));
    }

    // Read the payload bytes
    let mut payload_bytes = vec![0u8; payload_length as usize];
    cursor
        .read_exact(&mut payload_bytes)
        .map_err(DecodeError::IO)?;

    // Initialize segment with offset
    let mut segment = Segment::new_with_offset(offset);

    // Decode the bitmap payload into the segment
    decode_bitmap(offset, &payload_bytes, &mut segment)?;

    // Return the completed segment
    Ok(segment)
}

/// Decodes bitmap data into values and inserts them into a segment.
///
/// This function processes each bit in the bitmap to reconstruct the original
/// values:
/// 1. For each bit position that is set to 1 in the bitmap
/// 2. Calculate the corresponding value: offset + position + 1
/// 3. Insert the value into the segment
///
/// ## Parameters
/// * `offset` - Base value for the segment
/// * `bitmap` - Byte slice containing the bitmap data
/// * `segment` - Mutable reference to the segment for storing values
///
/// ## Returns
/// * `Ok(())` - If bitmap was successfully decoded
/// * `Err(DecodeError)` - If any error occurs during decoding
///
/// ## Errors
/// * `SegmentError` - If any validation error occurs while inserting values
///   into the segment
///
/// ## Implementation Notes
/// This function doesn't perform additional allocation beyond what's already
/// allocated in the segment. All integer calculations are performed using plain
/// addition which won't overflow given the constraints on offset and bitmap
/// size enforced by earlier validation.
fn decode_bitmap(offset: u64, bitmap: &[u8], segment: &mut Segment) -> Result<(), DecodeError> {
    // Process each bit in the bitmap to reconstruct original values.
    // 1. Iterate over each byte in the bitmap
    // 2. Iterate over each bit in the byte
    // 3. Calculate the value from the bit position and add it to the results.
    for (byte_idx, &byte) in bitmap.iter().enumerate() {
        for bit_idx in 0..8 {
            // Check if this bit is set
            if byte & (1 << bit_idx) != 0 {
                // Calculate position within the bitmap
                let position = byte_idx * 8 + bit_idx;

                // Convert bitmap position to value:
                // - Add offset (base of the segment)
                // - Add position + 1 (converting 0-based bit to 1-based value)
                let value = offset + (position as u64) + 1;
                segment.try_insert(value)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use crate::idpack::{Decodable, DecodeError, Segments};

    /// Test specific error cases with crafted invalid inputs
    #[test_case(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; "overflow in LEB128")]
    #[test_case(&[1, 0xFF, 0xFF, 0xFF, 0xFF]; "excessive allocation")]
    #[test_case(&[1, 1]; "incomplete segment - missing bitmap data")]
    #[test_case(&[1]; "incomplete segment - missing length")]
    #[test_case(&[]; "empty input")]
    fn test_specific_invalid_inputs(bytes: &[u8]) {
        // Empty input is actually valid and should produce empty segments
        if bytes.is_empty() {
            Segments::decode(bytes).expect("empty input should not fail");
            return;
        }

        // For all other cases, we expect either:
        // 1. A proper error (most likely)
        // 2. Successful decoding (if the invalid input happens to be valid)
        Segments::decode(bytes).expect_err("invalid input should fail decoding");
    }

    /// Test scenarios with valid first segment but invalid second segment
    #[test_case(
        &[10, 2, 0b00000011, 0xFF, 0xFF, 0xFF, 0xFF];
        "valid first segment + LEB128 overflow in second"
    )]
    #[test_case(
        &[10, 2, 0b00000011, 11, 0xFF, 0xFF];
        "valid first segment + excessive allocation in second"
    )]
    #[test_case(
        &[10, 2, 0b00000011, 11, 1];
        "valid first segment + truncated second segment"
    )]
    #[test_case(
        &[10, 1, 0b00000011, 11];
        "valid first segment + incomplete second segment (missing length)"
    )]
    fn test_partial_valid_data(bytes: &[u8]) {
        // Parse the first segment to verify it's valid
        let mut cursor = std::io::Cursor::new(bytes);
        super::read_segment_into(&mut cursor, 0).expect("first segment should be valid");

        // Attempting to decode the entire byte sequence should fail
        let full_result = Segments::decode(bytes);
        assert!(
            full_result.is_err(),
            "decoding full sequence with invalid second segment should fail, got: {full_result:?}"
        );
    }

    /// Test handling of valid first segment followed by garbage data
    #[test]
    fn test_valid_segment_with_trailing_garbage() {
        // Start with a valid segment (with 1-byte bitmap)
        let mut bytes = vec![10, 1, 0b00000011];

        // Append random garbage data that doesn't form a valid second segment
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Attempting to decode should fail with an appropriate error
        let result = Segments::decode(&bytes);
        assert!(
            result.is_err(),
            "decoding with trailing garbage should fail, got: {result:?}"
        );

        // We can also check that partial decoding works correctly
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let segment =
            super::read_segment_into(&mut cursor, 0).expect("should decode first valid segment");

        assert_eq!(segment.offset(), 10, "correct offset should be decoded");
        assert_eq!(
            segment.payload_values().len(),
            2,
            "correct number of values should be decoded"
        );
    }

    /// Test handling of multiple well-formed but semantically invalid segments
    #[test]
    fn test_multiple_invalid_segment_relationships() {
        // Create sequence with valid structure but invalid semantic relationships:
        // 1. First segment: [100, 110, 120]
        // 2. Second segment: [90, 95] (invalid: offset < previous max)
        // 3. Third segment: [150, 200] (valid relationship with second, but overall sequence invalid)

        let mut invalid_bytes = Vec::new();

        // First segment (valid)
        invalid_bytes.extend_from_slice(&[100, 3, 0b00000111]);

        // Second segment (invalid relationship with first)
        invalid_bytes.extend_from_slice(&[90, 2, 0b00000011]);

        // Third segment (valid relationship with second, but overall sequence invalid)
        invalid_bytes.extend_from_slice(&[55, 2, 0b00000011]);

        // Decoding should return an error
        Segments::decode(&invalid_bytes)
            .expect_err("multiple segment relationship violations should fail decoding");
    }

    /// Test handling of semantically invalid but structurally correct data
    #[test]
    fn test_semantically_invalid_data() {
        // Craft a payload with invalid segment relationships
        // This example creates segments where a later segment has an offset
        // smaller than a previous segment's max value

        // First segment: offset=100, values=[100, 110, 120]
        // Second segment: offset=50 (invalid - should be > 120)

        // This would be encoded as:
        // - First segment: offset=100 (absolute), length=3 bytes, bitmap=[...]
        // - Second segment: offset=50 (delta from 120 would be -70, which is invalid)

        // We'll manually construct this invalid encoding
        let mut invalid_bytes = Vec::new();

        // First segment (valid)
        invalid_bytes.extend_from_slice(&[100, 3, 0b00000111]); // Simple encoding

        // Second segment (invalid relationship)
        invalid_bytes.extend_from_slice(&[50, 2, 0b00000011]); // Invalid delta

        // Decoding should return an error
        Segments::decode(&invalid_bytes)
            .expect_err("semantically invalid data should fail decoding");
    }

    /// Test to verify overflow handling in segment offset calculation
    #[test]
    fn test_overflow_handling() {
        // Create a cursor with minimal content for offset delta, length, and bitmap
        let mut cursor = std::io::Cursor::new([2u8, 1, 0].as_slice());

        // Set previous max value just below u64::MAX
        let prev_max = u64::MAX - 1;

        // Attempt to decode a segment, which should fail with arithmetic overflow
        let result = super::read_segment_into(&mut cursor, prev_max);

        assert_matches!(
            result,
            Err(DecodeError::ArithmeticOverflow),
            "expected arithmetic overflow when offset calculation exceeds u64::MAX"
        );
    }
}
