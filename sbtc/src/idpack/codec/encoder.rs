//! Segment encoding implementation with efficient compression.

use crate::idpack::{Segment, Segments};
use crate::leb128::Leb128;

use super::Encodable;

/// Implementation of encoding for segment collections with delta-optimization.
///
/// Encodes multiple segments sequentially with optimizations:
/// - Delta-encoding offsets between adjacent segments
/// - Bitmap-based payload compression for efficient storage
impl Encodable for Segments {
    /// Encodes a collection of segments into a byte vector.
    ///
    /// ## Format
    /// Each segment is encoded as:
    /// 1. Segment offset (LEB128):
    ///    - For first segment: absolute offset
    ///    - For subsequent segments: delta from previous segment's maximum value
    /// 2. Payload length (LEB128): Number of bytes in the bitmap
    /// 3. Bitmap payload: Bits set where values exist
    ///
    /// ## Returns
    /// * `Vec<u8>` - Encoded byte vector, or empty vector if segments collection is empty
    fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Return empty bytes for empty segments
        if self.is_empty() {
            return result;
        }

        // Track the previous segment's max value for delta encoding of offsets.
        let mut last_segment_max_value = 0;

        for segment in self.iter() {
            // Calculate offset to encode: absolute for first segment, delta from
            // the previous segment's max value for subsequent segments. Helps to
            // reduce the encoded offset size when there are multiple segments.
            let actual_offset = segment.offset().saturating_sub(last_segment_max_value); // Delta encoding for savings

            // Encode segment using the bitmap encoder
            let mut payload_bytes = encode_bitmap(segment);

            // Write the segment offset, determined above
            Leb128::encode_into(actual_offset, &mut result);

            // Write the payload length header
            let payload_length = payload_bytes.len() as u64;
            Leb128::encode_into(payload_length, &mut result);

            // Append the encoded segment payload
            result.append(&mut payload_bytes);

            // Update the previous segment's max value for delta encoding
            last_segment_max_value = segment.max();
        }

        result
    }
}

/// Encodes a single segment using bitmap encoding.
///
/// This function creates a bitmap representation of the segment values, where:
/// - Each bit position corresponds to a value relative to the segment offset
/// - Bit at position N represents whether value (offset+N+1) exists in the segment
///
/// ## Parameters
/// * `segment` - Reference to the segment to encode
///
/// ## Returns
/// * `Vec<u8>` - Encoded bitmap bytes
///
/// ## Algorithm
/// 1. Calculate required bitmap size based on range of values
/// 2. Allocate zeroed buffer of appropriate size
/// 3. For each value in the segment:
///    a. Calculate its position relative to offset
///    b. Set the corresponding bit in the bitmap
fn encode_bitmap(segment: &Segment) -> Vec<u8> {
    // Calculate bitmap size requirements
    let range = segment.range();
    let bytes_needed = range.div_ceil(8);

    // Allocate bitmap array filled with zeros
    let mut bitmap = vec![0u8; bytes_needed as usize];

    // Populate the bitmap by setting bits for each value (excluding the
    // offset).
    for &value in segment.payload_values() {
        // Convert from value to bit position:
        // 1. Subtract offset to get relative position
        // 2. Subtract 1 more because bit 0 represents (offset+1)
        //
        // SAFETY: The following subtractions are safe because:
        // 1. The Segment type works explicitly with unsigned integers,
        // 2. and segment.values() returns values in the segment excluding the
        //    offset, hence all values from segment.values() are > offset and ≥ 0,
        //    guaranteed by the invariant of the Segment type,
        // 2. Therefore, the following is always ≥ 0:
        let relative_pos: u64 = value - segment.offset() - 1;

        // Calculate byte and bit index within the bitmap
        let byte_index = relative_pos / 8;
        let bit_index = relative_pos % 8;

        // Set the corresponding bit in the bitmap
        //
        // SAFETY: The index access is safe because:
        // 1. bytes_needed is calculated based on the range() of values in the
        //    segment, so byte_index is always in range [0, bytes_needed-1]
        // 2. And bitmap is sized exactly to bytes_needed
        //
        // SAFETY: The bit shift operation is safe because:
        // 1. bit_index = relative_pos % 8 is always in range [0, 7]
        // 2. Shifting by 0-7 bits is safe for u8 (which has 8 bits)
        bitmap[byte_index as usize] |= 1 << bit_index;
    }

    bitmap
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idpack::{Segment, Segments};
    use more_asserts::assert_le;
    use test_case::test_case;

    /// Test encoding of segments with various value patterns
    #[test_case(&[10], 0, &[10, 0]; "offset only")]
    #[test_case(&[10, 11, 12], 2, &[10, 1, 0b00000011]; "sequential values")]
    #[test_case(&[10, 11, 18], 8, &[10, 1, 0b10000001]; "sparse values")]
    #[test_case(&[10, 11, 18, 26], 16, &[10, 2, 0b10000001, 0b10000000]; "multiple bytes")]
    #[test_case(&[0, 8, 16, 24, 32], 32, &[0, 4, 0b10000000, 0b10000000, 0b10000000, 0b10000000]; "byte boundaries")]
    #[test_case(&[0, 255], 255, &[0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0b01000000]; "maximum first byte")]
    #[test_case(&[42], 0, &[42, 0]; "custom offset only")]
    fn test_segment_encoding(
        values: &[u64],
        expected_range: u64,
        expected_encoded: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create a segment from the test values
        let mut segment = Segment::new_with_offset(values[0]);
        for &value in &values[1..] {
            segment.try_insert(value)?;
        }

        // Verify the expected range calculation
        assert_eq!(
            segment.range(),
            expected_range,
            "segment range calculation should match expected"
        );

        // Create a segments collection and encode
        let mut segments = Segments::default();
        segments.try_push(segment.clone())?;
        let encoded = segments.encode();

        // Verify the encoded output matches expectations
        assert_eq!(
            encoded, expected_encoded,
            "encoded output should match expected bytes"
        );

        // Double-check bitmap encoding specifically
        if values.len() > 1 {
            let bitmap = encode_bitmap(&segment);

            // Verify bitmap contents
            for &value in segment.payload_values() {
                let relative_pos = value - segment.offset() - 1;
                let byte_index = (relative_pos / 8) as usize;
                let bit_index = (relative_pos % 8) as usize;

                assert_le!(
                    byte_index,
                    bitmap.len(),
                    "bitmap should have enough bytes for value {value}"
                );

                assert!(
                    (bitmap[byte_index] & (1 << bit_index)) != 0,
                    "expected bit set for value {value} at byte {byte_index} bit {bit_index}"
                );
            }
        }

        Ok(())
    }

    /// Test delta encoding between segments
    #[test_case(
        &[(10, &[11, 12]), (20, &[21, 22])],
        &[10, 1, 0b00000011, 8, 1, 0b00000011];
        "simple delta"
    )]
    #[test_case(
        &[(10, &[11, 12]), (100, &[101]), (200, &[201, 202, 203])],
        &[10, 1, 0b00000011, 88, 1, 0b00000001, 99, 1, 0b00000111];
        "multi segment delta"
    )]
    fn test_segments_delta_encoding(
        segment_specs: &[(u64, &[u64])],
        expected_encoded: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create segments with specified offsets and values
        let mut segments = Segments::default();

        for (offset, values) in segment_specs {
            let mut segment = Segment::new_with_offset(*offset);
            for &value in *values {
                segment.try_insert(value)?;
            }
            segments.try_push(segment)?;
        }

        // Encode the segments
        let encoded = segments.encode();

        // Verify against expected encoding
        assert_eq!(
            encoded, expected_encoded,
            "delta encoding should match expected bytes"
        );

        Ok(())
    }

    /// Test encoding of empty segments collection
    #[test]
    fn test_empty_segments() {
        let segments = Segments::default();
        let encoded = segments.encode();
        assert_eq!(
            encoded.len(),
            0,
            "empty segments should encode to empty bytes"
        );
    }
}
