//! Fixed-Width Delta encoding implementation for maximum compression.
//!
//! This module provides specialized encoding methods that optimize integer
//! sequences by storing deltas between values with the minimum required bit
//! width. The implementation includes several compression optimizations:
//!
//! - Tiny sequence optimization for segments with exactly two values
//! - Sequential value optimization for consecutive integers (0-bit width)
//! - Embedded bit width for small values to eliminate header bytes
//! - Bit-level packing across byte boundaries for dense storage
//! - Specialized extreme value handling for large deltas

use crate::{codec::SegmentEncodeError, leb128::Leb128, Segment};

use super::{bit_buffer::BitBuffer, types::BitWidth, FixedWidthDeltaStrategy};

/// Encoding methods for the Fixed-Width Delta strategy.
impl FixedWidthDeltaStrategy {
    /// Encodes a value sequence using the optimal specialized method for
    /// maximum compression.
    ///
    /// This is the main entry point that analyzes the segment and selects the
    /// most space-efficient encoding approach from five specialized methods:
    /// - Tiny sequence (2 values): Ultra-compact, no bit width or count bytes
    /// - Sequential (consecutive integers): Zero-bit payload optimization
    /// - Embedded bit width: Bit width stored in flags byte to save 1 byte
    /// - Normal bit width: Standard bit-packed encoding
    /// - Extreme bit width: Byte-aligned encoding for large deltas
    ///
    /// ## Parameters
    /// * `segment` - The segment to encode
    /// * `result` - Vector to append encoded bytes to
    ///
    /// ## Returns
    /// `Ok(())` on success, or an error if encoding fails
    pub fn encode_value_sequence(
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // Determine optimal bit width representation
        let bit_width = Self::determine_optimal_bit_width(segment);

        // Choose encoding method based on the bit width type
        match bit_width {
            BitWidth::Tiny => Self::encode_tiny_sequence(segment, result),
            BitWidth::Sequential => {
                // Sequential values (bit width 0)
                // Write count (no bit width needed when embedded in flags)
                Leb128::encode_into(segment.value_count() as u64, result);
                Ok(())
            }
            BitWidth::Embedded(width) => {
                // Write count (bit width is embedded in flags)
                Leb128::encode_into(segment.value_count() as u64, result);
                Self::encode_bit_packed_normal(segment, width, result)
            }
            BitWidth::Normal(width) => {
                // Write explicit bit width
                result.push(width);
                // Write count
                Leb128::encode_into(segment.value_count() as u64, result);
                Self::encode_bit_packed_normal(segment, width, result)
            }
            BitWidth::Extreme(width) => {
                // Write explicit bit width
                result.push(width);
                // Write count
                Leb128::encode_into(segment.value_count() as u64, result);
                Self::encode_bit_packed_extreme(segment, width, result)
            }
        }
    }

    /// Encodes a tiny sequence (exactly 2 values) with ultra-compact
    /// representation.
    ///
    /// This optimization eliminates bit width and count bytes, storing only the
    /// delta between two values using variable-length LEB128 encoding. This
    /// achieves maximum compression for pairs of values, a common case in many
    /// datasets.
    ///
    /// ## Parameters
    /// * `segment` - The segment containing exactly 2 values
    /// * `result` - Vector to append encoded bytes to
    ///
    /// ## Returns
    /// `Ok(())` on success, or an error if encoding fails
    pub fn encode_tiny_sequence(
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        let values = segment.values();
        let delta = Self::calculate_delta(values[0], segment.offset());
        Leb128::encode_into(delta, result);
        Ok(())
    }

    /// Encodes values using bit-level packing for normal bit widths.
    ///
    /// This method packs delta values using exactly the minimum number of bits
    /// required, even across byte boundaries. This achieves maximum compression
    /// by eliminating wasted bits from traditional byte-aligned approaches.
    ///
    /// # Parameters
    /// * `segment` - The segment to encode
    /// * `bit_width` - Number of bits to use per delta value
    /// * `result` - Vector to append encoded bytes to
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if encoding fails
    pub fn encode_bit_packed_normal(
        segment: &Segment,
        bit_width: u8,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // Estimate bytes needed and preallocate for performance
        let total_bits = bit_width as usize * segment.value_count();
        let bytes_needed = (total_bits + 7) / 8;
        result.reserve(bytes_needed);

        // Create bit buffer for precise bit-level packing
        let mut bit_buffer = BitBuffer::new();
        let mut prev = segment.offset();

        // Process each value, packing deltas at the bit level
        for &value in segment.values() {
            // Calculate delta and pack into bit buffer
            let delta = Self::calculate_delta(value, prev);
            bit_buffer.append(delta, bit_width);

            // Flush complete bytes to minimize memory usage
            result.extend(bit_buffer.flush_bytes());
            prev = value;
        }

        // Handle any remaining bits to ensure no data is lost
        if let Some(byte) = bit_buffer.remaining_byte() {
            result.push(byte);
        }

        Ok(())
    }

    /// Specialized encoder for extremely large bit widths.
    ///
    /// For deltas requiring more than 32 bits, this method uses byte-aligned
    /// encoding to maintain precision and avoid potential overflow issues.
    /// While slightly less space-efficient than bit packing, it ensures
    /// correctness for extreme values approaching u64::MAX.
    ///
    /// # Parameters
    /// * `segment` - The segment containing large delta values
    /// * `bit_width` - Number of bits required per delta (32-64)
    /// * `result` - Vector to append encoded bytes to
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if encoding fails
    fn encode_bit_packed_extreme(
        segment: &Segment,
        bit_width: u8,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // For extreme bit widths, use byte-by-byte encoding to maintain precision
        let mut prev = segment.offset();

        for &value in segment.values() {
            let delta = Self::calculate_delta(value, prev);

            // Write delta as a sequence of bytes, preserving exact bit patterns
            // This ensures no precision is lost even for values near u64::MAX
            for i in 0..8 {
                // Only write as many bytes as needed based on bit width
                if i * 8 < bit_width as usize {
                    let byte = ((delta >> (i * 8)) & 0xFF) as u8;
                    result.push(byte);
                }
            }

            prev = value;
        }

        Ok(())
    }
}
