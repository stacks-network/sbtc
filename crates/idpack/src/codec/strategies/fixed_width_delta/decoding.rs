//! Decoding implementation for the Fixed-Width Delta encoding strategy.
//!
//! This module provides specialized decoding routines for the Fixed-Width Delta
//! compression strategy, which stores values as deltas using minimum bit width.
//! The implementation includes several optimizations:
//!
//! - Adaptive bit width selection based on value patterns
//! - Special handling for sequential values (delta=1) with zero bit width
//! - Tiny sequence optimization for segments with exactly two values
//! - Embedded bit width for small bit widths to save header bytes
//! - Bit-level packing that crosses byte boundaries for maximum compression

use std::io::{Cursor, Read};

use crate::{
    codec::{arithmetic::CheckedArithmetic, SegmentDecodeError, VALUE_COUNT_LIMIT},
    leb128::ReadLeb128,
    ALLOC_BYTES_LIMIT,
};

use super::{
    bit_buffer::BitBuffer, types::DecodingFormat, FixedWidthDeltaStrategy, DELTA_ADJUSTMENT,
    EXTREME_BIT_WIDTH_THRESHOLD, MAX_BIT_WIDTH,
};

/// Decoding methods for the Fixed-Width Delta strategy.
impl FixedWidthDeltaStrategy {
    /// Selects and executes the optimal decoding method based on format flags.
    ///
    /// Analyzes the encoding flags to determine which specialized decoding path
    /// should be used, matching the compression optimizations applied during
    /// encoding:
    /// - Tiny sequence (exactly 2 values)
    /// - Embedded bit width (bit width encoded in flags)
    /// - Explicit bit width (bit width follows flags)
    ///
    /// ## Parameters
    /// * `cursor` - Data source for reading encoded values
    /// * `flags` - Format flags that determine encoding optimizations
    /// * `offset` - The first value in the sequence
    /// * `values` - Destination vector for decoded values
    ///
    /// ## Returns
    /// `Ok(())` on success, or appropriate error if decoding fails
    pub fn decode_values(
        cursor: &mut Cursor<&[u8]>,
        flags: u8,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        // Extract flags
        let format = DecodingFormat::from_flags(flags);

        // Choose decoding method based on format
        match format {
            DecodingFormat::Tiny => Self::decode_tiny_sequence(cursor, offset, values),
            DecodingFormat::EmbeddedWidth(bit_width) => {
                Self::decode_bit_packed_values(cursor, bit_width, offset, values)
            }
            DecodingFormat::ExplicitWidth => {
                // Read explicit bit width
                let mut bit_width_buf = [0u8; 1];
                cursor
                    .read_exact(&mut bit_width_buf)
                    .map_err(SegmentDecodeError::IO)?;
                Self::decode_bit_packed_values(cursor, bit_width_buf[0], offset, values)
            }
        }
    }

    /// Decodes a tiny sequence (exactly 2 values) from the encoded data.
    ///
    /// For tiny sequences, only a delta value is stored using variable-length
    /// LEB128. This achieves maximum compression for pairs of values by
    /// eliminating bit width and count fields.
    ///
    /// ## Parameters
    /// * `cursor` - Cursor positioned at the encoded delta
    /// * `offset` - The segment's offset value (first value)
    /// * `values` - Vector to append decoded values to
    ///
    /// ## Returns
    /// `Ok(())` on success, or an error if decoding fails
    fn decode_tiny_sequence(
        cursor: &mut Cursor<&[u8]>,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        // Read the LEB128-encoded delta
        let delta = cursor.read_leb128()?;

        // Calculate and add the second value (offset is already in values)
        let next_value = Self::delta_to_value(offset, delta)?;
        values.push(next_value);

        Ok(())
    }

    /// Decodes bit-packed values with automatic format selection.
    ///
    /// This method dispatches to specialized decoders based on bit width,
    /// applying the optimal decoding approach for maximum compression:
    /// - Zero bit width: Sequential values (consecutive integers)
    /// - Normal bit widths: Bit buffer for efficient cross-byte decoding
    /// - Extreme bit widths: Direct byte-aligned approach for large values
    ///
    /// ## Parameters
    /// * `cursor` - Source of encoded data
    /// * `bit_width` - Number of bits used per delta value
    /// * `offset` - First value in the sequence
    /// * `values` - Output vector for decoded values
    ///
    /// ## Returns
    /// `Ok(())` on success, or appropriate error if decoding fails
    fn decode_bit_packed_values(
        cursor: &mut Cursor<&[u8]>,
        bit_width: u8,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        if bit_width > MAX_BIT_WIDTH {
            return Err(SegmentDecodeError::InvalidBitWidth(bit_width));
        }

        // Read value count
        let count = cursor.read_leb128()?;
        if count == 0 {
            return Err(SegmentDecodeError::InvalidValueCount(0));
        }
        if count > VALUE_COUNT_LIMIT as u64 {
            return Err(SegmentDecodeError::ValueCountLimitExceeded(count));
        }

        // Reserve capacity for values to avoid reallocations
        values.reserve(count as usize);

        // Handle different decoding paths based on bit width category for maximum compression
        match bit_width {
            0 => Self::decode_sequential_values(count, offset, values),
            width if width >= EXTREME_BIT_WIDTH_THRESHOLD => {
                Self::decode_extreme_bit_width_values(cursor, width, count, offset, values)
            }
            _ => Self::decode_normal_bit_width_values(cursor, bit_width, count, offset, values),
        }
    }

    /// Ultra-efficient decoding for sequences of consecutive integers.
    ///
    /// This special case achieves maximum compression for sequential values by
    /// eliminating all delta payload bytes. The encoded format simply stores
    /// the count, and the decoder generates values by incrementing from the
    /// offset.
    ///
    /// ## Parameters
    /// * `count` - Number of sequential values to generate
    /// * `offset` - Starting value (first value already in the values vector)
    /// * `values` - Destination for decoded sequential values
    ///
    /// ## Returns
    /// `Ok(())` on success
    fn decode_sequential_values(
        count: u64,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        for _ in 0..count {
            let prev_value = values.last().copied().unwrap_or(offset);
            values.push(prev_value + 1);
        }
        Ok(())
    }

    /// Decodes values using the bit buffer approach for standard bit widths.
    ///
    /// This method unpacks values that were encoded with bit-level packing,
    /// providing maximum compression by using the exact minimum number of bits
    /// required per delta, even across byte boundaries.
    ///
    /// ## Parameters
    /// * `cursor` - Source of packed bit data
    /// * `bit_width` - Number of bits per delta value
    /// * `count` - Number of values to decode
    /// * `offset` - First value in the sequence
    /// * `values` - Destination for decoded values
    ///
    /// ## Returns
    /// `Ok(())` on success, or error if decoding fails
    fn decode_normal_bit_width_values(
        cursor: &mut Cursor<&[u8]>,
        bit_width: u8,
        count: u64,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        let mut bit_buffer = BitBuffer::new();
        let mut prev_value = offset;

        for _ in 0..count {
            // Fill buffer until we have enough bits
            Self::fill_bit_buffer(&mut bit_buffer, cursor, bit_width)?;

            // Extract delta and calculate next value
            let delta = bit_buffer.extract(bit_width);
            let next_value = Self::delta_to_value(prev_value, delta)?;

            values.push(next_value);
            prev_value = next_value;
        }

        Ok(())
    }

    /// Specialized decoding for values with large bit widths.
    ///
    /// For extremely large deltas, this method uses a byte-aligned approach
    /// rather than the bit buffer to ensure precision and performance.
    /// This mirrors the encoding approach for consistent handling.
    ///
    /// ## Parameters
    /// * `cursor` - Source of encoded data
    /// * `bit_width` - Number of bits per delta (32-64)
    /// * `count` - Number of values to decode
    /// * `offset` - First value in the sequence
    /// * `values` - Destination for decoded values
    ///
    /// ## Returns
    /// `Ok(())` on success, or error if decoding fails
    fn decode_extreme_bit_width_values(
        cursor: &mut Cursor<&[u8]>,
        bit_width: u8,
        count: u64,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        if bit_width > MAX_BIT_WIDTH {
            return Err(SegmentDecodeError::InvalidBitWidth(bit_width));
        }

        let mut prev_value = offset;
        let bytes_needed = (bit_width as u64 + 7) / 8;

        // Calculate the total bytes needed for all values based on the value
        // count and bit width, ensuring we don't exceed the allocation limit.
        let total_bytes = bytes_needed
            .checked_mul(count)
            .ok_or(SegmentDecodeError::IntegerOverflow)?;

        // Check that the total bytes needed does not exceed the allocation limit.
        if total_bytes > ALLOC_BYTES_LIMIT as u64 {
            return Err(SegmentDecodeError::AllocationLimitExceeded(total_bytes));
        }

        for _ in 0..count {
            // Read the delta bytes directly, matching the encoding approach
            let mut delta = 0u64;
            for i in 0..bytes_needed {
                let mut byte = [0u8; 1];
                if cursor.read_exact(&mut byte).is_err() {
                    return Err(SegmentDecodeError::UnexpectedEndOfData);
                }
                delta |= (byte[0] as u64) << (i * 8);
            }

            // Convert delta to value and store
            let next_value = Self::delta_to_value(prev_value, delta)?;
            values.push(next_value);
            prev_value = next_value;
        }

        Ok(())
    }

    /// Ensures the bit buffer contains enough bits for extraction operations.
    ///
    /// This helper method reads bytes from the cursor and fills the bit buffer
    /// until it has at least the requested number of bits available. This is
    /// critical for correctly handling bit-level extraction across byte
    /// boundaries.
    ///
    /// ## Parameters
    /// * `bit_buffer` - Buffer to fill with bits
    /// * `cursor` - Source of encoded data
    /// * `bits_needed` - Minimum number of bits required
    ///
    /// ## Returns
    /// `Ok(())` on success, or error if unexpected end of data
    fn fill_bit_buffer(
        bit_buffer: &mut BitBuffer,
        cursor: &mut Cursor<&[u8]>,
        bits_needed: u8,
    ) -> Result<(), SegmentDecodeError> {
        while bit_buffer.bits_available < bits_needed as u32 {
            let mut byte_buf = [0u8; 1];
            if cursor.read_exact(&mut byte_buf).is_err() {
                return Err(SegmentDecodeError::UnexpectedEndOfData);
            }
            bit_buffer.buffer |= (byte_buf[0] as u64) << bit_buffer.bits_available;
            bit_buffer.bits_available += 8;
        }
        Ok(())
    }

    /// Reconstructs an absolute value from an encoded delta with adjustment.
    ///
    /// Converts a delta back to its absolute value, applying the delta adjustment
    /// and handling special cases for sequential values. Includes precise
    /// overflow checking to ensure integrity of decoded values.
    ///
    /// ## Parameters
    /// * `prev_value` - The previous absolute value
    /// * `delta` - The encoded delta value
    ///
    /// ## Returns
    /// The decoded absolute value, or error if arithmetic overflow
    fn delta_to_value(prev_value: u64, delta: u64) -> Result<u64, SegmentDecodeError> {
        if delta == 0 {
            // Special case for consecutive values (minimum delta)
            prev_value.checked_op("adjustment", || prev_value.checked_add(DELTA_ADJUSTMENT))
        } else {
            // Standard delta reconstruction with adjustment
            prev_value
                .checked_op("delta", || prev_value.checked_add(delta))?
                .checked_op("adjustment", || {
                    prev_value.checked_add(delta + DELTA_ADJUSTMENT)
                })
        }
    }
}
