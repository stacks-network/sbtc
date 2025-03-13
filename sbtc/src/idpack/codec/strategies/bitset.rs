//! # BitSet Encoding Strategy
//!
//! The BitSet encoding strategy compresses integer sequences by representing values as
//! individual bits in a compact bitmap. This strategy achieves maximum compression for
//! dense sets of values within a limited range.
//!
//! ## How It Works
//!
//! Each value in the segment is represented by setting a bit at the corresponding position
//! in a bitmap, where:
//!
//! * Position is calculated as `(value - offset - 1)`
//! * Offset is stored once as the segment's base value
//! * Only the range from `offset+1` to `offset+range` needs representation
//!
//! ## Optimizations
//!
//! ### 1. Embedded Length (≤56 bits)
//!
//! For small-to-medium ranges (≤56 bits), the bitmap length is stored in the flags byte,
//! saving 1 byte compared to explicit length encoding.
//!
//! ### 2. Dense Value Compression
//!
//! BitSet encoding shines when segments contain dense clusters of values, as each value
//! requires only a single bit regardless of its magnitude. This makes it highly efficient
//! for sequences with many consecutive or closely spaced values.
//!
//! ## When To Use
//!
//! BitSet encoding is most efficient for:
//!
//! * Dense sequences where most values in a range are present
//! * Small ranges that benefit from embedded bitmap optimization
//! * Sequences with predictable, evenly-spaced values
//! * Segments where range is significantly smaller than maximum value

use std::io::{Cursor, Read};

use crate::idpack::codec::VALUE_COUNT_LIMIT;
use crate::idpack::ALLOC_BYTES_LIMIT;
use crate::idpack::{codec, Segment, SegmentEncoding};
use crate::leb128::ReadLeb128;
use crate::Leb128;

use super::EncodingStrategy;
use super::SegmentDecodeError;
use super::SegmentEncodeError;

/// Flag bit indicating that the bitmap length is embedded in the flags byte.
/// When set, the bitmap length is encoded in bits 4-6 of the flags byte.
const EMBEDDED_LENGTH_FLAG: u8 = codec::ENCODING_FLAG_2;

/// Mask for extracting the embedded bitmap length from the flags byte (bits 4-6).
/// The embedded length can represent bitmap sizes from 0-7 bytes.
const EMBEDDED_LENGTH_MASK: u8 =
    codec::ENCODING_FLAG_3 | codec::ENCODING_FLAG_4 | codec::ENCODING_FLAG_5;

/// Shift amount for positioning the bitmap length bits in the flags byte.
const EMBEDDED_LENGTH_SHIFT: u8 = 4;

/// Implements the BitSet encoding strategy, which compresses integer values by
/// representing them as bits in a bitmap.
pub struct BitsetStrategy;

impl EncodingStrategy for BitsetStrategy {
    /// Returns the type flag indicating BitSet encoding.
    fn type_flag(&self) -> u8 {
        codec::TYPE_BITSET
    }

    /// Creates flags for the segment based on its characteristics.
    ///
    /// The flag creation applies optimizations in descending priority:
    /// 1. Small ranges (≤56 bits): Embeds the bitmap length in the flags for
    ///    1-byte savings
    /// 2. Larger ranges: Encodes length explicitly for maximum compatibility
    ///
    /// ## Parameters
    /// * `segment` - The segment to create flags for
    ///
    /// ## Returns
    /// The flags byte with appropriate bits set.
    fn create_flags(&self, segment: &Segment) -> u8 {
        let mut flags = 0;

        // Calculate range and byte requirements for the bitmap
        // Note: We don't add 1 to range because range is inclusive of offset,
        // and we shift values by (offset + 1) during encoding.
        let bits_needed = segment.range();
        let bytes_needed = bits_needed.div_ceil(8);

        // Optimization 1: For small-to-medium bitmaps (1-7 bytes), embed length in flags
        // This saves 1 byte compared to explicit length encoding.
        if bytes_needed <= 7 {
            flags |= EMBEDDED_LENGTH_FLAG;
            flags |= ((bytes_needed as u8) << EMBEDDED_LENGTH_SHIFT) & EMBEDDED_LENGTH_MASK;
        }

        // Note: For larger bitmaps (>7 bytes), we use explicit length encoding.
        // This is indicated by BITSET_FLAG_EMBED_LENGTH not being set.

        flags
    }

    /// Returns the encoding type for this strategy.
    fn encoding_type(&self) -> SegmentEncoding {
        SegmentEncoding::Bitset
    }

    /// Estimates the encoded size in bytes for the given segment.
    ///
    /// The calculation includes:
    /// - Bitmap bytes based on segment range for larger ranges
    /// - Extra length byte for bitmaps > 7 bytes
    ///
    /// ## Parameters
    /// * `segment` - The segment to estimate size for
    ///
    /// ## Returns
    /// The estimated encoded size in bytes
    fn estimate_payload_size(&self, values: &[u64]) -> Option<usize> {
        if values.is_empty() {
            return None;
        }

        // We expect values to be sorted, so min and max are at the ends.
        // We just ensured the values are non-empty, so this is safe.
        let min_value = values[0];
        let max_value = values[values.len() - 1];

        // Calculate bitmap size requirements
        let range = max_value - min_value;
        let bytes_needed = range.div_ceil(8) as usize;

        // Safety check to prevent OOM for extremely sparse data
        if bytes_needed > ALLOC_BYTES_LIMIT as usize {
            return None;
        }

        // For bitmaps > 7 bytes, we need an explicit length byte
        Some(bytes_needed + (bytes_needed > 7) as usize)
    }

    /// Encodes a segment using the BitSet strategy.
    ///
    /// The encoding process uses one of two approaches for maximum
    /// compression:
    /// 1. Embedded length: For small bitmaps (≤7 bytes), the bitmap length is
    ///    embedded in the flags byte to save 1 byte
    /// 2. Standard bitmap: For larger ranges, an explicit length byte plus the
    ///    minimum number of bitmap bytes needed
    ///
    /// Values are encoded as bits relative to the segment's offset, with
    /// position 0 representing (offset+1).
    ///
    /// ## Parameters
    /// * `flags` - The encoding flags
    /// * `segment` - The segment to encode
    /// * `result` - Vector to append encoded bytes to
    ///
    /// ## Returns
    /// Ok(()) on success, or an error if encoding fails
    fn encode(
        &self,
        flags: u8,
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // Calculate bitmap size requirements.
        let range = segment.range();
        let bytes_needed = range.div_ceil(8);

        // Safety check to prevent OOM for extremely sparse data
        if bytes_needed > ALLOC_BYTES_LIMIT as u64 {
            return Err(SegmentEncodeError::ByteAllocationLimit(bytes_needed));
        }

        // Safety check to prevent OOM for extremely large bitmaps
        let value_count = segment.len() as u64;
        if value_count > VALUE_COUNT_LIMIT as u64 {
            return Err(SegmentEncodeError::TooManyValues(value_count));
        }

        // Allocate bitmap array filled with zeros.
        let mut bitmap = vec![0u8; bytes_needed as usize];

        // Populate the bitmap by setting bits for each value (excluding the
        // offset).
        for &value in segment.values() {
            // Convert from value to bit position:
            // 1. Subtract offset to get relative position
            // 2. Subtract 1 more because bit 0 represents (offset+1)
            let relative_pos = value - segment.offset() - 1;

            // Calculate byte and bit index within the bitmap
            let byte_index = relative_pos / 8;
            let bit_index = relative_pos % 8;

            // Set the corresponding bit in the bitmap
            bitmap[byte_index as usize] |= 1 << bit_index;
        }

        // Optimization 1: Check if length is embedded in flags
        let has_embed_length = flags & EMBEDDED_LENGTH_FLAG != 0;

        // Write explicit length only when not embedded in flags
        // This saves 1 byte for small-to-medium bitmaps
        if !has_embed_length {
            Leb128::encode_into(bytes_needed, result);
        }

        // Write the bitmap bytes to the result
        result.extend_from_slice(&bitmap);

        Ok(())
    }

    /// Decodes a BitSet-encoded segment.
    ///
    /// The decoding process:
    /// 1. Extracts the bitmap length from flags or reads it explicitly
    /// 2. Reads the bitmap bytes
    /// 3. Processes each bit, converting set bits to values
    /// 4. Adjusts values by adding (offset+1)
    ///
    /// ## Parameters
    /// * `cursor` - Cursor positioned at the start of encoded data
    /// * `flags` - The encoding flags
    /// * `offset` - The segment's offset value
    /// * `values` - Vector to append decoded values to
    ///
    /// ## Returns
    /// Ok(()) on success, or an error if decoding fails
    fn decode(
        &self,
        cursor: &mut Cursor<&[u8]>,
        flags: u8,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        // For larger bitmaps, first determine the bitmap length

        // Optimization 1: Check if length is embedded in flags
        let has_embed_length = flags & EMBEDDED_LENGTH_FLAG != 0;

        // Extract bitmap length either from flags or explicit LEB128 value
        let bitmap_len = if has_embed_length {
            // Extract bits 4-6 which contain length in bytes (0-7)
            ((flags & EMBEDDED_LENGTH_MASK) >> EMBEDDED_LENGTH_SHIFT) as u64
        } else {
            // Read explicit length as LEB128 encoded value
            cursor.read_leb128()?
        };

        if bitmap_len > VALUE_COUNT_LIMIT as u64 {
            return Err(SegmentDecodeError::TooManyValues(bitmap_len));
        }

        // Read the actual bitmap bytes
        let mut bitmap = vec![0u8; bitmap_len as usize];
        cursor.read_exact(&mut bitmap)?;

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
                    values.push(value);
                }
            }
        }

        Ok(())
    }
}
