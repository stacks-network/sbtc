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
//! ### 1. Embedded Bitmap (≤4 bits)
//!
//! For tiny ranges (≤4 bits), the entire bitmap is stored directly in the flags byte,
//! requiring zero additional bytes. This enables ultra-compact encoding for common
//! small-range patterns.
//!
//! ### 2. Embedded Length (≤56 bits)
//!
//! For small-to-medium ranges (≤56 bits), the bitmap length is stored in the flags byte,
//! saving 1 byte compared to explicit length encoding.
//!
//! ### 3. Dense Value Compression
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

use crate::codec;
use crate::codec::SegmentDecodeError;
use crate::codec::SegmentEncodeError;
use crate::codec::VALUE_COUNT_LIMIT;
use crate::leb128::Leb128;
use crate::leb128::ReadLeb128;
use crate::segment::Segment;
use crate::SegmentEncoding;
use std::io::{Cursor, Read};

use super::EncodingStrategy;

/// Flag indicating bitmap is directly embedded in flag byte
/// When set, no additional bytes are written and the bitmap is stored in bits 3-6
const EMBEDDED_BITMAP_FLAG: u8 = codec::ENCODING_FLAG_1; // Bit 2
/// Mask for extracting embedded bitmap bits (bits 3-6)
/// This provides a zero-byte optimization for tiny ranges (≤4 bits)
const EMBEDDED_BITMAP_MASK: u8 = codec::ENCODING_FLAG_2
    | codec::ENCODING_FLAG_3
    | codec::ENCODING_FLAG_4
    | codec::ENCODING_FLAG_5;
/// Shift amount for positioning embedded bitmap bits
const EMBEDDED_BITMAP_SHIFT: u8 = 3;
/// Number of bits available for embedded bitmap
const EMBEDDED_BITMAP_NUM_BITS: u8 = 4;

/// Flag bit indicating that the bitmap length is embedded in the flags byte.
/// When set, the bitmap length is encoded in bits 4-6 of the flags byte.
/// This flag is **not** compatible with [`BITSET_FLAG_EMBED_BITMAP`].
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
    /// 1. Tiny ranges (≤4 bits): Uses embedded bitmap in flags for zero-byte
    ///    encoding
    /// 2. Small ranges (≤56 bits): Embeds the bitmap length in the flags for
    ///    1-byte savings
    /// 3. Larger ranges: Encodes length explicitly for maximum compatibility
    ///
    /// # Arguments
    /// * `segment` - The segment to create flags for
    ///
    /// # Returns
    /// The flags byte with appropriate bits set.
    fn create_flags(&self, segment: &Segment) -> u8 {
        let mut flags = 0;

        // Calculate range and byte requirements for the bitmap
        // Note: We don't add 1 to range because range is inclusive of offset,
        // and we shift values by (offset + 1) during encoding.
        let bits_needed = segment.range();
        let bytes_needed = bits_needed.div_ceil(8);

        // Optimization 1: For tiny ranges (≤4 bits), use embedded bitmap in flags
        // This is our highest compression optimization - zero additional bytes.
        if bits_needed <= EMBEDDED_BITMAP_NUM_BITS as u64 {
            // Create the actual bitmap bits
            let mut bitmap_bits = 0u8;
            for &value in segment.values() {
                // Calculate bit position: value - offset - 1.
                // The -1 converts from 1-based range to 0-based bit positions.
                let pos = value - segment.offset() - 1;
                bitmap_bits |= 1 << pos;
            }

            // Set embedded bitmap flag and position the bitmap bits correctly
            flags |= EMBEDDED_BITMAP_FLAG;
            flags |= (bitmap_bits << EMBEDDED_BITMAP_SHIFT) & EMBEDDED_BITMAP_MASK;

            return flags;
        }

        // Optimization 2: For small-to-medium bitmaps (1-7 bytes), embed length in flags
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
    /// - Zero bytes for tiny ranges (≤4 bits) using embedded bitmap optimization
    /// - Bitmap bytes based on segment range for larger ranges
    /// - Extra length byte for bitmaps > 7 bytes
    ///
    /// # Arguments
    /// * `segment` - The segment to estimate size for
    ///
    /// # Returns
    /// The estimated encoded size in bytes
    fn estimate_size(&self, segment: &Segment) -> usize {
        // For a bitmap, calculate bytes needed to store all bits
        let range = segment.range() as usize;

        // Check if eligible for embedded bitmap (no additional bytes needed)
        if segment.range() <= EMBEDDED_BITMAP_NUM_BITS as u64 {
            // Only flags byte is needed, but since this estimates the additional
            // size beyond the standard header, return 0
            return 0;
        }

        // Range already accounts for the correct number of positions
        let bytes_needed = range.div_ceil(8);

        // For bitmaps > 7 bytes, we need an explicit length byte
        bytes_needed + (bytes_needed > 7) as usize
    }

    /// Encodes a segment using the BitSet strategy.
    ///
    /// The encoding process uses one of three approaches for maximum
    /// compression:
    /// 1. Embedded bitmap: For tiny ranges (≤4 bits), the bitmap is stored
    ///    directly in the flags byte with no additional bytes written
    /// 2. Embedded length: For small bitmaps (≤7 bytes), the bitmap length is
    ///    embedded in the flags byte to save 1 byte
    /// 3. Standard bitmap: For larger ranges, an explicit length byte plus the
    ///    minimum number of bitmap bytes needed
    ///
    /// Values are encoded as bits relative to the segment's offset, with
    /// position 0 representing (offset+1).
    ///
    /// # Arguments
    /// * `flags` - The encoding flags
    /// * `segment` - The segment to encode
    /// * `result` - Vector to append encoded bytes to
    ///
    /// # Returns
    /// Ok(()) on success, or an error if encoding fails
    fn encode(
        &self,
        flags: u8,
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // Optimization 1: Embedded bitmap - nothing to write, all data is in flags
        // This provides maximum compression (zero bytes) for tiny ranges
        if flags & EMBEDDED_BITMAP_FLAG != 0 {
            // Early return - the bitmap is already embedded in the flags byte
            // which is handled by the segment encoder, not here
            return Ok(());
        }

        // Calculate bitmap size requirements.
        let range = segment.range();
        let bytes_needed = range.div_ceil(8);

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

        // Optimization 2: Check if length is embedded in flags
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
    /// # Arguments
    /// * `cursor` - Cursor positioned at the start of encoded data
    /// * `flags` - The encoding flags
    /// * `offset` - The segment's offset value
    /// * `values` - Vector to append decoded values to
    ///
    /// # Returns
    /// Ok(()) on success, or an error if decoding fails
    fn decode(
        &self,
        cursor: &mut Cursor<&[u8]>,
        flags: u8,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        // Optimization 1: Check for tiny range with embedded bitmap in flags
        if flags & EMBEDDED_BITMAP_FLAG != 0 {
            // Extract the bitmap bits from the flags byte
            // Bits 3-6 contain our embedded bitmap (4 bits total)
            let bitmap_bits = (flags & EMBEDDED_BITMAP_MASK) >> EMBEDDED_BITMAP_SHIFT;

            // Process each bit in the embedded bitmap
            for bit_pos in 0..EMBEDDED_BITMAP_NUM_BITS {
                // If bit is set, convert to value and add to result
                if bitmap_bits & (1 << bit_pos) != 0 {
                    // Convert bit position to value:
                    // 1. Add offset (base of the segment)
                    // 2. Add bit_pos + 1 (converting 0-based bit to 1-based value)
                    values.push(offset + bit_pos as u64 + 1);
                }
            }

            return Ok(());
        }

        // For larger bitmaps, first determine the bitmap length

        // Optimization 2: Check if length is embedded in flags
        let has_embed_length = flags & EMBEDDED_LENGTH_FLAG != 0;

        // Extract bitmap length either from flags or explicit LEB128 value
        let bitmap_len = if has_embed_length {
            // Extract bits 4-6 which contain length (0-7)
            ((flags & EMBEDDED_LENGTH_MASK) >> EMBEDDED_LENGTH_SHIFT) as u64
        } else {
            // Read explicit length as LEB128 encoded value
            cursor.read_leb128()?
        };

        if bitmap_len > VALUE_COUNT_LIMIT as u64 {
            return Err(SegmentDecodeError::ValueCountLimitExceeded(bitmap_len));
        }

        // Read the actual bitmap bytes
        let mut bitmap = vec![0u8; bitmap_len as usize];
        cursor.read_exact(&mut bitmap)?;

        // Process each bit in the bitmap to reconstruct original values
        for (byte_idx, &byte) in bitmap.iter().enumerate() {
            for bit_idx in 0..8 {
                // Check if this bit is set
                if byte & (1 << bit_idx) != 0 {
                    // Calculate position within the bitmap
                    let position = byte_idx * 8 + bit_idx;

                    // Convert bitmap position to value:
                    // 1. Add offset (base of the segment)
                    // 2. Add position + 1 (converting 0-based bit to 1-based value)
                    let value = offset + (position as u64) + 1;
                    values.push(value);
                }
            }
        }

        Ok(())
    }

    /// Determines if the BitSet strategy is applicable for the given segment.
    ///
    /// BitSet encoding is most efficient for:
    /// - Segments with at least 2 values (segments with 1 value use Single encoding)
    /// - Segments with any range (even tiny ranges now benefit from embedded bitmap)
    /// - Dense ranges benefit most, but efficient for any range with compression needs
    ///
    /// # Arguments
    /// * `segment` - The segment to evaluate
    ///
    /// # Returns
    /// `true` if BitSet encoding is appropriate, `false` otherwise
    fn is_applicable(&self, segment: &Segment) -> bool {
        // Prefer single-value encoding (simpler) if we can't make use of the
        // bitmap.
        if segment.len() < 2 {
            return false;
        }

        true
    }
}
