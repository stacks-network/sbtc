//! # Fixed-Width Delta Encoding Strategy
//!
//! The Fixed-Width Delta encoding strategy compresses integer sequences by encoding the
//! differences (deltas) between consecutive values using the minimum number of bits required.
//! This strategy achieves maximum compression through bit-level optimizations and pattern detection.
//!
//! ## How It Works
//!
//! Instead of encoding absolute values, this strategy:
//!
//! * Stores the first value as the segment offset
//! * Encodes subsequent values as differences from previous values
//! * Adjusts each delta by subtracting 1 (leveraging the fact that sorted values differ by at least 1)
//! * Uses the minimum bit width needed to represent all deltas
//! * Packs delta bits contiguously across byte boundaries
//!
//! ## Optimizations
//!
//! ### 1. Tiny Sequence Optimization (2 values)
//!
//! For segments with exactly 2 values, only the delta is encoded using variable-length LEB128.
//! This eliminates all overhead bytes (bit width, count), achieving maximum compression for pairs.
//!
//! ### 2. Embedded Bit Width (0-7 bits)
//!
//! For deltas requiring 0-7 bits, the bit width is stored directly in the flags byte,
//! saving 1 byte compared to explicit bit width encoding.
//!
//! ### 3. Regular Pattern Bonus
//!
//! Segments with consistent delta patterns receive a size bonus in estimation,
//! reflecting their higher compressibility.
//!
//! ### 4. Bit-level Packing
//!
//! Deltas are packed contiguously at the bit level, using only the exact number of bits
//! required, regardless of byte boundaries.
//!
//! ## When To Use
//!
//! Fixed-Width Delta encoding is most efficient for:
//!
//! * Sparse sequences where few values in a range are present
//! * Sequences with large gaps between some values
//! * Pairs of values (via tiny sequence optimization)
//! * Sequences with regular patterns or constant deltas
//! * Values approaching u64::MAX where bitmap becomes impractical

mod bit_buffer;
mod decoding;
mod encoding;
mod helpers;
mod types;

use std::io::Cursor;

use types::BitWidth;

use crate::{
    codec::{self, SegmentDecodeError, SegmentEncodeError},
    leb128::Leb128,
    Segment, SegmentEncoding,
};

use super::EncodingStrategy;

/// Type used for internal delta calculations to ensure cross-platform consistency
type DeltaValue = u64;

// Fixed-Width Delta specific constants
/// Flag indicating bit width is embedded directly in the flag byte.
/// When set, this optimization saves 1 byte by storing the bit width in bits 4-6.
/// This is crucial for maximum compression of small-delta sequences.
const EMBEDDED_BIT_WIDTH_FLAG: u8 = codec::ENCODING_FLAG_1; // Bit 2

/// Bit mask for extracting embedded bit width from flags.
/// Bits 4-6 can represent values 0-7, allowing storage of the most common bit widths
/// without requiring an additional byte.
const EMBEDDED_BIT_WIDTH_MASK: u8 =
    codec::ENCODING_FLAG_3 | codec::ENCODING_FLAG_4 | codec::ENCODING_FLAG_5; // Bits 4-6 for width (0-7)

/// Shift amount to position bit width in flags byte.
/// Used to extract or insert bit width values to/from the flags byte.
const EMBEDDED_BIT_WIDTH_SHIFT: u8 = 4;

/// Maximum bit width that can be embedded in flags.
/// Bit widths 0-7 can be stored directly in the flags byte,
/// eliminating the need for an explicit bit width byte.
const MAX_EMBEDDABLE_BIT_WIDTH: u8 = 7;

/// Flag indicating a tiny sequence optimization (2 values only).
/// When set, this enables ultra-compact encoding where only a single delta
/// value is stored using LEB128 encoding (no bit width, no count).
const TINY_SEQUENCE_FLAG: u8 = codec::ENCODING_FLAG_2; // Bit 3

/// Size of tiny sequences for specialized encoding.
/// Exactly 2 values trigger optimized encoding that eliminates
/// overhead bytes for maximum compression efficiency.
const TINY_SEQUENCE_THRESHOLD: usize = 2;

/// Delta adjustment applied during encoding/decoding.
/// Since consecutive values in a sorted set must differ by at least 1,
/// we can subtract this value from deltas to reduce their magnitude,
/// potentially saving bits and improving compression.
const DELTA_ADJUSTMENT: DeltaValue = 1;

/// Minimum number of values for fixed-width delta to be efficient.
/// This strategy requires at least 2 values to calculate a delta.
const MIN_VALUE_COUNT: usize = 2;

/// Number of values needed to qualify for regular pattern bonus.
/// Sequences with consistent deltas and at least this many values
/// receive a compression bonus (size estimate reduced by 1 byte).
const REGULAR_PATTERN_THRESHOLD: usize = 5;

/// Maximum standard bit width that can be used.
/// Defines the upper limit for delta encoding precision.
const MAX_BIT_WIDTH: u8 = 64;

/// Threshold for special handling of large bit widths
const EXTREME_BIT_WIDTH_THRESHOLD: u8 = 60;

/// Implements Fixed-Width Delta encoding strategy for maximum compression of
/// integer sequences.
pub struct FixedWidthDeltaStrategy;

impl EncodingStrategy for FixedWidthDeltaStrategy {
    /// Returns the type flag byte identifying this encoding strategy.
    ///
    /// # Returns
    /// The fixed-width delta encoding type identifier
    fn type_flag(&self) -> u8 {
        codec::TYPE_FW_DELTA
    }

    /// Returns the segment encoding type for this strategy.
    ///
    /// # Returns
    /// The fixed-width delta encoding type
    fn encoding_type(&self) -> SegmentEncoding {
        SegmentEncoding::FixedWidthDelta
    }

    /// Creates flags for the segment based on its characteristics.
    ///
    /// This method applies multiple optimization techniques to maximize compression:
    /// 1. For tiny sequences (2 values), sets the tiny sequence flag
    /// 2. For bit widths 0-7, embeds the width directly in the flags byte
    ///
    /// These optimizations can save 1+ bytes in the encoded representation.
    ///
    /// # Arguments
    /// * `segment` - The segment to create flags for
    ///
    /// # Returns
    /// The flags byte with appropriate bits set
    fn create_flags(&self, segment: &Segment) -> u8 {
        // Use the BitWidth enum to determine the optimal encoding
        match Self::determine_optimal_bit_width(segment) {
            BitWidth::Tiny => TINY_SEQUENCE_FLAG,
            BitWidth::Sequential => EMBEDDED_BIT_WIDTH_FLAG,
            BitWidth::Embedded(width) => {
                EMBEDDED_BIT_WIDTH_FLAG
                    | ((width << EMBEDDED_BIT_WIDTH_SHIFT) & EMBEDDED_BIT_WIDTH_MASK)
            }
            _ => 0, // Normal and Extreme widths need no special flags
        }
    }

    /// Estimates the encoded size in bytes for the given segment.
    ///
    /// This method analyzes segment characteristics to provide an accurate size
    /// estimate, applying several compression optimizations:
    /// 1. Tiny sequence optimization for 2 values
    /// 2. Bit width embedding for small bit widths (0-7)
    /// 3. Special handling for sequential values (bit width 0)
    /// 4. Compression bonus for regular patterns
    ///
    /// # Arguments
    /// * `segment` - The segment to estimate size for
    ///
    /// # Returns
    /// The estimated encoded size in bytes
    ///
    /// # Panics
    /// If segment contains fewer than 2 values
    fn estimate_size(&self, segment: &Segment) -> usize {
        // Validate segment has minimum required values
        // This is an important early check for valid encoding
        if segment.len() < MIN_VALUE_COUNT {
            panic!(
                "Fixed-width delta encoding requires at least {} values",
                MIN_VALUE_COUNT
            );
        }

        // Optimization 1: Tiny sequence (exactly 2 values)
        // This is our most efficient encoding, using only LEB128 bytes for the delta
        // No flags, no explicit bit width, no count field - maximum compression
        if segment.len() == TINY_SEQUENCE_THRESHOLD {
            // Calculate the delta between the two values with adjustment
            let delta = Self::calculate_delta(segment[1], segment[0]);
            // Return exact byte count needed for the LEB128-encoded delta
            return Leb128::calculate_size(delta);
        }

        // For larger sequences, compute key metrics that determine encoding size
        let max_bit_width = Self::calculate_max_bit_width(segment);
        let is_regular_pattern = Self::has_regular_pattern(segment);
        let delta_count = segment.value_count();

        // Base size calculation starts at 0 and adds components
        let mut size = 0;

        // Add byte for explicit bit width only if too large to embed in flags
        // Small bit widths (0-7) get embedded in flags, saving 1 byte
        if max_bit_width > MAX_EMBEDDABLE_BIT_WIDTH {
            size += 1;
        }

        // Add LEB128-encoded count size - varies based on value count
        // Using LEB128 saves bytes for segments with <128 values (common case)
        size += Leb128::calculate_size(segment.value_count() as u64);

        // Optimization 2: Sequential values (bit width 0)
        // When all deltas are 1, we don't need to store any bit-packed data
        if max_bit_width == 0 {
            // Optimization 3: Apply regular pattern bonus for eligible segments
            // This reflects that sequential patterns compress extremely well
            if is_regular_pattern && delta_count >= REGULAR_PATTERN_THRESHOLD {
                return size.saturating_sub(1).max(1);
            }
            return size;
        }

        // For non-zero bit widths, calculate packed bits size
        // This is the most precise calculation - exact bit count with ceiling division
        let total_bits = max_bit_width as usize * delta_count;
        size += (total_bits + 7) / 8; // Ceiling division for bits to bytes

        // Optimization 3: Apply regular pattern bonus for eligible segments
        // This optimistically reduces size estimate for highly compressible patterns
        if is_regular_pattern && delta_count >= REGULAR_PATTERN_THRESHOLD {
            size = size.saturating_sub(1).max(1); // Never go below 1 byte
        }

        size
    }

    /// Encodes a segment using the Fixed-Width Delta strategy.
    ///
    /// The encoding process applies multiple compression techniques:
    /// 1. Tiny sequence optimization for exactly 2 values
    /// 2. Embedding bit widths 0-7 directly in flags
    /// 3. Sequential value optimization (bit width 0)
    /// 4. Bit-level packing for minimal byte usage
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
        _flags: u8,
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // Validate segment has minimum required values
        if segment.len() < MIN_VALUE_COUNT {
            return Err(SegmentEncodeError::InsufficientValueCount {
                min: MIN_VALUE_COUNT,
                actual: segment.len(),
            });
        }

        // Delegate to the structured encoding method
        Self::encode_value_sequence(segment, result)
    }

    /// Decodes a Fixed-Width Delta encoded segment.
    ///
    /// This method reconstructs the original values by:
    /// 1. Handling special cases (tiny sequences, sequential values)
    /// 2. Extracting bit width from flags or reading it explicitly
    /// 3. Reading and unpacking bit-packed deltas
    /// 4. Converting deltas back to absolute values
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
        // Delegate to the structured decoding method
        Self::decode_values(cursor, flags, offset, values)
    }

    /// Determines if the Fixed-Width Delta strategy is applicable for the given segment.
    ///
    /// This strategy requires at least 2 values to calculate deltas, but is
    /// otherwise broadly applicable to many integer sequences for compression.
    ///
    /// # Arguments
    /// * `segment` - The segment to evaluate
    ///
    /// # Returns
    /// `true` if the segment has at least 2 values, `false` otherwise
    fn is_applicable(&self, segment: &Segment) -> bool {
        segment.len() >= MIN_VALUE_COUNT
    }
}
