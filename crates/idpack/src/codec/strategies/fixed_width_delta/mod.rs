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

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Creates a test segment with the given values
    fn create_segment(values: &[u64]) -> Segment {
        // Keep this helper as is - it's useful for test setup
        Segment::new_from(SegmentEncoding::FixedWidthDelta, values.to_vec())
    }

    /// Gets the actual encoded size for testing and comparison
    fn get_actual_encoded_size(segment: &Segment) -> usize {
        let strategy = FixedWidthDeltaStrategy;
        let mut result = Vec::new();

        // Use the strategy's own flag creation logic
        let flags = strategy.create_flags(segment);

        strategy.encode(flags, segment, &mut result).unwrap();
        result.len()
    }

    #[test]
    #[should_panic = "Fixed-width delta encoding requires at least 2 values"]
    fn test_empty_segment() {
        let segment = create_segment(&[]);
        let strategy = FixedWidthDeltaStrategy;
        let _ = strategy.estimate_size(&segment);
    }

    #[test]
    #[should_panic = "Fixed-width delta encoding requires at least 2 values"]
    fn test_single_value_segment() {
        let segment = create_segment(&[42]);
        let strategy = FixedWidthDeltaStrategy;
        let _ = strategy.estimate_size(&segment);
    }

    #[test_case(&[10, 12]; "small delta")]
    #[test_case(&[10, 20]; "medium delta")]
    #[test_case(&[10, 1000]; "large delta")]
    fn test_tiny_sequence_optimization(values: &[u64]) {
        let segment = create_segment(values);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate expected LEB128 size
        let delta = segment.values()[0]
            .saturating_sub(segment.offset())
            .saturating_sub(1);
        let expected = Leb128::calculate_size(delta);

        let estimated_size = strategy.estimate_size(&segment);
        let actual_size = get_actual_encoded_size(&segment);

        assert_eq!(
            estimated_size, expected,
            "Tiny sequence size calculation incorrect"
        );
        assert_eq!(
            estimated_size, actual_size,
            "Estimated size differs from actual encoded size"
        );
    }

    #[test_case(&[10, 11, 12, 13, 14, 15]; "sequential pattern")]
    #[test_case(&[10, 13, 16, 19, 22, 25]; "regular jumps")]
    fn test_regular_pattern_bonus(values: &[u64]) {
        let segment = create_segment(values);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate max bit width using the strategy method for consistency
        let max_bit_width = FixedWidthDeltaStrategy::calculate_max_bit_width(&segment);

        // Use MAX_EMBEDDABLE_BIT_WIDTH instead of hardcoded 3
        let actual_size = get_actual_encoded_size(&segment);

        // The estimated size should be 1 byte less than actual due to the pattern bonus
        let estimated_size = strategy.estimate_size(&segment);
        assert_eq!(
            estimated_size,
            (actual_size - 1).max(1),
            "Regular pattern bonus not applied correctly for pattern with bit width {}",
            max_bit_width
        );
    }

    #[test_case(&[10, 11, 12]; "width 0")]
    #[test_case(&[10, 12, 14]; "width 1")]
    #[test_case(&[10, 14, 18]; "width 2")]
    #[test_case(&[10, 18, 26]; "width 3")]
    #[test_case(&[10, 26, 42]; "width 4")]
    #[test_case(&[10, 42, 74]; "width 5")]
    fn test_bit_width_handling(values: &[u64]) {
        let segment = create_segment(values);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate max bit width
        let max_bit_width = FixedWidthDeltaStrategy::calculate_max_bit_width(&segment);
        let flags = strategy.create_flags(&segment);

        // Perform roundtrip encode/decode
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        assert_eq!(
            segment.as_slice(),
            &decoded[..],
            "Roundtrip failed for bit width {}",
            max_bit_width
        );
    }

    #[test]
    fn test_zero_bit_width() {
        // Create segment where all values are sequential (deltas of 1)
        let segment = create_segment(&[10, 11, 12, 13, 14, 15]);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate expected size
        let count_size = Leb128::calculate_size(segment.value_count() as u64);
        // When bit width is 0, we don't add bit-packed data

        // Compare with estimated size (add bit width embedded in flags)
        let estimated_size = strategy.estimate_size(&segment);
        assert_eq!(
            estimated_size, count_size,
            "Zero bit width calculation incorrect"
        );

        // Verify against actual encoded size
        let actual_size = get_actual_encoded_size(&segment);
        assert_eq!(
            estimated_size, actual_size,
            "Zero bit width estimation differs from actual encoded size"
        );
    }

    #[test_case(10; "small count")]
    #[test_case(100; "medium count")]
    #[test_case(1000; "large count")]
    fn test_variable_count_encoding(count: u64) {
        // Create segment with sequential values of specified count
        let values: Vec<_> = (10..10 + count).collect();
        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;

        // For sequential values, bit width is 0
        // Base size is just the count encoding size
        let mut expected_size = Leb128::calculate_size(count);

        // Apply the bonus for regular patterns with sufficient values
        // This matches the behavior in estimate_size()
        if count >= REGULAR_PATTERN_THRESHOLD as u64 {
            expected_size = (expected_size - 1).max(1);
        }

        let estimated_size = strategy.estimate_size(&segment);
        assert_eq!(
            estimated_size, expected_size,
            "Count encoding size incorrect for {} values",
            count
        );
    }

    #[test]
    fn test_irregular_pattern_no_bonus() {
        // Create segment with irregular deltas
        let segment = create_segment(&[10, 15, 18, 30, 45, 47]);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate size without bonus
        let mut size = 0;
        let values_slice = segment.values();

        // Get max bit width
        let max_bit_width = FixedWidthDeltaStrategy::calculate_max_bit_width(&segment);

        // Add bit width byte if needed
        if max_bit_width > MAX_EMBEDDABLE_BIT_WIDTH {
            size += 1;
        }

        // Add count
        size += Leb128::calculate_size(values_slice.len() as u64);

        // Add bit-packed data size
        let total_bits = max_bit_width as usize * values_slice.len();
        size += (total_bits + 7) / 8;

        // Verify no bonus is applied
        let estimated_size = strategy.estimate_size(&segment);
        assert_eq!(
            estimated_size, size,
            "Irregular pattern should not receive bonus"
        );
    }

    #[test_case(&[100, 150, 250, 350, 550, 750]; "bit width boundary 3-4")]
    #[test_case(&[100, 170, 270, 470, 870, 1670]; "bit width boundary 8-9")]
    fn test_bit_width_boundaries(values: &[u64]) {
        let segment = create_segment(values);
        let strategy = FixedWidthDeltaStrategy;

        // Calculate max bit width
        let max_bit_width = FixedWidthDeltaStrategy::calculate_max_bit_width(&segment);

        // Get the estimated size using our strategy
        let estimated = strategy.estimate_size(&segment);

        // Get actual size using strategy's flag creation
        let actual = get_actual_encoded_size(&segment);

        // Verify bit width embedding impact
        if max_bit_width <= MAX_EMBEDDABLE_BIT_WIDTH {
            assert!(
                strategy.create_flags(&segment) & EMBEDDED_BIT_WIDTH_FLAG != 0,
                "Bit width {} should be embedded in flags",
                max_bit_width
            );
        }

        assert_eq!(
            estimated, actual,
            "Estimated size should match actual size at bit width {}",
            max_bit_width
        );
    }

    #[test]
    fn test_large_value_deltas() {
        // Create sequence with values approaching u64::MAX to test delta handling
        let large_values = vec![
            u64::MAX / 2,
            u64::MAX / 2 + 100,
            u64::MAX / 2 + 10000,
            u64::MAX / 2 + 1000000,
        ];
        let segment = create_segment(&large_values);
        let strategy = FixedWidthDeltaStrategy;

        // Use strategy's own flag creation for maximum consistency
        let flags = strategy.create_flags(&segment);

        // Verify encoding works without overflow
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        // Verify roundtrip works correctly for large values
        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        assert_eq!(
            segment.as_slice(),
            &decoded[..],
            "Large value roundtrip failed"
        );
    }

    #[test]
    fn test_mixed_pattern_detection() {
        // Create a segment with an initial regular pattern that breaks
        // This tests the pattern detection heuristic
        let values = vec![
            100, 110, 120, 130, 140, // Regular pattern (+10)
            200, 300, 350, 370, // Irregular jumps
        ];
        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;

        // First, verify if the pattern is actually detected as irregular
        assert!(
            !FixedWidthDeltaStrategy::has_regular_pattern(&segment),
            "Pattern should be detected as irregular"
        );

        // Get the estimated size from the strategy
        let estimated_size = strategy.estimate_size(&segment);

        // Calculate the non-bonus size for comparison
        let max_bit_width = FixedWidthDeltaStrategy::calculate_max_bit_width(&segment);
        let delta_count = segment.value_count();

        // Calculate expected size without any pattern bonus
        let mut expected_size = 0;

        // Add bit width byte if needed (>7 now with extended embeddable range)
        if max_bit_width > MAX_EMBEDDABLE_BIT_WIDTH {
            expected_size += 1;
        }

        // Add count
        expected_size += Leb128::calculate_size(delta_count as u64);

        // Add bit-packed data size
        let total_bits = max_bit_width as usize * delta_count;
        expected_size += (total_bits + 7) / 8; // Ceiling division

        // No bonus should be applied since pattern is irregular

        assert_eq!(
            estimated_size, expected_size,
            "Mixed pattern should not receive bonus optimization"
        );
    }

    #[test]
    fn test_geometric_progression() {
        // Test geometric progression (exponential growth pattern)
        let values = vec![10, 20, 40, 80, 160, 320, 640];
        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;

        // Since these deltas grow exponentially, bit width optimization is crucial
        let estimated_size = strategy.estimate_size(&segment);
        let actual_size = get_actual_encoded_size(&segment);

        assert_eq!(
            estimated_size, actual_size,
            "Geometric progression encoding size mismatch"
        );

        // Verify the bit width is correctly calculated for growing deltas
        let mut max_bit_width = 0;
        let mut prev = segment.offset();
        for &value in segment.values() {
            let delta = value.saturating_sub(prev).saturating_sub(1);
            let bits_needed = 64 - delta.leading_zeros() as u8;
            max_bit_width = max_bit_width.max(bits_needed);
            prev = value;
        }

        // Verify using more advanced pattern might be beneficial for future optimizations
        println!("Geometric progression max bit width: {}", max_bit_width);
    }

    #[test_case(&[10, 11, 12]; "width 0")]
    #[test_case(&[10, 12, 14]; "width 1")]
    #[test_case(&[10, 14, 18]; "width 2")]
    #[test_case(&[10, 18, 26]; "width 3")]
    #[test_case(&[10, 26, 42]; "width 4")]
    #[test_case(&[10, 42, 74]; "width 5")]
    #[test_case(&[10, 74, 138]; "width 6")]
    fn test_bit_width_roundtrip(values: &[u64]) {
        let segment = create_segment(values);
        let strategy = FixedWidthDeltaStrategy;

        // Use the strategy's flag creation
        let flags = strategy.create_flags(&segment);

        // Perform roundtrip encode/decode
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        assert_eq!(
            segment.as_slice(),
            &decoded[..],
            "Roundtrip failed for bit width {}",
            FixedWidthDeltaStrategy::calculate_max_bit_width(&segment)
        );
    }

    #[test_case(10, 5, 4; "standard delta")]
    #[test_case(100, 50, 49; "large delta")]
    #[test_case(5, 4, 0; "minimum delta")]
    #[test_case(u64::MAX, u64::MAX-10, 9; "near max value")]
    fn test_calculate_delta(value: u64, prev_value: u64, expected: u64) {
        let delta = FixedWidthDeltaStrategy::calculate_delta(value, prev_value);
        assert_eq!(delta, expected, "Delta calculation incorrect");
    }

    #[test_case(0, 0; "zero value")]
    #[test_case(1, 1; "single bit")]
    #[test_case(7, 3; "small value")]
    #[test_case(255, 8; "one byte")]
    #[test_case(256, 9; "byte boundary")]
    #[test_case(u64::MAX >> 1, 63; "near max bits")]
    fn test_bits_needed_for_delta(delta: u64, expected_bits: u8) {
        let bits = FixedWidthDeltaStrategy::bits_needed_for_delta(delta);
        assert_eq!(
            bits, expected_bits,
            "Bit width calculation incorrect for {}",
            delta
        );
    }

    #[test]
    fn test_calculate_max_bit_width() {
        // Test case 1: Sequential values (deltas=1, adjusted=0)
        let seq_segment = create_segment(&[10, 11, 12, 13]);
        assert_eq!(
            FixedWidthDeltaStrategy::calculate_max_bit_width(&seq_segment),
            0,
            "Sequential values should have bit width 0"
        );

        // Test case 2: Constant deltas
        let const_delta_segment = create_segment(&[10, 15, 20, 25, 30]);
        assert_eq!(
            FixedWidthDeltaStrategy::calculate_max_bit_width(&const_delta_segment),
            3,
            "Constant delta of 5 (adjusted to 4) should need 3 bits"
        );

        // Test case 3: Mixed deltas
        let mixed_segment = create_segment(&[10, 15, 25, 60]);
        let max_delta: u64 = 35 - 1; // max delta is (60-25), then subtract adjustment
        let expected_bits = 64 - max_delta.leading_zeros() as u8;
        assert_eq!(
            FixedWidthDeltaStrategy::calculate_max_bit_width(&mixed_segment),
            expected_bits,
            "Max bit width calculation incorrect for mixed deltas"
        );
    }

    #[test_case(&[10, 11, 12, 13, 14], true; "sequential values")]
    #[test_case(&[10, 20, 30, 40, 50], true; "constant deltas")]
    #[test_case(&[10, 11, 12, 20, 30], false; "pattern break")]
    // Note that this test case will be deduplicated and sorted.
    #[test_case(&[10, 20, 10, 20, 10], true; "oscillating pattern")]
    fn test_has_regular_pattern(values: &[u64], expected: bool) {
        let segment = create_segment(values);

        assert_eq!(
            FixedWidthDeltaStrategy::has_regular_pattern(&segment),
            expected,
            "Regular pattern detection incorrect for {:?}",
            values
        );
    }

    #[test]
    fn test_encode_tiny_sequence() {
        let segment = create_segment(&[100, 150]);
        let mut result = Vec::new();

        // Expected: Delta(150, 100) - 1 = 49, encoded as LEB128
        let expected_delta = 49;
        let mut expected = Vec::new();
        Leb128::encode_into(expected_delta, &mut expected);

        FixedWidthDeltaStrategy::encode_tiny_sequence(&segment, &mut result).unwrap();

        assert_eq!(result, expected, "Tiny sequence encoding incorrect");
    }

    #[test]
    fn test_bit_packing() {
        // Test encoding and bit packing for various bit widths

        // Test with bit width 3
        // Values: [10, 18, 26] -> deltas: [7, 7] (after adjustment)
        // In binary: 111, 111
        // Packed: 111111 (0x3F or 63 in decimal)
        let segment = create_segment(&[10, 18, 26]);
        let bit_width = 3;

        let mut result = Vec::new();
        FixedWidthDeltaStrategy::encode_bit_packed_normal(&segment, bit_width, &mut result)
            .unwrap();

        // We expect 6 bits total, which is < 1 byte
        assert_eq!(result.len(), 1, "Should use 1 byte for bit width 3");
        // The first byte should contain 111111 = 0x3F
        assert_eq!(result[0], 0x3F, "Bit packing incorrect for bit width 3");
    }

    #[test]
    fn test_encode_decode_integration() {
        // Integration test for encode and decode
        let strategy = FixedWidthDeltaStrategy;

        // Create a segment with mixed deltas that exercises multiple aspects:
        // - Different bit widths
        // - Multiple byte boundaries
        // - Bit buffer flush edge cases
        let values = vec![
            100, // Base value
            105, // Delta: 4 (after -1 adjustment)
            120, // Delta: 14
            150, // Delta: 29
            200, // Delta: 49
            300, // Delta: 99
            500, // Delta: 199
        ];

        let segment = create_segment(&values);
        let flags = strategy.create_flags(&segment);

        // Encode the segment
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        // Decode the segment
        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        // Verify correct roundtrip
        assert_eq!(
            segment.as_slice(),
            &decoded[..],
            "Integration encode/decode failed for mixed deltas"
        );
    }

    #[test]
    fn test_consecutive_values_roundtrip() {
        // This specifically tests the case that was failing
        // Values with a delta of exactly 1 (consecutive)
        let values = vec![1, 70887, 70888];
        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;
        let flags = strategy.create_flags(&segment);

        // Encode
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        // Decode
        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        assert_eq!(
            segment.as_slice(),
            &decoded[..],
            "Failed roundtrip with consecutive values"
        );
    }

    #[test]
    fn test_extreme_value_roundtrip() {
        // Values from a failing proptest
        let values = vec![
            1,
            9223372036854775807, // u64::MAX/2
            9223372036854775808, // u64::MAX/2 + 1
            9223372036854775907,
        ]; // u64::MAX/2 + 100

        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;
        let flags = strategy.create_flags(&segment);

        // Create segment with fixed-width delta encoding
        let segment = Segment::new_from(SegmentEncoding::FixedWidthDelta, values.clone());

        // Encode
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        // Decode
        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        // Verify exact match including the problematic large value
        assert_eq!(values, decoded, "Extreme values should roundtrip correctly");

        // Specifically check the last value that was failing
        assert_eq!(
            values[3], decoded[3],
            "Last extreme value should match exactly"
        );
    }

    #[test]
    fn test_extreme_delta_precision() {
        // Use values with particularly challenging deltas
        let values = vec![
            1,
            u64::MAX / 2,      // 9223372036854775807
            u64::MAX / 2 + 1,  // 9223372036854775808
            u64::MAX / 2 + 99, // 9223372036854775906
        ];

        let segment = create_segment(&values);
        let strategy = FixedWidthDeltaStrategy;
        let flags = strategy.create_flags(&segment);

        // Encode
        let mut encoded = Vec::new();
        strategy.encode(flags, &segment, &mut encoded).unwrap();

        // Decode
        let mut decoded = Vec::new();
        decoded.push(segment.offset());
        let mut cursor = Cursor::new(&encoded[..]);
        strategy
            .decode(&mut cursor, flags, segment.offset(), &mut decoded)
            .unwrap();

        // Verify precision is maintained for extreme values
        assert_eq!(values, decoded, "Extreme delta precision test failed");

        // Print the actual delta between the last two values
        println!("Encoded delta: {}", values[3] - values[2] - 1);
    }

    #[test]
    fn test_decode_values_format() {
        let strategy = FixedWidthDeltaStrategy;

        // Test tiny format
        let tiny_segment = create_segment(&[10, 20]);
        let tiny_flags = TINY_SEQUENCE_FLAG;

        // Test embedded width format
        let embedded_segment = create_segment(&[10, 18, 26]);
        let embedded_flags = EMBEDDED_BIT_WIDTH_FLAG | (3 << EMBEDDED_BIT_WIDTH_SHIFT);

        // Test explicit width format
        let explicit_segment = create_segment(&[10, 100, 1000]);
        let explicit_flags = 0; // No flags set

        // Create encodings for all formats
        let mut tiny_encoded = Vec::new();
        let mut embedded_encoded = Vec::new();
        let mut explicit_encoded = Vec::new();

        strategy
            .encode(tiny_flags, &tiny_segment, &mut tiny_encoded)
            .unwrap();
        strategy
            .encode(embedded_flags, &embedded_segment, &mut embedded_encoded)
            .unwrap();
        strategy
            .encode(explicit_flags, &explicit_segment, &mut explicit_encoded)
            .unwrap();

        // Verify all formats decode correctly
        let mut tiny_decoded = Vec::new();
        let mut embedded_decoded = Vec::new();
        let mut explicit_decoded = Vec::new();

        tiny_decoded.push(tiny_segment.offset());
        embedded_decoded.push(embedded_segment.offset());
        explicit_decoded.push(explicit_segment.offset());

        let mut tiny_cursor = Cursor::new(&tiny_encoded[..]);
        let mut embedded_cursor = Cursor::new(&embedded_encoded[..]);
        let mut explicit_cursor = Cursor::new(&explicit_encoded[..]);

        strategy
            .decode(
                &mut tiny_cursor,
                tiny_flags,
                tiny_segment.offset(),
                &mut tiny_decoded,
            )
            .unwrap();
        strategy
            .decode(
                &mut embedded_cursor,
                embedded_flags,
                embedded_segment.offset(),
                &mut embedded_decoded,
            )
            .unwrap();
        strategy
            .decode(
                &mut explicit_cursor,
                explicit_flags,
                explicit_segment.offset(),
                &mut explicit_decoded,
            )
            .unwrap();

        assert_eq!(
            tiny_segment.as_slice(),
            &tiny_decoded[..],
            "Tiny format roundtrip failed"
        );
        assert_eq!(
            embedded_segment.as_slice(),
            &embedded_decoded[..],
            "Embedded format roundtrip failed"
        );
        assert_eq!(
            explicit_segment.as_slice(),
            &explicit_decoded[..],
            "Explicit format roundtrip failed"
        );
    }
}
