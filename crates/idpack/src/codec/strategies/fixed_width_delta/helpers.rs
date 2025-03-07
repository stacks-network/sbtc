//! Helper methods for Fixed-Width Delta encoding optimization.
//!
//! This module provides core analytical functions that maximize compression
//! by detecting patterns, calculating optimal bit widths, and selecting
//! the most space-efficient encoding approach for integer sequences.

use crate::Segment;

use super::{
    types::BitWidth, DeltaValue, FixedWidthDeltaStrategy, DELTA_ADJUSTMENT,
    EXTREME_BIT_WIDTH_THRESHOLD, MAX_BIT_WIDTH, MAX_EMBEDDABLE_BIT_WIDTH, TINY_SEQUENCE_THRESHOLD,
};

/// Helper methods.
impl FixedWidthDeltaStrategy {
    /// Determines if the segment has a regular delta pattern.
    ///
    /// Regular patterns (constant deltas) can be compressed more efficiently
    /// and receive a size bonus in estimation. This method checks if all deltas
    /// in the segment are identical.
    ///
    /// ## Parameters
    /// * `segment` - The segment to analyze
    ///
    /// ## Returns
    /// `true` if all deltas are equal, `false` otherwise
    pub fn has_regular_pattern(segment: &Segment) -> bool {
        if segment.len() < 2 {
            return false;
        }

        let values = segment.values();
        let mut prev = segment.offset();
        let mut first_delta = None;

        for &value in values {
            let delta = Self::calculate_delta(value, prev);

            if let Some(expected) = first_delta {
                if delta != expected {
                    return false;
                }
            } else {
                first_delta = Some(delta);
            }

            prev = value;
        }

        true
    }

    /// Calculates the delta between two values with adjustment for optimal
    /// compression.
    ///
    /// The delta adjustment creates a zero-centered distribution that improves
    /// compression by allowing smaller bit widths for most real-world data
    /// patterns. This significantly reduces encoded size for common cases.
    ///
    /// ## Parameters
    /// * `value` - The current value
    /// * `prev` - The previous value
    ///
    /// ## Returns
    /// The adjusted delta value for optimal compression
    pub fn calculate_delta(value: DeltaValue, prev_value: DeltaValue) -> DeltaValue {
        if value <= prev_value {
            // Handle the edge case where values are equal or (incorrectly) decreasing
            return 0;
        }

        value - prev_value - DELTA_ADJUSTMENT
    }

    /// Calculates the number of bits needed to represent a delta value.
    ///
    /// This method is critical for maximum compression as it determines the
    /// minimum bit width needed to represent deltas, allowing us to pack
    /// values with no wasted bits.
    ///
    /// ## Parameters
    /// * `delta` - The delta value to measure
    ///
    /// ## Returns
    /// The number of bits required (0-64)
    pub fn bits_needed_for_delta(delta: DeltaValue) -> u8 {
        MAX_BIT_WIDTH - delta.leading_zeros() as u8
    }

    /// Calculates the maximum bit width needed for a segment's deltas.
    ///
    /// Determines the minimum bit width that can represent all deltas in the segment.
    /// This is essential for maximizing compression while ensuring all values can be
    /// encoded without loss.
    ///
    /// ## Parameters
    /// * `segment` - The segment containing the values
    ///
    /// ## Returns
    /// The minimum bit width required for all deltas (0-64)
    pub fn calculate_max_bit_width(segment: &Segment) -> u8 {
        let mut max_bit_width = 0;
        let mut prev = segment.offset();

        for &value in segment.values() {
            let delta = Self::calculate_delta(value, prev);
            let bits_needed = Self::bits_needed_for_delta(delta);
            max_bit_width = max_bit_width.max(bits_needed);
            prev = value;
        }

        max_bit_width
    }

    /// Analyzes a segment to determine the optimal bit width representation.
    ///
    /// This method examines the value patterns in the segment to select the
    /// most space-efficient bit width category from five options:
    /// - Tiny: Special case for exactly 2 values (ultra-compressed)
    /// - Sequential: Consecutive integers (zero bits per value)
    /// - Embedded: Small bit widths that fit in flags byte (0-7 bits)
    /// - Normal: Standard bit widths requiring explicit storage (8-31 bits)
    /// - Extreme: Large bit widths with byte-aligned storage (32-64 bits)
    ///
    /// ## Parameters
    /// * `segment` - The segment to analyze
    ///
    /// ## Returns
    /// The optimal bit width representation for maximum compression
    pub fn determine_optimal_bit_width(segment: &Segment) -> BitWidth {
        // Check for tiny sequence first
        if segment.len() == TINY_SEQUENCE_THRESHOLD {
            return BitWidth::Tiny;
        }

        // Calculate max bit width
        let bit_width = Self::calculate_max_bit_width(segment);

        // Select appropriate width representation
        if bit_width == 0 {
            BitWidth::Sequential
        } else if bit_width <= MAX_EMBEDDABLE_BIT_WIDTH {
            BitWidth::Embedded(bit_width)
        } else if bit_width >= EXTREME_BIT_WIDTH_THRESHOLD {
            BitWidth::Extreme(bit_width)
        } else {
            BitWidth::Normal(bit_width)
        }
    }
}
