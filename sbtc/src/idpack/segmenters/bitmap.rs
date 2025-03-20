use crate::{
    idpack::{Segment, Segments},
    leb128::Leb128,
};

use super::{Segmenter, SegmenterError};

/// Bitmap cost calculation result for compression optimization.
///
/// Contains the calculated byte costs for both segmentation options:
/// 1. splitting at the current position, or
/// 2. continuing the current segment.
#[derive(Debug)]
struct BitmapCosts {
    /// Total bytes required if we split at current position
    /// Includes current segment bytes plus new segment overhead and payload
    bytes_if_split: usize,

    /// Total bytes required if we continue current segment to include next value
    /// Includes overhead plus expanded bitmap payload
    bytes_if_combined: usize,
}

impl BitmapCosts {
    /// Determines if splitting produces a smaller byte size
    ///
    /// This core decision function compares exact byte costs to ensure
    /// optimal segmentation.
    ///
    /// ## Returns
    /// * `true` if splitting saves bytes compared to continuing the current segment,
    /// * `false` otherwise
    fn should_split(&self) -> bool {
        // Simple core decision: split when it saves bytes
        self.bytes_if_split < self.bytes_if_combined
    }

    /// Calculates bitmap costs for both splitting and continuing scenarios.
    ///
    /// Performs precise byte-level analysis to determine optimal segmentation:
    /// * Calculates exact bitmap size using ceiling division
    /// * Includes accurate LEB128 overhead costs based on value sizes
    ///
    /// ## Parameters
    /// * `offset` - The current segment's offset value (first value)
    /// * `prev` - The previous value in the sequence
    /// * `next` - The next value being considered for inclusion
    ///
    /// ## Returns
    /// A [`BitmapCosts`] instance containing the byte costs for both options.
    fn calculate(offset: u64, prev: u64, next: u64) -> Self {
        // Calculate current sizes
        let current_payload = (prev - offset).div_ceil(8);
        let current_length_header = Leb128::calculate_size(current_payload);

        // Calculate combined sizes
        let combined_payload = (next - offset).div_ceil(8);
        let combined_length_header = Leb128::calculate_size(combined_payload);
        let bytes_if_combined = combined_length_header + combined_payload as usize;

        // Calculate split sizes
        let split_length_header = 1; // Will always be one byte for only an offset
        let split_offset = Leb128::calculate_size(next.saturating_sub(prev));
        let bytes_if_split = current_length_header
            + current_payload as usize
            + split_offset
            + split_length_header as usize;

        // Return the precise byte costs for compression decision
        Self {
            bytes_if_split,
            bytes_if_combined,
        }
    }
}

/// A bitmap segmenter that optimizes for byte savings using direct size comparison
///
/// This segmenter analyzes each potential split point with byte-level precision
/// to achieve optimal compression for integer sequences.
pub struct BitmapSegmenter;

impl Segmenter for BitmapSegmenter {
    /// Creates a new `Segments` instance with optimal boundaries
    ///
    /// This main entry point for bitmap segmentation divides values into segments
    /// at exactly the points that optimize compression.
    ///
    /// ## Parameters
    /// * `values` - The sorted sequence of values to segment
    ///
    /// ## Returns
    /// A `Result` containing either the optimally segmented values or an error
    fn package(&self, values: &[u64]) -> Result<Segments, SegmenterError> {
        // If no values, return empty segments
        if values.is_empty() {
            return Ok(Segments::default());
        }

        // Ensure input is sorted and unique for bitmap segmentation
        if !Self::is_unique_sorted(values) {
            return Err(SegmenterError::InvalidSequence);
        }

        // Find optimal segment boundaries based on byte savings
        let boundaries = self.find_segment_boundaries(values);

        // Create segments using identified boundaries
        let segments = self.create_segments_from_boundaries(values, &boundaries)?;

        Ok(segments)
    }

    /// Estimates the total packaged and encoded size in bytes.
    ///
    /// ## Parameters
    /// * `values` - The sorted sequence of values to estimate size for
    ///
    /// ## Returns
    /// * `Ok(size)` - The estimated size in bytes that would be used when
    ///   encoding
    /// * `Err(error)` - If input validation fails (empty or unsorted input)
    ///
    /// ## Notes
    /// This currently uses the full packaging process, but an improvement
    /// would be to calculate boundaries and use them to estimate the size
    /// without creating (allocating) the segments.
    fn estimate_size(&self, values: &[u64]) -> Result<usize, SegmenterError> {
        if values.is_empty() {
            return Ok(0);
        }

        // Generate optimally segmented values using our boundary detection algorithm
        let segments = self.package(values)?;

        // Track the previous segment offset for delta encoding
        let mut prev_max = 0;

        // Calculate the precise byte size with optimal compression
        let encoded_size = segments.iter().fold(0, |total_bytes, segment| {
            // Calculate LEB128-encoded delta offset from the previous segment's max value
            let delta = segment.offset().saturating_sub(prev_max);
            let offset_size = Leb128::calculate_size(delta);

            // Calculate bitmap size requirements
            let bytes_needed = segment.range().div_ceil(8);

            // Calculate the byte-length header size for the bitmap
            let length_header_size = Leb128::calculate_size(bytes_needed);

            // Update previous offset for next iteration
            prev_max = segment.max();

            // Calculate the total size for the segment
            let segment_size = offset_size + length_header_size + bytes_needed as usize;

            // Add the new segment size to the accumulator
            total_bytes + segment_size
        });

        Ok(encoded_size)
    }
}

impl BitmapSegmenter {
    /// Finds optimal segment boundaries by directly comparing byte costs
    ///
    /// This core algorithm analyzes each potential split point to optimize
    /// compression by comparing byte costs for splitting vs. continuing.
    ///
    /// These byte-perfect decisions ensure optimal compression by creating
    /// segments exactly where they save bytes.
    ///
    /// ## Parameters
    /// * `values` - The sorted sequence of values to segment
    ///
    /// ## Returns
    /// A vector of boundary indices representing optimal segment divisions
    fn find_segment_boundaries(&self, values: &[u64]) -> Vec<usize> {
        let mut boundaries = vec![0]; // Always include start index

        // Handle empty and single value sequences
        if values.len() <= 1 {
            boundaries.push(values.len());
            return boundaries;
        }

        // Track the first value in current segment (used as segment offset)
        // This affects bitmap size calculations.
        // SAFETY: we just ensured that `values` is not empty
        let mut current_offset = values[0];

        // Iterate over pairs of previous and next values to calculate byte costs
        // and determine optimal split points
        for (pos, window) in values.windows(2).enumerate() {
            let [prev, next] = *window else {
                // This branch is unreachable with windows(2), but is needed
                // for the compiler to understand the pattern match.
                continue;
            };

            // Calculate bitmap costs for splitting vs. combining
            let bitmap_costs = BitmapCosts::calculate(current_offset, prev, next);

            // Determine if splitting here maximizes compression
            let should_split = bitmap_costs.should_split();

            if should_split {
                // If we're splitting, then the next position is a start boundary
                // for the next segment
                boundaries.push(pos + 1);

                // `next` is the new segment's offset
                current_offset = next;
            }
        }

        // Always include end boundary
        boundaries.push(values.len());

        boundaries
    }

    /// Creates bitmap segments based on the identified boundaries
    ///
    /// Converts logical segment boundaries into actual encoded segments.
    ///
    /// ## Parameters
    /// * `values` - The sorted sequence of original values
    /// * `boundaries` - The optimal boundary indices determined by analysis
    ///
    /// ## Returns
    /// * Ok(Segments)
    /// * Err(SegmenterError::InvalidBoundaries) - If boundaries are invalid
    /// * Err(SegmenterError::Segment) - If segment manipulation fails (i.e. unsorted values)
    /// * Err(SegmenterError::Segments) - If segments manipulation fails (i.e. overlapping segments)
    fn create_segments_from_boundaries(
        &self,
        values: &[u64],
        boundaries: &[usize],
    ) -> Result<Segments, SegmenterError> {
        let mut segments = Segments::default();

        // Create a segment for each pair of boundaries
        for window in boundaries.windows(2) {
            let [start_idx, end_idx] = *window else {
                // This branch is unreachable with windows(2), but is needed
                // for the compiler to understand the pattern match.
                continue;
            };

            // SAFETY: `start_idx` and `end_idx` are always valid range values
            // as the boundaries themselves are derived from index positions
            // within the `values` slice (where the last `end_idx` is always
            // `values.len()` and thus valid for the exclusive range).
            let slice = &values[start_idx..end_idx];
            let Some(offset) = slice.first() else {
                return Err(SegmenterError::InvalidBoundaries);
            };

            // Create segment using offset
            let mut segment = Segment::new_with_offset(*offset);

            // Use iterator to add remaining values without indexing
            for &value in slice.iter().skip(1) {
                segment.try_insert(value)?;
            }

            segments.try_push(segment)?;
        }

        Ok(segments)
    }

    /// Checks if a slice is sorted in ascending order and contains only unique
    /// values.
    ///
    /// Bitmap segmentation requires sorted input as it relies on gaps between
    /// consecutive values.
    ///
    /// ## Parameters
    /// * `values` - The sequence to check for sorting
    ///
    /// ## Returns
    /// * `true` if values are sorted in ascending order and doesn't contain
    ///    duplicates,
    /// * `false` otherwise
    #[inline]
    fn is_unique_sorted(values: &[u64]) -> bool {
        values.is_empty() || values.windows(2).all(|w| w[0] < w[1])
    }
}

#[cfg(test)]
mod tests {
    use crate::idpack::Encodable;

    use super::*;
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use test_case::test_case;

    /// Tests validation error handling
    #[test]
    fn test_validation_errors() {
        // Unsorted input
        assert_matches!(
            BitmapSegmenter.package(&[5, 3, 1]),
            Err(SegmenterError::InvalidSequence)
        );

        // Duplicate values
        assert_matches!(
            BitmapSegmenter.package(&[5, 5, 10]),
            Err(SegmenterError::InvalidSequence)
        );
    }

    /// Tests the boundary detection with direct byte savings calculations
    #[test_case(&[10], &[0, 1]; "single value")]
    #[test_case(&[10, 11, 12, 13, 14], &[0, 5]; "small sequential - no splits")]
    #[test_case(&[10, 20, 30, 40, 50], &[0, 5]; "evenly spaced - no splits")]
    #[test_case(&[10, 11, 12, 1000, 1001, 1002], &[0, 3, 6]; "clear gap with byte savings")]
    #[test_case(&[1, 1000000], &[0, 1, 2]; "extreme gap forces split")]
    #[test_case(&[1, 2, 3, 100000, 100001], &[0, 3, 5]; "large gap with min size respected")]
    #[test_case(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109], &[0, 10, 20]; "larger sequence with multiple splits")]
    fn test_byte_saving_boundary_detection(values: &[u64], expected_boundaries: &[usize]) {
        let boundaries = BitmapSegmenter.find_segment_boundaries(values);
        assert_eq!(
            boundaries, expected_boundaries,
            "unexpected boundaries for values: {values:?}"
        );
    }

    /// Tests precise break-even gap detection
    #[test_case(&[1, 1000000], 2; "extreme gap creates 2 segments")]
    #[test_case(&[1, 2, 3, 4, 5], 1; "small dense sequence stays as 1 segment")]
    #[test_case(&[1, 2, 50000, 50001], 2; "gap creates 2 segments")]
    #[test_case(&[10, 10 + 16], 1; "gap of 16 with 1-byte delta - no split")]
    #[test_case(&[10, 10 + 17], 2; "gap of 17 with 1-byte delta - split")]
    #[test_case(&[10000, 10000 + 24], 2; "gap of 24 with 2-byte delta - split")]
    #[test_case(&[10000, 10000 + 25], 2; "gap of 25 with 2-byte delta - split")]
    #[test_case(&[1, 1_000_000, 1_000_001], 2; "single value followed by large gap")]
    #[test_case(&[1, 2, 1_000_000, 1_000_001], 2; "multiple values followed by large gap")]
    #[test_case(&[1, 1_000_000, 1_000_001, 2_000_000], 3; "multiple large gaps")]
    #[test_case(&[1, 1_000, 10_000, 10_001, 100_000], 4; "multiple varied gaps")]
    #[test_case(&[1, 11, 21, 31, 41, 51, 61, 71, 81, 91], 1; "10 values spread over 100 range")]
    #[test_case(&[1, 2, 3, 10_000, 20_000, 30_000], 4; "large range with few values")]
    fn test_split_calculations(values: &[u64], expected_segments: usize) {
        let result = BitmapSegmenter.package(values).unwrap();
        assert_eq!(
            result.len(),
            expected_segments,
            "failed to correctly split values: {values:?}"
        );
    }

    /// Test the estimate_size method against actual encoding size
    #[test_case(&[]; "empty input")]
    #[test_case(&[5]; "single value")]
    #[test_case(&[10, 11, 12]; "sequential values")]
    #[test_case(&[10, 20, 30]; "spaced values")]
    #[test_case(&[10, 11, 50]; "values with gap")]
    #[test_case(&[1, 100, 1000, 10000]; "large gaps")]
    #[test_case(&[1, 2, 3, 20, 21, 22, 50, 51, 52]; "multiple segments")]
    #[test_case(&[0]; "zero")]
    #[test_case(&[u64::MAX]; "u64::max")]
    #[test_case(&[0, u64::MAX]; "full range")]
    #[test_case(&[0, 1, 2, 3, 4, 5, 6, 7, 8]; "byte boundary")]
    fn test_size_estimation_accuracy(values: &[u64]) -> Result<(), Box<dyn std::error::Error>> {
        // Skip empty check for this test to avoid early return
        if values.is_empty() {
            return Ok(());
        }

        // Create a bitmap segmenter to test
        let segmenter = BitmapSegmenter;

        // Get estimated size
        let estimated_size = segmenter.estimate_size(values)?;

        // Get actual size by packaging and encoding
        let segments = segmenter.package(values)?;
        let encoded = segments.encode();
        let actual_size = encoded.len();

        // Verify estimate matches actual size
        assert_eq!(
            estimated_size, actual_size,
            "estimated size {estimated_size} should match actual encoded size {actual_size}",
        );

        Ok(())
    }

    /// Test error handling for invalid inputs
    #[test_case(&[5, 3, 10] => Err(SegmenterError::InvalidSequence); "unsorted input")]
    #[test_case(&[1, 2, 2, 3] => Err(SegmenterError::InvalidSequence); "duplicate values")]
    fn test_estimate_size_invalid_inputs(values: &[u64]) -> Result<usize, SegmenterError> {
        BitmapSegmenter.estimate_size(values)
    }

    /// Test estimate consistency across multiple calls
    #[test]
    fn test_estimate_consistency() -> Result<(), SegmenterError> {
        let segmenter = BitmapSegmenter;
        let values = &[10, 20, 30, 40, 50, 100, 200];

        // Multiple calls should return the same estimate
        let first_estimate = segmenter.estimate_size(values)?;
        let second_estimate = segmenter.estimate_size(values)?;
        let third_estimate = segmenter.estimate_size(values)?;

        assert_eq!(first_estimate, second_estimate);
        assert_eq!(second_estimate, third_estimate);

        Ok(())
    }

    // Add property-based testing for broader input coverage
    proptest! {
        /// Property-based test for size estimation accuracy across randomized inputs
        #[test]
        fn prop_size_estimation_accuracy(
            // Generate sorted u64 vectors with reasonable size constraints
            values in prop::collection::vec(0..50_000_u64, 0..100)
                .prop_map(|mut v| {
                    v.sort_unstable();
                    v.dedup();  // Remove duplicates for valid input
                    v
                })
        ) {
            // Skip empty vectors (already tested explicitly)
            prop_assume!(!values.is_empty());

            let segmenter = BitmapSegmenter;

            // This could potentially fail, which proptest will handle
            let estimated_size = segmenter.estimate_size(&values)?;

            let segments = segmenter.package(&values)?;
            let encoded = segments.encode();
            let actual_size = encoded.len();

            // The key property being tested
            prop_assert_eq!(
                estimated_size,
                actual_size,
                "estimated size {} should match actual encoded size {}",
                estimated_size,
                actual_size
            );
        }
    }
}
