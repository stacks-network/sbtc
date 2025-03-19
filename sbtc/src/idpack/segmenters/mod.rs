mod bitmap;

use crate::leb128::Leb128;

use super::segments::Segments;
use super::{segment, segments};

pub use bitmap::BitmapSegmenter;

/// Errors which can occur during the adaptive segmentation process.
#[derive(Debug, thiserror::Error)]
pub enum SegmenterError {
    /// The input is not sorted.
    #[error("the input is not sorted")]
    UnsortedInput,

    /// The input contains duplicate values.
    #[error("the input contains duplicate values")]
    DuplicateValue(usize),

    /// An error was returned by the segment module.
    #[error(transparent)]
    Segment(#[from] segment::SegmentError),

    /// An error was returned by the segments module.
    #[error(transparent)]
    Segments(#[from] segments::SegmentsError),

    /// An error occurred during size estimation.
    #[error("error estimating segment size")]
    SizeEstimation,

    /// The segmenter encountered invalid boundaries.
    #[error("the segmenter encountered invalid boundaries")]
    InvalidBoundaries,
}

/// Trait for segmenting integer values into optimal segments.
pub trait Segmenter {
    /// Segments the input values into a series of segments.
    ///
    /// ## Parameters
    /// * `values` - The input values to segment.
    ///
    /// ## Returns
    /// A vector of segments containing the input values.
    fn package(&self, values: &[u64]) -> Result<Segments, SegmenterError>;

    /// Estimates (near-exact) the total encoded size in bytes with maximum
    /// compression precision.
    ///
    /// ## Parameters
    /// * `values` - The sorted sequence of values to estimate size for
    ///
    /// ## Returns
    /// * `Ok(size)` - The estimated size in bytes that would be used when
    ///   encoding
    /// * `Err(error)` - If input validation fails (empty or unsorted input)
    ///
    /// ## Default Implementation
    ///
    /// The default implementation naively uses the full packaging process to
    /// generate the optimal segments and calculate the exact byte size. This is
    /// a simple and straightforward approach that ensures consistent size
    /// estimates with the actual encoding process. However, it may be
    /// inefficient for large input sizes or performance-sensitive applications.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idpack::codec::Encodable;
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use test_case::test_case;

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
    #[test_case(&[1, 1, 1, 1, 10, 20, 20, 20, 20, 30, 30, 30, 30, 30, 30, 30, 30, 30, 100]; "duplicates")]
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
    #[test]
    fn test_estimate_size_invalid_inputs() {
        // Create a segmenter
        let segmenter = BitmapSegmenter;

        // Empty input should return size 0
        let result = segmenter.estimate_size(&[]);
        assert_matches!(result, Ok(0));

        // Unsorted input should fail
        let result = segmenter.estimate_size(&[5, 3, 10]);
        assert_matches!(
            result,
            Err(SegmenterError::UnsortedInput),
            "unsorted input should fail"
        );

        // Input with (sorted) duplicates should succeed
        segmenter
            .estimate_size(&[1, 2, 2, 3])
            .expect("duplicate (but sorted) values should not cause an error");
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
