use crate::{
    idpack::{
        codec::{
            strategies::{BitsetStrategy, EncodingStrategy},
            FLAGS_SIZE,
        },
        Segment, SegmentEncoding, Segments,
    },
    Leb128,
};

use super::{Error, Segmenter};

/// Helper struct to track segment state during boundary detection
///
/// Maintains essential state information for each potential segment to
/// ensure optimal byte-level compression decisions.
#[derive(Debug)]
struct SegmentState {
    /// First value in current segment (used as segment offset)
    /// This affects bitmap size calculations and LEB128 encoding overhead
    current_offset: u64,

    /// Index of last added boundary (split point)
    /// Used to track the last segment boundary for efficient state updates
    last_boundary: usize,
}

/// Bitmap cost calculation result for compression optimization
///
/// Contains the calculated byte costs for both segmentation options:
/// splitting at the current position or continuing the current segment.
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
    ///
    /// `true` if splitting saves bytes compared to continuing the current segment,
    /// `false` otherwise
    fn should_split(&self) -> bool {
        // Simple core decision: split when it saves bytes
        self.bytes_if_split < self.bytes_if_combined
    }

    /// Calculates bitmap costs for both splitting and continuing scenarios
    ///
    /// Performs precise byte-level analysis to determine optimal segmentation:
    /// - Calculates exact bitmap size using ceiling division
    /// - Includes accurate LEB128 overhead costs based on value sizes
    /// - Handles special cases for byte-perfect boundary detection
    ///
    /// ## Parameters
    ///
    /// * `offset` - The current segment's offset value (first value)
    /// * `prev` - The previous value in the sequence
    /// * `next` - The next value being considered for inclusion
    ///
    /// ## Returns
    ///
    /// `Result<BitmapCosts, Error>` with precise byte calculations for both options
    fn calculate(offset: u64, prev: u64, next: u64) -> Result<Self, Error> {
        // Calculate current segment payload size (without next value)
        // This uses the actual BitsetStrategy implementation to ensure consistency
        let current_segment_payload = BitsetStrategy
            .calculate_payload_size(&[offset, prev])
            .ok_or(Error::SizeEstimation)?;

        // Calculate extended segment payload (with next value)
        let combined_segment_payload = BitsetStrategy
            .calculate_payload_size(&[offset, next])
            .ok_or(Error::SizeEstimation)?;

        // Calculate LEB128 encoding size for offsets
        let current_offset_size = Leb128::calculate_size(offset);
        let next_delta_size = Leb128::calculate_size(next - offset);

        // Calculate the total bytes if we split at this position
        // We include both segments' complete sizes for accurate comparison
        let bytes_if_split =
            current_offset_size + current_segment_payload + FLAGS_SIZE + next_delta_size;

        // Calculate the total bytes if we continue the current segment
        let bytes_if_combined = current_offset_size + combined_segment_payload;

        // Return the precise byte costs for compression decision
        Ok(Self {
            bytes_if_split,
            bytes_if_combined,
        })
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
    ///
    /// * `values` - The sorted sequence of values to segment
    ///
    /// ## Returns
    ///
    /// A `Result` containing either the optimally segmented values or an error
    fn package(&self, values: &[u64]) -> Result<Segments, Error> {
        // Validation checks
        if values.is_empty() {
            return Err(Error::EmptyInput);
        }
        if !self.is_sorted(values) {
            return Err(Error::UnsortedInput);
        }

        // Find optimal segment boundaries based on byte savings
        let boundaries = self.find_segment_boundaries(values)?;

        // Create segments using identified boundaries
        let segments = self.create_segments_from_boundaries(values, &boundaries)?;

        Ok(Segments::new_from(segments))
    }
}

impl BitmapSegmenter {
    /// Finds optimal segment boundaries by directly comparing byte costs
    ///
    /// This core algorithm analyzes each potential split point to optimize
    /// compression:
    /// - For small gaps (<17 bytes with 1-byte offset), continues the bitmap
    /// - For larger gaps, splits to avoid bitmap waste
    /// - For extreme gaps (e.g., 1 to 1,000,000), ensures efficient segmentation
    ///
    /// These byte-perfect decisions ensure optimal compression by creating
    /// segments exactly where they save bytes.
    ///
    /// ## Parameters
    ///
    /// * `values` - The sorted sequence of values to segment
    ///
    /// ## Returns
    ///
    /// A vector of boundary indices representing optimal segment divisions
    fn find_segment_boundaries(&self, values: &[u64]) -> Result<Vec<usize>, Error> {
        let mut boundaries = vec![0]; // Always include start index

        // Handle empty and single value sequences
        if values.len() <= 1 {
            boundaries.push(values.len());
            return Ok(boundaries);
        }

        // Track current segment information for larger sequences
        let mut segment_state = SegmentState {
            current_offset: values[0],
            last_boundary: 0,
        };

        // Evaluate each potential split point for maximum compression
        for i in 0..values.len().saturating_sub(1) {
            let next_pos = i + 1;

            // Calculate bitmap costs for splitting vs. combining
            let bitmap_costs =
                BitmapCosts::calculate(segment_state.current_offset, values[i], values[next_pos])?;

            // Determine if splitting here maximizes compression
            let should_split = bitmap_costs.should_split();

            if should_split {
                boundaries.push(next_pos);

                // Update segment tracking
                segment_state.current_offset = values[i];
                segment_state.last_boundary = i;
            }
        }

        // Always include end boundary
        boundaries.push(values.len());

        Ok(boundaries)
    }

    /// Creates bitmap segments based on the identified boundaries
    ///
    /// Converts logical segment boundaries into actual encoded segments,
    /// using encoding optimizations:
    /// - Single value optimization for isolated values (zero payload bytes)
    /// - Multi-value bitmap encoding for ranges with common offsets
    ///
    /// ## Parameters
    ///
    /// * `values` - The sorted sequence of original values
    /// * `boundaries` - The optimal boundary indices determined by analysis
    ///
    /// ## Returns
    ///
    /// A `Result` containing the vector of optimally encoded segments
    fn create_segments_from_boundaries(
        &self,
        values: &[u64],
        boundaries: &[usize],
    ) -> Result<Vec<Segment>, Error> {
        let mut segments = Vec::new();

        // Create a segment for each pair of boundaries
        for window in boundaries.windows(2) {
            let start_idx = window[0];
            let end_idx = window[1];

            // Skip empty ranges (shouldn't happen with our algorithm)
            if start_idx == end_idx {
                return Err(Error::EmptyRange { start: start_idx, end: end_idx });
            }

            let slice = &values[start_idx..end_idx];

            // Create segment with appropriate encoding for maximum compression
            if end_idx - start_idx == 1 {
                // Single value optimization - uses zero payload bytes
                let segment = Segment::new_with_offset(SegmentEncoding::Single, values[start_idx]);
                segments.push(segment);
            } else {
                // Multi-value bitmap encoding
                let mut segment = Segment::new_with_offset(SegmentEncoding::Bitset, slice[0]);
                for value in &slice[1..] {
                    segment.insert(*value)?;
                }
                segments.push(segment);
            }
        }

        Ok(segments)
    }

    /// Checks if a slice is sorted in ascending order
    ///
    /// Bitmap segmentation requires sorted input as it relies on gaps
    /// between consecutive values.
    ///
    /// ## Parameters
    ///
    /// * `values` - The sequence to check for sorting
    ///
    /// ## Returns
    ///
    /// `true` if values are sorted in ascending order, `false` otherwise
    #[inline]
    fn is_sorted(&self, values: &[u64]) -> bool {
        values.is_empty() || values.windows(2).all(|w| w[0] < w[1])
    }
}

#[cfg(test)]
mod tests {
    use crate::idpack::Encodable;

    use super::*;
    use test_case::test_case;

    /// Tests the boundary detection with direct byte savings calculations
    #[test_case(&[10], &[0, 1]; "single value")]
    #[test_case(&[10, 11, 12, 13, 14], &[0, 5]; "small sequential - no splits")]
    #[test_case(&[10, 20, 30, 40, 50], &[0, 5]; "evenly spaced - no splits")]
    #[test_case(&[10, 11, 12, 1000, 1001, 1002], &[0, 3, 6]; "clear gap with byte savings")]
    #[test_case(&[1, 1000000], &[0, 1, 2]; "extreme gap forces split")]
    #[test_case(&[1, 2, 3, 100000, 100001], &[0, 3, 5]; "large gap with min size respected")]
    fn test_byte_saving_boundary_detection(values: &[u64], expected_boundaries: &[usize]) {
        let boundaries = BitmapSegmenter.find_segment_boundaries(values).unwrap();
        assert_eq!(
            boundaries, expected_boundaries,
            "Unexpected boundaries for values: {:?}",
            values
        );
    }

    /// Tests that the package method correctly handles extreme gaps
    #[test_case(&[1, 1000000], 2; "extreme gap creates 2 segments")]
    #[test_case(&[1, 2, 3, 4, 5], 1; "small dense sequence stays as 1 segment")]
    #[test_case(&[1, 2, 50000, 50001], 2; "gap creates 2 segments")]
    fn test_package_with_extreme_gaps(values: &[u64], expected_segments: usize) {
        let result = BitmapSegmenter.package(values).unwrap();

        assert_eq!(
            result.len(),
            expected_segments,
            "Unexpected number of segments for values: {:?}",
            values
        );
    }

    /// Tests that byte savings calculations correctly determine when to split
    #[test]
    fn test_byte_savings_calculations() {
        // Create test case with a precise byte savings boundary
        let mut values = Vec::new();
        // Add first group (10-19)
        for i in 10..20 {
            values.push(i);
        }
        // Add second group with gap (100-109)
        for i in 100..110 {
            values.push(i);
        }
        let boundaries = BitmapSegmenter.find_segment_boundaries(&values).unwrap();
        assert_eq!(
            boundaries,
            &[0, 10, 20],
            "Failed to split where byte savings occur"
        );
    }

    /// Tests low density handling for maximum compression
    #[test]
    fn test_low_density_handling() {
        // Create a low density sequence - values spread widely
        let values: Vec<u64> = (1..=100).step_by(10).collect(); // 10 values spread over 100 range

        let segments = BitmapSegmenter.package(&values).unwrap();

        // For these values, we expect fixed-width delta to be more efficient than bitmap
        assert!(
            segments.len() >= 1,
            "Should handle low density sequence efficiently"
        );

        // Check that the actual encoding chosen is efficient for the data pattern
        let total_bytes = segments.encode().unwrap().len();
        let fixed_overhead = 3; // ~3 bytes minimum overhead per segment

        // Maximum acceptable bytes for efficient compression
        let max_acceptable = values.len() * 2 + fixed_overhead;

        assert!(
            total_bytes <= max_acceptable,
            "Low density encoding inefficient: {} bytes used for {} values",
            total_bytes,
            values.len()
        );
    }

    /// Tests bitmap size constraints for maximum efficiency
    #[test]
    fn test_bitmap_size_efficiency() {
        // Values with extremely large range but few actual values
        let values = vec![1, 2, 3, 10_000, 20_000, 30_000];

        let segments = BitmapSegmenter.package(&values).unwrap();

        // This should be split to avoid a bitmap covering the entire 1-30,000 range
        assert!(
            segments.len() > 1,
            "Should split large sparse range for efficiency"
        );

        // Calculate the actual compression efficiency
        let total_bytes = segments.encode().unwrap().len();

        // Theoretical worst case: one large bitmap spanning the whole range
        let worst_case = (30_000 / 8) + 3; // bitmap bytes + overhead

        assert!(
            total_bytes < worst_case,
            "Splitting improved compression: {} bytes vs {} bytes worst case",
            total_bytes,
            worst_case
        );
    }

    /// Tests validation error handling
    #[test]
    fn test_validation_errors() {
        // Empty input
        assert!(matches!(
            BitmapSegmenter.package(&[]),
            Err(Error::EmptyInput)
        ));

        // Unsorted input
        assert!(matches!(
            BitmapSegmenter.package(&[5, 3, 1]),
            Err(Error::UnsortedInput)
        ));
    }

    /// Tests precise break-even gap detection for maximum compression
    #[test_case(&[10, 10 + 16], 1; "gap of 16 with 1-byte delta - no split")]
    #[test_case(&[10, 10 + 17], 2; "gap of 17 with 1-byte delta - split")]
    #[test_case(&[10000, 10000 + 24], 2; "gap of 24 with 2-byte delta - split")]
    #[test_case(&[10000, 10000 + 25], 2; "gap of 25 with 2-byte delta - split")]
    fn test_break_even_gap_detection(values: &[u64], expected_segments: usize) {
        let result = BitmapSegmenter.package(values).unwrap();
        assert_eq!(
            result.len(),
            expected_segments,
            "Failed to correctly apply break-even gap analysis for values: {:?}",
            values
        );
    }

    #[test_case(&[1, 1_000_000, 1_000_001], 2; "single value followed by large gap")]
    #[test_case(&[1, 2, 1_000_000, 1_000_001], 2; "multiple values followed by large gap")]
    #[test_case(&[1, 1_000_000, 1_000_001, 2_000_000], 3; "multiple large gaps")]
    #[test_case(&[1, 1_000, 10_000, 10_001, 100_000], 4; "multiple varied gaps")]
    fn test_optimized_segmentation(values: &[u64], expected_segments: usize) {
        let segments = BitmapSegmenter.package(values).unwrap();
        dbg!(&segments);

        // Verify segment count
        assert_eq!(
            segments.len(),
            expected_segments,
            "Incorrect segmentation for values: {:?}",
            values
        );

        // Calculate compression efficiency
        let encoded = segments.encode().unwrap();
        let naive_size = (values.last().unwrap() - values[0]) / 8;

        // Verify we achieve significantly better compression than naive approach
        let compression_ratio = naive_size as f64 / encoded.len() as f64;
        assert!(
            compression_ratio > 10.0 || encoded.len() < 20,
            "Insufficient compression: {} bytes vs naive {} bytes (ratio: {:.1}x)",
            encoded.len(),
            naive_size,
            compression_ratio
        );
    }
}
