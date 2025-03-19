use crate::{
    idpack::{Segment, Segments},
    leb128::Leb128,
};

use super::{Segmenter, SegmenterError};

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

        // Ensure input is sorted for bitmap segmentation
        if !values.is_sorted() {
            return Err(SegmenterError::UnsortedInput);
        }

        // Find optimal segment boundaries based on byte savings
        let boundaries = self.find_segment_boundaries(values);

        // Create segments using identified boundaries
        let segments = self.create_segments_from_boundaries(values, &boundaries)?;

        Ok(segments)
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

        // Track current segment information for larger sequences
        let mut segment_state = SegmentState {
            // SAFETY: we just ensured that `values` is not empty
            current_offset: values[0],
            last_boundary: 0,
        };

        // Iterate over pairs of previous and next values to calculate byte costs
        // and determine optimal split points
        for (pos, window) in values.windows(2).enumerate() {
            let [prev, next] = *window else {
                // This branch is unreachable with windows(2), but is needed
                // for the compiler to understand the pattern match.
                continue;
            };

            // Calculate bitmap costs for splitting vs. combining
            let bitmap_costs = BitmapCosts::calculate(segment_state.current_offset, prev, next);

            // Determine if splitting here maximizes compression
            let should_split = bitmap_costs.should_split();

            if should_split {
                // If we're splitting, then the next position is a start boundary
                // for the next segment
                boundaries.push(pos + 1);

                // `next` is the new segment's offset
                segment_state.current_offset = next;
                // Track the logical end of the current (now previous) segment
                segment_state.last_boundary = pos;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use test_case::test_case;

    /// Tests validation error handling
    #[test]
    fn test_validation_errors() {
        // Unsorted input
        assert_matches!(
            BitmapSegmenter.package(&[5, 3, 1]),
            Err(SegmenterError::UnsortedInput)
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
}
