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
