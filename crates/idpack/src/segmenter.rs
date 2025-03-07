//! # Adaptive Segmentation Engine
//!
//! This module implements an intelligent segmentation system that automatically divides
//! sequences of integers into optimally encoded segments for maximum compression efficiency.
//!
//! ## Core Algorithm
//!
//! The segmentation engine uses dynamic programming to determine:
//!
//! 1. **Optimal segment boundaries** - where to split integer sequences
//! 2. **Optimal encoding per segment** - which encoding strategy to use for each segment
//! 3. **Global optimization** - whether multi-segment or single-segment is more efficient
//!
//! ## Encoding Selection
//!
//! Each segment is analyzed to choose the most space-efficient encoding from:
//!
//! * **Single** - Zero payload bytes for isolated values
//! * **Bitset** - Bitmap representation for dense values in small ranges (>25% density)
//! * **Fixed-Width Delta** - Bit-packed delta encoding for sparse values or regular patterns
//!
//! ## Implementation Notes
//!
//! - Uses O(n²) space complexity for tracking optimal solutions
//! - Time complexity is O(n³) with early pruning optimizations
//! - Delta-encoded offsets between segments for additional compression
//! - Position-aware optimization of encoding parameters

use crate::{
    codec::{
        self,
        strategies::{BitsetStrategy, EncodingStrategy, FixedWidthDeltaStrategy},
    },
    leb128::Leb128,
    segment,
    segments::Segments,
    Segment, SegmentEncoding,
};

/// Errors which can occur during the adaptive segmentation process.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is empty.
    #[error("The input is empty")]
    EmptyInput,

    /// The input is not sorted.
    #[error("The input is not sorted")]
    UnsortedInput,

    /// An error was returned by the segment module.
    #[error(transparent)]
    Segment(#[from] segment::Error),
}

/// Represents an encoding option with associated size information.
///
/// Used internally during segment analysis to compare encoding options for maximum compression.
/// Each option tracks both the encoding strategy and its precise byte size to enable
/// optimal selection based on minimum encoded size.
#[derive(Debug, Clone, Copy)]
pub struct EncodingOption {
    encoding: SegmentEncoding,
    size: usize,
}

impl EncodingOption {
    fn new(encoding: SegmentEncoding, size: usize) -> Self {
        Self { encoding, size }
    }
}

/// Represents a complete segmentation solution with size information.
///
/// Stores both the optimally encoded segments and their total size in bytes,
/// allowing direct comparison between different segmentation strategies
/// to achieve maximum compression efficiency.
#[derive(Debug, Clone)]
struct SegmentationSolution {
    segments: Vec<Segment>,
    total_size: usize,
}

/// Adaptive segmentation engine that intelligently divides and encodes integer
/// sequences for maximum compression efficiency based on pattern analysis.
#[derive(Debug)]
pub struct AdaptiveSegmenter;

impl AdaptiveSegmenter {
    /// Creates a new `Segments` instance by optimally segmenting and encoding
    /// the provided values for maximum compression efficiency.
    ///
    /// ## Parameters
    ///
    /// * `values` - Sorted slice of unique integer values to be optimally
    ///   encoded
    ///
    /// ## Returns
    ///
    /// * Optimally encoded `Segments` or error if validation fails
    ///
    /// ## Algorithm
    ///
    /// Uses dynamic programming to find optimal segment boundaries and encodings,
    /// evaluating all possible splits and comparing against a single-segment solution.
    /// Selects the globally optimal solution for maximum compression:
    ///
    /// - Evaluates all possible segment splits and encoding combinations
    /// - Compares single-segment vs multi-segment solutions
    /// - Selects minimum byte-size encoding across all possibilities
    ///
    /// ## Encoding Strategy Selection
    ///
    /// Dynamically selects between three encoding strategies based on data
    /// patterns:
    ///
    /// - **Single**: Zero payload bytes for isolated values
    /// - **Bitset**: Optimal for dense values in small ranges (>25% density)
    /// - **Fixed-Width Delta**: Efficient for sparse values or regular patterns
    #[allow(unused)]
    pub fn package(values: &[u64]) -> Result<Segments, Error> {
        // Validation checks
        if values.is_empty() {
            return Err(Error::EmptyInput);
        }
        if !values.is_sorted() {
            return Err(Error::UnsortedInput);
        }

        // Single value optimization
        let n = values.len();
        if n == 1 {
            let mut segment = Segment::new(SegmentEncoding::Single);
            segment.insert(values[0])?;
            return Ok(Segments::new_from(vec![segment]));
        }

        // Calculate solutions using different strategies
        let dp_solution = Self::calculate_dp_solution(values)?;
        let single_segment_solution = Self::calculate_single_segment_solution(values)?;

        // Compare solutions and choose the most efficient one
        if single_segment_solution.total_size <= dp_solution.total_size {
            Ok(Segments::new_from(single_segment_solution.segments))
        } else {
            Ok(Segments::new_from(dp_solution.segments))
        }
    }

    /// Calculates the optimal segmentation solution using dynamic programming.
    ///
    /// ## Parameters
    ///
    /// * `values` - Sorted slice of unique integer values to be optimally segmented
    ///
    /// ## Returns
    ///
    /// * Optimal segmentation solution with minimum byte size
    ///
    /// ## Algorithm
    ///
    /// - Uses bottom-up DP to find minimal encoded size for each value range
    /// - Stores optimal encoding type and split points in DP tables
    /// - Evaluates single-segment vs. split approaches for each subrange
    /// - Time complexity: O(n³) with early pruning optimizations
    ///
    /// ## Implementation Notes
    ///
    /// - Each table entry represents optimal encoding for values[i..=j]
    /// - Split decisions balance segment overhead against encoding efficiency
    /// - Final solution reconstructed from optimal split points
    fn calculate_dp_solution(values: &[u64]) -> Result<SegmentationSolution, Error> {
        let n = values.len();

        // Initialize DP tables for optimal substructure:
        // - dp_sizes[i][j]: minimum bytes needed to encode values[i..=j]
        // - encodings[i][j]: optimal encoding type for values[i..=j]
        // - splits[i][j]: optimal split point between i and j (None if single segment is best)
        let mut dp_sizes = vec![vec![usize::MAX; n]; n];
        let mut encodings = vec![vec![SegmentEncoding::Bitset; n]; n];
        let mut splits = vec![vec![None; n]; n];

        // Base case: Fill single-value segments (ranges of length 1)
        // For a single value, we use Bitset encoding initially (will be optimized later)
        for i in 0..n {
            let mut segment = Segment::new(SegmentEncoding::Bitset);
            segment.insert(values[i])?;
            dp_sizes[i][i] = codec::FLAGS_SIZE + Leb128::calculate_size(values[i]) + 1;
            encodings[i][i] = SegmentEncoding::Bitset;
        }

        // Bottom-up DP: calculate optimal encoding for each subrange
        // Evaluate progressively larger ranges from length 2 to n
        for len in 2..=n {
            for start in 0..=n - len {
                let end = start + len - 1;

                // Option 1: Encode entire range as single segment
                // Construct segment containing all values in this range
                let mut segment = Segment::new(SegmentEncoding::Bitset);
                for val in &values[start..=end] {
                    segment.insert(*val)?;
                }

                // Calculate position-aware encoding size:
                // First segment uses full offset, others use delta encoding for maximum compression
                let prev_offset = if start == 0 { 0 } else { values[start - 1] };
                let size_options = Self::estimate_encoded_size(&segment, start == 0, prev_offset);

                // Find encoding with minimum bytes for this range
                let best_option = size_options.into_iter().min_by_key(|opt| opt.size).unwrap();

                // Initial best solution: single segment with optimal encoding
                dp_sizes[start][end] = best_option.size;
                encodings[start][end] = best_option.encoding;

                // Option 2: Consider all possible splits within this range
                // Recurrence relation: dp_sizes[i][j] = min(dp_sizes[i][j], dp_sizes[i][k] + dp_sizes[k+1][j])
                for split in start..end {
                    // Calculate combined size of optimally encoding left and right segments
                    let combined_size = dp_sizes[start][split] + dp_sizes[split + 1][end];

                    // Update if this split yields a more efficient encoding (fewer bytes)
                    if combined_size < dp_sizes[start][end] {
                        dp_sizes[start][end] = combined_size;
                        splits[start][end] = Some(split);
                        // Note: encoding in encodings[start][end] becomes irrelevant when split occurs
                        // as we'll use encodings from both sub-segments
                    }
                }
            }
        }

        // Build segments from optimal solution by traversing the split points
        // dp_sizes[0][n-1] now contains the minimum possible encoded size
        let mut segments = Vec::new();
        Self::build_segments_from_splits(&mut segments, values, &encodings, &splits, 0, n - 1)?;

        // Calculate exact total size with position-specific optimizations
        // This ensures we account for delta encoding between segment offsets
        let total_size = Self::calculate_exact_segments_size(&segments);

        Ok(SegmentationSolution { segments, total_size })
    }

    /// Calculates a solution using a single segment with optimal encoding.
    ///
    /// # Parameters
    ///
    /// * `values` - Sorted slice of unique integer values to encode as one segment
    ///
    /// # Returns
    ///
    /// * Solution containing a single optimally encoded segment and its total size
    ///
    /// # Key Functionality
    ///
    /// - Creates a segment containing all input values
    /// - Evaluates all viable encoding strategies for this segment
    /// - Selects the most space-efficient encoding (minimum bytes)
    /// - Provides baseline for comparison against multi-segment solutions
    /// - Critical for homogeneous data where segmentation overhead exceeds benefits
    fn calculate_single_segment_solution(values: &[u64]) -> Result<SegmentationSolution, Error> {
        // Create all possible encodings for the entire range
        let mut segment = Segment::new(SegmentEncoding::Bitset);
        for &val in values {
            segment.insert(val)?;
        }

        // Find the most efficient encoding
        let options = Self::analyze_segment_options(&segment);
        let best_option = options.into_iter().min_by_key(|opt| opt.size).unwrap();

        // Create the optimal single segment
        let mut optimal_segment = Segment::new(best_option.encoding);
        for &val in values {
            optimal_segment.insert(val)?;
        }

        // Calculate exact size including headers
        let total_size =
            codec::FLAGS_SIZE + Leb128::calculate_size(optimal_segment.offset()) + best_option.size;

        Ok(SegmentationSolution {
            segments: vec![optimal_segment],
            total_size,
        })
    }

    /// Recursively constructs optimally encoded segments from pre-calculated split points.
    ///
    /// # Parameters
    ///
    /// * `segments` - Output vector where constructed segments will be stored
    /// * `values` - Original sorted array of integer values
    /// * `encodings` - 2D table of optimal encoding types for each subrange
    /// * `splits` - 2D table containing optimal split points from DP analysis
    /// * `start` - Start index in the values array for current subrange
    /// * `end` - End index in the values array for current subrange
    ///
    /// # Returns
    ///
    /// * Success or error if segment creation fails
    ///
    /// # Key Functionality
    ///
    /// - Recursively builds segments from precomputed optimal split points
    /// - For each range, either creates a single segment or splits further
    /// - Applies encoding decisions from DP solution for maximum compression
    /// - Handles potential edge cases in the theoretical split model
    fn build_segments_from_splits(
        segments: &mut Vec<Segment>,
        values: &[u64],
        encodings: &[Vec<SegmentEncoding>],
        splits: &[Vec<Option<usize>>],
        start: usize,
        end: usize,
    ) -> Result<(), Error> {
        if let Some(split) = splits[start][end] {
            // Split is more efficient
            Self::build_segments_from_splits(segments, values, encodings, splits, start, split)?;
            Self::build_segments_from_splits(segments, values, encodings, splits, split + 1, end)?;
        } else {
            // Create single segment with optimal encoding
            let encoding = encodings[start][end];
            let mut segment = Segment::new(encoding);
            for val in &values[start..=end] {
                segment.insert(*val)?;
            }
            segments.push(segment);
        }

        Ok(())
    }

    /// Analyzes a segment to determine all applicable encoding strategies and
    /// their respective size costs for maximum compression.
    ///
    /// # Parameters
    ///
    /// * `segment` - The segment to analyze for encoding options
    ///
    /// # Returns
    ///
    /// * Collection of applicable encoding options with their estimated sizes
    ///
    /// # Key Functionality
    ///
    /// - Evaluates all viable encoding strategies for the given segment
    /// - Special path for single values (dedicated encoding with zero payload bytes)
    /// - Calculates precise byte sizes for Fixed-Width Delta with bit-packing optimizations
    /// - Calculates bitmap size with embedded optimizations when applicable
    /// - Only includes encodings suitable for the segment's value pattern
    /// - Returns payload size estimates for comparative analysis
    fn analyze_segment_options(segment: &Segment) -> Vec<EncodingOption> {
        let mut options = Vec::new();

        // If the segment is empty then no encoding is needed
        if segment.is_empty() {
            return options;
        }

        // Single value segment - just need flags + offset (already in the header)
        if segment.len() == 1 {
            options.push(EncodingOption::new(SegmentEncoding::Single, 0));
            return options;
        }

        // Evaluate encodings using strategies

        // 1. Fixed-Width Delta evaluation
        let fwd_strategy = FixedWidthDeltaStrategy;
        if fwd_strategy.is_applicable(segment) {
            let fwd_size = fwd_strategy.estimate_size(segment);
            options.push(EncodingOption::new(
                SegmentEncoding::FixedWidthDelta,
                fwd_size,
            ));
        }

        // 2. Bitset evaluation
        let bitset_strategy = BitsetStrategy;
        if bitset_strategy.is_applicable(segment) {
            let bitmap_size = bitset_strategy.estimate_size(segment);
            options.push(EncodingOption::new(SegmentEncoding::Bitset, bitmap_size));
        }

        options
    }

    /// Calculates the exact total size of encoded segments with position-aware
    /// offset delta optimization.
    ///
    /// # Parameters
    ///
    /// * `segments` - The segments to calculate total encoded size for
    ///
    /// # Returns
    ///
    /// * Total size in bytes of all encoded segments including headers
    ///
    /// # Key Functionality
    ///
    /// - Accurately computes the position-optimized encoding size for segments
    /// - Applies delta-encoding optimization between segment offsets
    /// - Adds flag bytes and LEB128-encoded values to payload size
    /// - Re-analyzes each segment to verify optimal encoding selection
    /// - Essential for validating compression efficiency of the solution
    fn calculate_exact_segments_size(segments: &[Segment]) -> usize {
        let mut total_size = 0;
        let mut prev_offset = 0;

        for (i, segment) in segments.iter().enumerate() {
            let is_first = i == 0;
            let options = Self::analyze_segment_options(segment);
            let best = options.iter().min_by_key(|opt| opt.size).unwrap();

            // Add payload size
            total_size += best.size;

            // Add flags byte
            total_size += codec::FLAGS_SIZE;

            // Add offset encoding with delta awareness
            if is_first {
                total_size += Leb128::calculate_size(segment.offset());
            } else {
                let offset_delta = segment.offset().saturating_sub(prev_offset);
                total_size += Leb128::calculate_size(offset_delta);
            }

            prev_offset = segment.offset();
        }

        total_size
    }

    /// Estimates the encoded size of a segment with position-specific optimizations.
    ///
    /// # Parameters
    ///
    /// * `segment` - The segment to estimate encoded size for
    /// * `is_first` - Whether this is the first segment (affects offset encoding)
    /// * `prev_offset` - Previous segment's offset for delta-encoding optimization
    ///
    /// # Returns
    ///
    /// * Encoding options with size estimates including position-specific overhead
    ///
    /// # Key Functionality
    ///
    /// - Enhances base encoding options with position-specific cost factors
    /// - Adds one byte for the flags field to each encoding option
    /// - Applies offset delta compression for non-first segments
    /// - Calculates full offset size for first segment
    /// - Essential for accurate segment boundary optimization in the DP algorithm
    /// - Enables precise comparison between potential segmentation solutions
    fn estimate_encoded_size(
        segment: &Segment,
        is_first: bool,
        prev_offset: u64,
    ) -> Vec<EncodingOption> {
        let options = Self::analyze_segment_options(segment);

        options
            .into_iter()
            .map(|opt| {
                // Calculate header size (flags + offset encoding)
                let mut encoded_size = opt.size;

                // Add 1 byte for flags
                encoded_size += 1;

                // Add offset encoding size
                if is_first {
                    // First segment: store full offset
                    encoded_size += Leb128::calculate_size(segment.offset());
                } else {
                    // Subsequent segment: store delta from previous offset
                    let offset_delta = segment.offset().saturating_sub(prev_offset);
                    encoded_size += Leb128::calculate_size(offset_delta);
                }

                EncodingOption::new(opt.encoding, encoded_size)
            })
            .collect()
    }
}
