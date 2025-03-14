mod bitmap;

use crate::Leb128;

use super::codec::strategies::single::SingleValueStrategy;
use super::codec::strategies::BitsetStrategy;
use super::codec::strategies::EncodingStrategy;
use super::codec::FLAGS_SIZE;
use super::segment;
use super::segments::Segments;
use super::SegmentEncoding;

pub use bitmap::BitmapSegmenter;

/// Errors which can occur during the adaptive segmentation process.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is empty.
    #[error("the input is empty")]
    EmptyInput,

    /// The input is not sorted.
    #[error("the input is not sorted")]
    UnsortedInput,

    /// The input contains duplicate values.
    #[error("the input contains duplicate values")]
    DuplicateValue(usize),

    /// An error was returned by the segment module.
    #[error(transparent)]
    Segment(#[from] segment::Error),

    /// An error occurred during size estimation.
    #[error("error estimating segment size")]
    SizeEstimation,

    #[error("the segmenter encountered an empty range: {start} to {end}")]
    EmptyRange { start: usize, end: usize },
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
    fn package(&self, values: &[u64]) -> Result<Segments, Error>;

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
    fn estimate_size(&self, values: &[u64]) -> Result<usize, Error> {
        // Generate optimally segmented values using our boundary detection algorithm
        let segments = self.package(values)?;

        // Track the previous segment offset for delta encoding
        let mut previous_offset = 0;

        // Calculate the precise byte size with optimal compression
        let encoded_size = segments.iter().try_fold(0, |total_bytes, segment| {
            // Calculate delta-encoded offset size using LEB128
            let delta = segment.offset().saturating_sub(previous_offset);
            let offset_size = Leb128::calculate_size(delta);

            // Get the payload size using the strategy's own estimation
            // calculations
            let payload_size_estimate = match segment.encoding() {
                SegmentEncoding::Bitset => BitsetStrategy
                    .estimate_payload_size(segment.as_slice())
                    .ok_or(Error::SizeEstimation)?,
                SegmentEncoding::Single => SingleValueStrategy
                    .estimate_payload_size(segment.as_slice())
                    .ok_or(Error::SizeEstimation)?,
            };

            // Update previous offset for next iteration
            previous_offset = segment.offset();

            // Add this segment's total bytes to the accumulator
            Ok(total_bytes + FLAGS_SIZE + offset_size + payload_size_estimate)
        });

        encoded_size
    }
}
