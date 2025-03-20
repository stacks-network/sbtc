mod bitmap;

use super::segments::Segments;
use super::{segment, segments};

pub use bitmap::BitmapSegmenter;

/// Errors which can occur during the adaptive segmentation process.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum SegmenterError {
    /// The input values are not sorted or contain duplicates.
    #[error("input must be sorted and contain unique values")]
    InvalidSequence,

    /// An error was returned by the segment module.
    #[error(transparent)]
    Segment(#[from] segment::SegmentError),

    /// An error was returned by the segments module.
    #[error(transparent)]
    Segments(#[from] segments::SegmentsError),

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

    /// Estimates the total packaged and encoded size in bytes.
    ///
    /// ## Parameters
    /// * `values` - The sequence of values to estimate size for
    ///
    /// ## Returns
    /// * `Ok(size)` - The estimated size in bytes that would be used when
    ///   encoding
    /// * `Err(error)` - Upon encountering an error during estimation
    fn estimate_size(&self, values: &[u64]) -> Result<usize, SegmenterError>;
}
