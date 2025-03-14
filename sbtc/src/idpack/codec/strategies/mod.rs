pub mod bitset;
pub mod single;

use std::io::Cursor;

pub use bitset::BitsetStrategy;

use crate::idpack::{Segment, SegmentEncoding};

use super::{SegmentDecodeError, SegmentEncodeError};

// Define the encoding strategy trait
pub trait EncodingStrategy {
    /// Returns the base type flag for this encoding
    fn type_flag(&self) -> u8;

    /// Creates strategy-specific flags for the given segment
    /// Returns the complete flags byte including the base type flag
    fn create_flags(&self, segment: &Segment) -> u8;

    /// Returns the encoding type implemented by this strategy
    #[allow(unused)]
    fn encoding_type(&self) -> SegmentEncoding;

    /// Estimates the payload size in bytes (excluding headers)
    fn estimate_payload_size(&self, segment: &[u64]) -> Option<usize>;

    /// Encodes the segment values into bytes
    fn encode(
        &self,
        flags: u8,
        segment: &Segment,
        result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError>;

    /// Decodes bytes into values
    fn decode(
        &self,
        cursor: &mut Cursor<&[u8]>,
        flags: u8,
        offset: u64,
        values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError>;
}
