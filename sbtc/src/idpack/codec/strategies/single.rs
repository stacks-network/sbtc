//! Implements the Single Value encoding strategy.
//!
//! This strategy provides zero-byte payload encoding for segments containing
//! exactly one value. The value is encoded entirely as the segment's offset,
//! making it the most space-efficient encoding possible for isolated values.

use std::io::Cursor;

use crate::idpack::{codec, Segment, SegmentEncoding};

use super::EncodingStrategy;
use super::SegmentDecodeError;
use super::SegmentEncodeError;

/// Implementation of the Single Value encoding strategy.
///
/// This strategy encodes a segment containing exactly one value with zero
/// additional payload bytes. The value is encoded entirely within the offset
/// field of the segment header, providing maximum compression efficiency
/// for isolated values.
pub struct SingleValueStrategy;

impl EncodingStrategy for SingleValueStrategy {
    /// Returns the type flag indicating Single Value encoding (00).
    fn type_flag(&self) -> u8 {
        codec::TYPE_SINGLE
    }

    /// Creates the flags byte for Single Value encoding.
    ///
    /// Single encoding doesn't use any specialized flags since it has no
    /// configuration options or optimizations.
    fn create_flags(&self, _segment: &Segment) -> u8 {
        self.type_flag()
    }

    /// Returns the encoding type enum variant for this strategy.
    fn encoding_type(&self) -> SegmentEncoding {
        SegmentEncoding::Single
    }

    /// Estimates the size of the encoded payload in bytes.
    ///
    /// Always returns 0 for Single Value encoding since the value is
    /// stored entirely in the offset with no additional payload bytes.
    fn estimate_payload_size(&self, values: &[u64]) -> Option<usize> {
        // Single value encoding has no payload - value is contained in the
        // offset.
        if values.len() == 1 {
            return Some(0);
        }

        None
    }

    /// Encodes the segment into the result vector.
    ///
    /// For Single Value encoding, this is a no-op since the value is already
    /// encoded in the segment offset field.
    fn encode(
        &self,
        _flags: u8,
        _segment: &Segment,
        _result: &mut Vec<u8>,
    ) -> Result<(), SegmentEncodeError> {
        // No additional encoding needed - value = offset
        Ok(())
    }

    /// Decodes a Single Value encoded segment.
    ///
    /// For Single Value encoding, simply adds the offset value to the result
    /// vector without reading any additional payload bytes.
    fn decode(
        &self,
        _cursor: &mut Cursor<&[u8]>,
        _flags: u8,
        _offset: u64,
        _values: &mut Vec<u64>,
    ) -> Result<(), SegmentDecodeError> {
        Ok(())
    }

    /// Determines if this strategy is applicable for the given segment.
    ///
    /// Single Value encoding is only applicable for segments containing
    /// exactly one value.
    fn is_applicable(&self, values: &[u64]) -> bool {
        values.len() == 1
    }
}
