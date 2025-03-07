//! Segment decoding implementation with compression-optimized routines.
//!
//! This module handles the decoding of compressed integer segments using
//! various encoding strategies, each optimized for specific data patterns.
//! It implements delta-offset optimization between segments and supports
//! multiple segment decoding with continuation flags.

use std::io::{Cursor, Read};

use crate::codec::strategies::{EncodingStrategy, FixedWidthDeltaStrategy};
use crate::leb128::ReadLeb128;
use crate::segments::Segments;
use crate::{Segment, SegmentEncoding};

use super::strategies::BitsetStrategy;
use super::{Decodable, SegmentDecodeError};

/// Implements decoding from bytes into a collection of optimally encoded segments.
///
/// Handles empty input gracefully by returning an empty segments collection.
impl Decodable for Segments {
    /// Decodes a byte array into a Segments collection.
    ///
    /// Processes the entire byte array, ensuring all segments are properly
    /// decoded with their respective encoding strategies.
    fn decode(bytes: &[u8]) -> Result<Self, SegmentDecodeError> {
        // Fast path for empty input - return empty segments
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        // Decode all segments from the byte array
        let segments = decode_segments(bytes)?;

        // Construct the final Segments collection
        Ok(Self::new_from(segments))
    }
}

/// Decodes all segments from a byte array with continuation flag handling.
///
/// Processes segments sequentially until reaching the end of input or
/// encountering a segment without the continuation flag set.
pub fn decode_segments(bytes: &[u8]) -> Result<Vec<Segment>, SegmentDecodeError> {
    if bytes.is_empty() {
        return Err(SegmentDecodeError::EmptyInput);
    }

    let mut cursor = Cursor::new(bytes);
    let mut segments = Vec::new();
    let mut prev_offset = 0; // Tracks previous segment's offset for delta decoding
    let mut is_first = true; // First segment uses absolute offset encoding

    // Process segments sequentially, tracking continuation flags
    while cursor.position() < bytes.len() as u64 {
        // Read next segment with position-aware offset handling
        let (segment, has_more) = read_segment_into(&mut cursor, prev_offset, is_first)?;

        // Update state for next segment
        prev_offset = segment.offset();
        is_first = false;
        segments.push(segment);

        // Stop if no more segments indicated
        if !has_more {
            break;
        }
    }

    // Ensure we've consumed exactly the right amount of data
    // NOTE: Would need to remove this for stream decoding
    if cursor.position() as usize != bytes.len() {
        return Err(SegmentDecodeError::UnexpectedEndOfData);
    }

    Ok(segments)
}

/// Reads a single segment from the cursor with delta-offset optimization.
///
/// For maximum compression:
/// - First segment's offset is absolute
/// - Subsequent segments use delta offsets from the previous segment
pub fn read_segment_into(
    cursor: &mut Cursor<&[u8]>,
    prev_offset: u64,
    is_first: bool,
) -> Result<(Segment, bool), SegmentDecodeError> {
    // Read flags byte containing encoding type and optimization flags
    let mut flag_buffer = [0u8; 1];
    cursor
        .read_exact(&mut flag_buffer)
        .map_err(SegmentDecodeError::IO)?;
    let flags = flag_buffer[0];

    // Extract continuation flag (whether more segments follow)
    let has_continuation = (flags & super::FLAG_CONTINUATION) != 0;

    // Extract encoding type from the lower bits
    let encoding_type = flags & super::ENCODING_TYPE_MASK;

    // Map binary encoding type to segment encoding enum
    let segment_encoding = match encoding_type {
        super::TYPE_BITSET => SegmentEncoding::Bitset,
        super::TYPE_FW_DELTA => SegmentEncoding::FixedWidthDelta,
        super::TYPE_SINGLE => SegmentEncoding::Single,
        _ => return Err(SegmentDecodeError::UnrecognizedEncoding(encoding_type)),
    };

    // Read LEB128-encoded offset value
    let encoded_offset = cursor.read_leb128()?;

    // Apply delta decoding for non-first segments to maximize compression
    let actual_offset = if is_first {
        encoded_offset // First segment uses absolute offset
    } else {
        // Delta from previous segment's offset
        prev_offset
            .checked_add(encoded_offset)
            .ok_or(SegmentDecodeError::IntegerOverflow)?
    };

    // Initialize segment with correct encoding and offset
    let mut segment = Segment::new_with_offset(segment_encoding, actual_offset);

    // Collect decoded values (start with the offset)
    let mut values = Vec::new();
    values.push(actual_offset); // Push offset as first value

    // Decode payload using the appropriate strategy
    match encoding_type {
        // Bitmap-based encoding for dense ranges
        super::TYPE_BITSET => {
            BitsetStrategy.decode(
                cursor,
                flags & !super::FLAG_CONTINUATION,
                actual_offset,
                &mut values,
            )?;
        }

        // Fixed-width delta encoding for sparse/regular sequences
        super::TYPE_FW_DELTA => {
            FixedWidthDeltaStrategy.decode(
                cursor,
                flags & !super::FLAG_CONTINUATION,
                actual_offset,
                &mut values,
            )?;
        }

        // Single-value encoding for isolated values
        super::TYPE_SINGLE => {
            // No additional processing needed for single value encoding
            // (value is already in the offset)
        }

        // Unknown encoding type - should never happen for valid data
        _ => return Err(SegmentDecodeError::UnrecognizedEncoding(encoding_type)),
    }

    // Add decoded values to segment (skipping offset which was already set)
    for &value in values.iter().skip(1) {
        segment.insert(value)?;
    }

    // Return the constructed segment and whether there are more segments
    Ok((segment, has_continuation))
}
