//! Segment encoding implementation with maximum compression optimizations.
//!
//! This module provides efficient encoding of integer segments using
//! delta compression between segments, specialized encoding strategies,
//! and continuation flags for seamless multi-segment chaining.
//!
//! The encoder automatically selects the optimal encoding strategy based on
//! segment patterns and applies position-aware optimizations to minimize
//! the encoded size.

use crate::idpack::{Segment, SegmentEncoding, Segments};
use crate::leb128::Leb128;

use super::strategies::single::SingleValueStrategy;
use super::strategies::{BitsetStrategy, EncodingStrategy};
use super::{Encodable, SegmentEncodeError};

/// Implementation of encoding for segment collections with delta-optimization.
///
/// Encodes multiple segments sequentially with advanced optimizations:
/// - Delta-encoding offsets between adjacent segments
/// - Continuation flags for indicating additional segments
/// - Encoding type and strategy-specific flags in each segment
impl Encodable for Segments {
    /// Encodes a collection of segments into a byte vector.
    ///
    /// Applies position-aware optimizations to maximize compression efficiency.
    fn encode(&self) -> Result<Vec<u8>, SegmentEncodeError> {
        let mut result = Vec::new();

        if self.is_empty() {
            return Err(SegmentEncodeError::NoSegments);
        }

        let mut prev_offset = 0; // Track previous offset for delta calculation

        for (i, segment) in self.iter().enumerate() {
            // Determine segment position for flags and offset encoding
            let has_more = i < self.len() - 1; // Set continuation flag if not last segment
            let is_first = i == 0; // First segment needs absolute offset

            // Calculate offset to encode: absolute for first segment, delta for others
            // This is a critical compression optimization that reduces bytes needed
            // when segments have similar offsets
            let encoded_offset = if is_first {
                segment.offset() // First segment uses absolute offset
            } else {
                segment.offset().saturating_sub(prev_offset) // Delta encoding for savings
            };

            // Encode segment with appropriate offset and continuation flag
            let segment_bytes = encode_segment_with_offset(segment, has_more, encoded_offset)?;
            result.extend(segment_bytes);

            // Update previous offset for next segment's delta calculation
            prev_offset = segment.offset();
        }

        Ok(result)
    }
}

/// Encodes a single segment with the provided offset value and continuation flag.
///
/// Applies encoding strategy specific to the segment's type and adds the
/// necessary flags for maximum compression.
///
/// # Parameters
///
/// * `segment` - The segment to encode
/// * `has_continuation` - Whether more segments follow (sets flag)
/// * `offset` - Offset value to encode (absolute for first, delta for others)
///
/// # Returns
///
/// * Encoded bytes for this segment
fn encode_segment_with_offset(
    segment: &Segment,
    has_continuation: bool,
    offset: u64,
) -> Result<Vec<u8>, SegmentEncodeError> {
    // Return an error if the segment is empty (shouldn't happen)
    if segment.is_empty() {
        return Err(SegmentEncodeError::EmptySegment);
    }

    let mut result = Vec::new();

    // Create flags byte with type, optimization bits, and continuation flag
    let flags = create_flags_byte(segment, has_continuation)?;
    result.push(flags);

    // Add offset value using LEB128 variable-length encoding for maximum
    // compression LEB128 uses fewer bytes for smaller values, enhancing delta
    // encoding benefits
    Leb128::encode_into(offset, &mut result);

    // Add encoding-specific payload based on segment type
    match segment.encoding() {
        SegmentEncoding::Bitset => {
            // Bitmap-based encoding for dense ranges
            // Pass flags (without continuation bit) to access optimization bits
            BitsetStrategy.encode(flags & !super::FLAG_CONTINUATION, segment, &mut result)?;
        }
        SegmentEncoding::Single => {
            // No payload needed for single value encoding
            // Value is already encoded in the offset field - maximum compression
        }
    }

    Ok(result)
}

/// Creates a flags byte for a segment, incorporating continuation flag if
/// needed.
///
/// Combines encoding type, strategy-specific optimization flags, and
/// continuation indicators into a single byte for maximum compression.
///
/// # Parameters
///
/// * `segment` - The segment to create flags for
/// * `has_continuation` - Whether more segments follow this one
///
/// # Returns
///
/// * Combined flags byte with all encodings and indicators
fn create_flags_byte(segment: &Segment, has_continuation: bool) -> Result<u8, SegmentEncodeError> {
    // Select appropriate strategy based on segment encoding type
    let strategy: Box<dyn EncodingStrategy> = match segment.encoding() {
        SegmentEncoding::Bitset => Box::new(BitsetStrategy),
        SegmentEncoding::Single => Box::new(SingleValueStrategy),
    };

    // Get base type flag (bits 0-1) and strategy-specific flags (bits 2-6)
    let type_flag = strategy.type_flag(); // Indicates encoding type
    let strategy_flags = strategy.create_flags(segment); // Optimization bits

    // Verify strategy flags don't use reserved bits to maintain encoding integrity
    if strategy_flags & !super::ENCODING_FLAGS_MASK != 0 {
        return Err(SegmentEncodeError::InvalidStrategyFlags(
            strategy_flags,
            super::ENCODING_FLAGS_MASK,
        ));
    }

    // Combine encoding type with strategy-specific optimization flags
    let mut flags = type_flag | strategy_flags;

    // Add continuation flag (bit 7) if needed
    if has_continuation {
        flags |= super::FLAG_CONTINUATION;
    }

    Ok(flags)
}
