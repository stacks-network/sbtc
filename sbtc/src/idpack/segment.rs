//! Segment encoding for withdrawal IDs with guaranteed invariants.
//!
//! # Safety Invariants
//!
//! A `Segment` maintains critical invariants at all times:
//! - **Never empty**: Always contains at least one value (the offset)
//! - **Always sorted**: Values are in strictly ascending order
//! - **No duplicates**: Each value appears exactly once
//!
//! These invariants are enforced by the API and enable optimized encoding and
//! safe access without bounds checking in critical paths.

use std::fmt::Debug;

/// Error types that can occur when working with segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Values must be in strictly ascending order.
    /// Provides the value that violated the ordering constraint.
    #[error("Value {0} is out of order (must be inserted in strictly ascending order)")]
    UnsortedValue(u64),

    /// Each value must appear exactly once.
    /// Provides the duplicate value for diagnostic purposes.
    #[error("Duplicate value {0} detected (each value must be unique)")]
    DuplicateValue(u64),
}

/// Represents the encoding method used for a segment of integer values.
/// Each encoding strategy is optimized for different data patterns.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SegmentEncoding {
    /// Zero payload bytes - value encoded entirely as segment's offset.
    /// Optimal for isolated values.
    Single,

    /// Encodes integers as bits in a bitmap with a base offset.
    /// Optimal for dense values within small ranges (>25% density).
    Bitset,
}

impl std::fmt::Display for SegmentEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

/// Represents a segment of integer values encoded with a specific method.
/// Facilitates pattern-based optimal compression.
///
/// # Safety Invariants
/// - Contains at least one value (offset) at all times
/// - Values are always sorted in strictly ascending order
/// - No duplicate values are allowed
#[derive(Clone)]
pub struct Segment {
    encoding: SegmentEncoding,
    values: Vec<u64>,
}

impl Segment {
    /// Creates a new segment with the specified encoding and initial offset
    /// value. The offset is crucial for compression as it establishes the base
    /// value for the segment.
    pub fn new_with_offset(encoding: SegmentEncoding, offset: u64) -> Self {
        Self { encoding, values: vec![offset] }
    }

    /// Returns the offset (first value) of the segment.
    pub fn offset(&self) -> u64 {
        // SAFETY: `values` is never empty due to struct invariants
        self.values[0]
    }

    /// Returns the encoding method used for this segment.
    pub fn encoding(&self) -> SegmentEncoding {
        self.encoding
    }

    /// Inserts a value into the segment, requiring that values are sorted and
    /// unique.
    ///
    /// ## Errors
    /// - Duplicate values (`DuplicateValue`)
    /// - Unsorted values (`UnsortedInput`)
    pub fn insert(&mut self, value: u64) -> Result<(), Error> {
        // Validate that the new value is greater than the last value (sorted)
        // SAFETY: `values` is never empty due to struct invariants
        if value < self.values[self.values.len() - 1] {
            return Err(Error::UnsortedValue(value));
        }

        // Validate that the new value doesn't equal the current last value (deduplicated)
        // SAFETY: `values` is never empty due to struct invariants
        if value == self.values[self.values.len() - 1] {
            return Err(Error::DuplicateValue(value));
        }

        // Add the value to the segment
        self.values.push(value);

        Ok(())
    }

    /// Gets a slice of all values in the segment, including the offset.
    pub fn as_slice(&self) -> &[u64] {
        &self.values
    }

    /// Gets a slice of all values in the segment, excluding the offset.
    /// Returns an empty slice if there are no values beyond the offset.
    pub fn values(&self) -> &[u64] {
        if self.values.is_empty() {
            return &[];
        }

        &self.values[1..]
    }

    /// Returns the number of values in the segment (including offset).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns the number of values excluding the offset.
    /// Important for encoding decisions and payload size calculations.
    pub fn value_count(&self) -> usize {
        self.values.len().saturating_sub(1)
    }

    /// Returns `true` if segment contains values beyond the offset.
    pub fn has_values(&self) -> bool {
        self.value_count() > 0
    }

    /// Returns span of the segment (maximum value - offset).
    pub fn range(&self) -> u64 {
        self.max() - self.offset()
    }

    /// Returns the greatest value in the segment.
    pub fn max(&self) -> u64 {
        // SAFETY: `values` is never empty due to struct invariants
        self.values[self.values.len() - 1]
    }
}

/// String representation for segments: `EncodingType(value1,value2,...)`.
/// Useful for debugging during compression optimization.
impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(", self.encoding)?;
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{}", value)?;
        }
        write!(f, ")")
    }
}

/// Debug representation for segments, matching the Display format.
impl std::fmt::Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}
