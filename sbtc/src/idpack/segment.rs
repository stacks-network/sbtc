use std::{fmt::Debug, ops::Index};

/// Error types that can occur when working with segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is empty.
    #[error("The input is empty")]
    EmptyInput,

    /// The input is not sorted.
    /// Sorted input is essential for delta encoding and bitmap optimization.
    #[error("The input is not sorted")]
    UnsortedInput,

    /// The input contains duplicate values.
    /// Duplicate elimination is crucial for maximum compression.
    #[error("The input contains duplicate values")]
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
#[derive(Clone)]
pub struct Segment {
    encoding: SegmentEncoding,
    values: Vec<u64>,
}

impl Segment {
    /// Creates a new empty segment with the specified encoding method.
    pub fn new(encoding: SegmentEncoding) -> Self {
        Self { encoding, values: Vec::new() }
    }

    /// Creates a new segment with the specified encoding and initial offset value.
    /// The offset is crucial for compression as it establishes the base value.
    pub fn new_with_offset(encoding: SegmentEncoding, offset: u64) -> Self {
        let mut segment = Self::new(encoding);
        segment.values.push(offset);
        segment
    }

    /// Returns the offset (first value) of the segment.
    ///
    /// ## Panics
    ///
    /// This method will panic if the segment is empty. Use [`Self::is_empty()`]
    /// to check if the segment has any values first.
    pub fn offset(&self) -> u64 {
        self.values[0]
    }

    /// Returns the encoding method used for this segment.
    pub fn encoding(&self) -> SegmentEncoding {
        self.encoding
    }

    /// Inserts a value into the segment, maintaining sorted order.
    /// Enforces uniqueness and ordering constraints for optimal compression.
    ///
    /// ## Errors
    /// - Duplicate values (`DuplicateValue`)
    /// - Unsorted values (`UnsortedInput`)
    pub fn insert(&mut self, value: u64) -> Result<(), Error> {
        if self.values.contains(&value) {
            return Err(Error::DuplicateValue(value));
        }

        if !self.values.is_empty() && value < self.values[self.values.len() - 1] {
            return Err(Error::UnsortedInput);
        }

        self.values.push(value);
        Ok(())
    }

    /// Returns `true` if the segment contains no values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns a slice of all values in the segment, including the offset.
    pub fn as_slice(&self) -> &[u64] {
        &self.values
    }

    /// Returns all values except the offset. If the underlying vec is empty
    /// or contains only the offset, this method will return an empty slice.
    pub fn values(&self) -> &[u64] {
        if self.values.is_empty() {
            return &[];
        }

        &self.values[1..]
    }

    /// Returns the number of values in the segment (including offset).
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns the number of values excluding the offset.
    /// Important for encoding decisions and payload size calculations.
    pub fn value_count(&self) -> usize {
        self.values.len().saturating_sub(1)
    }

    /// Returns `true` if segment contains values beyond the offset.
    /// Helps determine if Single encoding is applicable.
    pub fn has_values(&self) -> bool {
        self.value_count() > 0
    }

    /// Returns span of the segment (maximum value - offset).
    /// Critical for Bitset sizing and bit width calculations.
    pub fn range(&self) -> u64 {
        self.values
            .iter()
            .max()
            .map(|x| x - self.offset())
            .unwrap_or_default()
    }

    /// Returns the greatest value in the segment.
    /// Used for range calculations and segment boundary decisions.
    ///
    /// ## Panics
    /// This method will panic if the segment is empty. Use [`Self::is_empty()`]
    /// to check if the segment has any values first.
    pub fn max_value(&self) -> u64 {
        self.values.iter().max().copied().unwrap()
    }
}

/// Provides indexed access to values in a segment.
/// Supports efficient value access during encoding operations.
impl Index<usize> for Segment {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
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
