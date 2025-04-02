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
pub enum SegmentError {
    /// Values must be in strictly ascending order.
    /// Provides the value that violated the ordering constraint.
    #[error("Value {0} is out of order (must be inserted in strictly ascending order)")]
    UnsortedValue(u64),

    /// The input contains duplicate values.
    /// Duplicate elimination is crucial for maximum compression.
    #[error("The input contains duplicate values")]
    DuplicateValue(u64),
}

/// Represents a segment of integer values encoded with a specific method.
/// Facilitates pattern-based optimal compression.
///
/// # Safety Considerations
/// - Contains at least one value (offset) at all times
/// - Values are always sorted in strictly ascending order
/// - Duplicate values are not allowed (and are silently ignored)
#[derive(Clone)]
pub struct Segment {
    values: Vec<u64>,
}

impl Segment {
    /// Creates a new segment with the specified encoding and initial offset
    /// value. The offset is crucial for compression as it establishes the base
    /// value for the segment.
    pub fn new_with_offset(offset: u64) -> Self {
        Self { values: vec![offset] }
    }

    /// Returns the offset (first value) of the segment.
    pub fn offset(&self) -> u64 {
        // SAFETY: `values` is never empty due to struct invariants
        self.values[0]
    }

    /// Inserts a value into the segment, requiring that values are sorted.
    /// Attempting to insert the same value consecutively is a no-op and only
    /// one copy is stored.
    ///
    /// ## Errors
    /// - Unsorted values (`UnsortedInput`)
    pub fn try_insert(&mut self, value: u64) -> Result<(), SegmentError> {
        // SAFETY: `values` is never empty due to struct invariants
        let last_value = self.max();

        // Validate that the new value is greater than the last value (sorted)
        if value < last_value {
            return Err(SegmentError::UnsortedValue(value));
        }

        // If the value already exists, return early (no duplicates allowed)
        if value == last_value {
            return Err(SegmentError::DuplicateValue(value));
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
    pub fn payload_values(&self) -> &[u64] {
        // SAFETY: `values` is never empty due to struct invariants
        &self.values[1..]
    }

    /// Returns the number of values in the segment (including offset).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.values.len()
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

/// String representation for segments: `Segment(value1,value2,...)`.
/// Useful for debugging during compression optimization.
impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Segment(")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use test_case::test_case;

    /// Test segment creation with different offsets
    #[test_case(0; "zero offset")]
    #[test_case(10; "small offset")]
    #[test_case(u64::MAX; "large offset")]
    fn test_new_segment(offset: u64) {
        let segment = Segment::new_with_offset(offset);

        // Verify offset is stored correctly
        assert_eq!(segment.offset(), offset);

        // Verify invariant: segment is never empty
        assert!(!segment.as_slice().is_empty());
        assert_eq!(segment.len(), 1);

        // Verify max equals offset when only offset exists
        assert_eq!(segment.max(), offset);

        // Verify range is zero when only offset exists
        assert_eq!(segment.range(), 0);
    }

    /// Test successful insertion in ascending order
    #[test]
    fn test_ordered_insertion() -> Result<(), SegmentError> {
        let mut segment = Segment::new_with_offset(10);

        // Insert values in strictly ascending order
        segment.try_insert(11)?;
        segment.try_insert(12)?;
        segment.try_insert(15)?;
        segment.try_insert(22)?;

        // Verify all values are stored
        assert_eq!(segment.len(), 5);
        assert_eq!(segment.as_slice(), &[10, 11, 12, 15, 22]);
        assert_eq!(segment.payload_values(), &[11, 12, 15, 22]);

        // Verify max and range
        assert_eq!(segment.offset(), 10);
        assert_eq!(segment.max(), 22);
        assert_eq!(segment.range(), 12); // 22 - 10

        Ok(())
    }

    #[test_case(&[10, 10] => Err(SegmentError::DuplicateValue(10)); "duplicate offsets")]
    #[test_case(&[10, 11, 11] => Err(SegmentError::DuplicateValue(11)); "duplicate values")]
    fn test_duplicate_value_error(values: &[u64]) -> Result<(), SegmentError> {
        let mut segment = Segment::new_with_offset(values[0]);

        // Insert duplicates
        for &value in &values[1..] {
            segment.try_insert(value)?;
        }
        Ok(())
    }

    /// Test insertion of out-of-order values
    #[test_case(10, 9; "value less than offset")]
    #[test_case(10, 0; "zero value with non-zero offset")]
    fn test_out_of_order_insertion(offset: u64, value: u64) {
        let mut segment = Segment::new_with_offset(offset);

        // Try inserting an out-of-order value
        let result = segment.try_insert(value);

        // Verify appropriate error is returned
        assert!(result.is_err());
        assert_matches!(result, Err(SegmentError::UnsortedValue(v)) if v == value);

        // Verify segment wasn't modified
        assert_eq!(segment.len(), 1);
        assert_eq!(segment.offset(), offset);
    }

    /// Test insertion after values are already present
    #[test]
    fn test_intermediate_insertion_error() -> Result<(), SegmentError> {
        let mut segment = Segment::new_with_offset(10);

        // Add values
        segment.try_insert(15)?;
        segment.try_insert(20)?;

        // Try inserting value between existing values (should fail)
        segment
            .try_insert(14)
            .expect_err("expected insertion error");

        // Verify value > max still works
        segment.try_insert(25)?;

        // Verify segment state
        assert_eq!(segment.as_slice(), &[10, 15, 20, 25]);

        Ok(())
    }

    /// Test segment with large ranges and edge values
    #[test_case(0, u64::MAX; "full range")]
    #[test_case(u64::MAX / 2, u64::MAX; "upper half")]
    #[test_case(0, 1; "minimum range")]
    fn test_range_calculation(offset: u64, max: u64) -> Result<(), SegmentError> {
        let mut segment = Segment::new_with_offset(offset);

        // Insert maximum value
        segment.try_insert(max)?;

        // Verify range calculation
        assert_eq!(segment.offset(), offset);
        assert_eq!(segment.range(), max - offset);
        assert_eq!(segment.max(), max);

        Ok(())
    }
}
