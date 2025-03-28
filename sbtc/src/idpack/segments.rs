use super::Segment;

/// Errors that can occur when working with segment collections.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentsError {
    /// Segments must be added in ascending order (no overlaps permitted).
    #[error(
        "New segment offset {offset} must be greater than previous segment's maximum value {prev_max}"
    )]
    OverlappingSegments {
        /// The offset of the segment being added
        offset: u64,
        /// The maximum value from the previous segment
        prev_max: u64,
    },
}

/// Collection of segment objects representing segmented integer data.
#[derive(Debug, Default, Clone)]
pub struct Segments(Vec<Segment>);

impl Segments {
    /// Returns an iterator over all values across all segments.
    ///
    /// Values are returned in segment-order, with each segment's values
    /// returned in ascending order.
    pub fn values(&self) -> impl Iterator<Item = u64> + '_ {
        self.0
            .iter()
            .flat_map(|segment| segment.as_slice().iter().copied())
    }

    /// Pushes a new segment to the end of the inner segments list, validating
    /// proper ordering with existing segments.
    ///
    /// To maintain correct segment ordering for compression and decoding, each
    /// new segment must have an offset greater than the maximum value of the
    /// previous segment.
    ///
    /// # Returns
    /// * `Ok(())` - If the segment was successfully added
    /// * `Err(SegmentsError::InvalidSegmentOrder)` - If the segment violates
    ///   ordering constraints
    pub fn try_push(&mut self, segment: Segment) -> Result<(), SegmentsError> {
        // Check if there are existing segments
        if let Some(last_segment) = self.0.last() {
            // Get the maximum value from the last segment
            let prev_max = last_segment.max();

            // Validate that new segment's offset is greater than previous max
            if segment.offset() <= prev_max {
                return Err(SegmentsError::OverlappingSegments {
                    offset: segment.offset(),
                    prev_max,
                });
            }
        }

        // Validation passed, add the segment
        self.0.push(segment);

        Ok(())
    }

    /// Returns the number of segments in the collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no segments in the collection.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the inner segments.
    ///
    /// Provides non-consuming access to segments, useful for
    /// analysis operations that don't modify the collection.
    pub fn iter(&self) -> impl Iterator<Item = &Segment> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Helper method to create a new `Segment` from a slice of values.
    fn segment(values: &[u64]) -> Segment {
        assert!(!values.is_empty(), "segment values cannot be empty");

        let mut segment = Segment::new_with_offset(values[0]);
        for &value in &values[1..] {
            segment.try_insert(value).unwrap();
        }
        segment
    }

    /// Test basic Segments construction and accessors
    #[test]
    fn test_new_segments() {
        // Empty segments
        let segments = Segments::default();
        assert!(segments.is_empty());
        assert_eq!(segments.len(), 0);
        assert_eq!(segments.iter().count(), 0);
        assert_eq!(segments.values().count(), 0);

        // Create with segments
        let mut segment1 = Segment::new_with_offset(10);
        segment1.try_insert(15).unwrap();

        let mut segments = Segments::default();
        segments.try_push(segment1).expect("failed to push segment");
        assert!(!segments.is_empty());
        assert_eq!(segments.len(), 1);
        assert_eq!(segments.iter().count(), 1);
        assert_eq!(segments.values().count(), 2); // Contains offset and value
    }

    /// Test segment ordering validation during push operations
    #[test_case(
        &[segment(&[10, 15, 20]), segment(&[30, 35, 40])] => Ok(());
        "valid ascending segments"
    )]
    #[test_case(
        &[segment(&[10]), segment(&[20]), segment(&[30])] => Ok(());
        "offset-only segments"
    )]
    #[test_case(
        &[segment(&[0, 1]), segment(&[2, 3]), segment(&[4, 5])] => Ok(());
        "minimal spacing"
    )]
    #[test_case(
        &[segment(&[10]), segment(&[10])] => Err(SegmentsError::OverlappingSegments {
            offset: 10,
            prev_max: 10,
        });
        "overlapping offset-only segments"
    )]
    #[test_case(
        &[segment(&[10, 15, 20]), segment(&[20, 25])] => Err(SegmentsError::OverlappingSegments {
            offset: 20,
            prev_max: 20,
        });
        "second offset equals first max"
    )]
    #[test_case(
        &[segment(&[10, 15, 20]), segment(&[19, 25])] => Err(SegmentsError::OverlappingSegments {
            offset: 19,
            prev_max: 20,
        });
        "second offset less than first max"
    )]
    #[test_case(
        &[segment(&[10, 15, 20]), segment(&[5, 25])] => Err(SegmentsError::OverlappingSegments {
            offset: 5,
            prev_max: 20,
        });
        "second offset less than first offset"
    )]
    fn test_segments_push(segments_to_push: &[Segment]) -> Result<(), SegmentsError> {
        let mut segments = Segments::default();
        for segment in segments_to_push {
            segments.try_push(segment.clone())?;
        }
        Ok(())
    }

    /// Test values() iterator functionality
    #[test]
    fn test_values_iterator() -> Result<(), SegmentsError> {
        let mut segments = Segments::default();

        // Add three segments with specific values
        let seg1 = segment(&[10, 11, 12]);
        segments.try_push(seg1)?;

        let seg2 = segment(&[20, 21]);
        segments.try_push(seg2)?;

        let seg3 = segment(&[30, 35, 40]);
        segments.try_push(seg3)?;

        // Collect all values and verify
        let all_values = segments.values().collect::<Vec<_>>();
        assert_eq!(all_values, vec![10, 11, 12, 20, 21, 30, 35, 40]);

        Ok(())
    }
}
