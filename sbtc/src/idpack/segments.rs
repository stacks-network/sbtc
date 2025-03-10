use std::ops::Index;

use super::Segment;

/// Collection of segment objects representing segmented integer data.
///
/// This structure manages multiple segments, each with its own encoding strategy,
/// allowing for efficient representation of complex value patterns.
#[derive(Debug, Default)]
pub struct Segments(Vec<Segment>);

/// Enables conversion of a Segments instance into an iterator.
///
/// Provides a clean way to process all segments sequentially in consumer code.
impl IntoIterator for Segments {
    type Item = Segment;
    type IntoIter = std::vec::IntoIter<Segment>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Provides indexed access to individual segments.
///
/// Allows segments to be accessed by position, simplifying code
/// that needs to work with specific segments.
impl Index<usize> for Segments {
    type Output = Segment;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Segments {
    /// Creates a new `Segments` instance from an iterator of segments.
    ///
    /// Provides a convenient way to initialize a collection from
    /// existing segment objects.
    pub fn new_from<I>(segments: I) -> Self
    where
        I: IntoIterator<Item = Segment>,
    {
        Self(segments.into_iter().collect())
    }

    /// Returns a sorted vector of all unique values in the segments.
    ///
    /// Collects all integer values across all segments, ensuring
    /// they are sorted and deduplicated.
    pub fn get_values(&self) -> Vec<u64> {
        let mut values = Vec::new();
        for segment in &self.0 {
            values.extend(segment.as_slice());
        }
        values.sort_unstable();
        values.dedup();
        values
    }

    /// Pushes a new segment to the end of the inner segments list.
    ///
    /// Allows incrementally building a collection of segments.
    pub fn push(&mut self, segment: Segment) {
        self.0.push(segment);
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
