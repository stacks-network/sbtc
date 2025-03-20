//! Round-trip testing for verifying that the entire compression pipeline
//! (package -> encode -> decode) works correctly for a wide variety of input
//! data patterns.

use crate::idpack::{
    codec::{Decodable, Encodable},
    segmenters::{BitmapSegmenter, Segmenter},
    Segments,
};
use proptest::prelude::*;
use std::collections::BTreeSet;
use test_case::test_case;

/// Maximum value for generated IDs to keep tests reasonable
const MAX_ID_VALUE: u64 = 10_000_000;

/// Maximum gap between consecutive values in sparse sequences
const MAX_SPARSE_GAP: u64 = 1_000_000;

// Main property test suite for round-trip testing of segmentation and encoding
proptest! {
    #[test]
    fn test_roundtrip_dense_sequences(values in prop::collection::vec(1..10000u64, 1..1000)) {
        let sorted_unique = to_sorted_unique(&values);
        prop_assume!(!sorted_unique.is_empty());
        roundtrip_test(&sorted_unique).expect("round-trip failed");
    }

    #[test]
    fn test_roundtrip_sparse_sequences(
        base in 1..1000u64,
        increments in prop::collection::vec(1..MAX_SPARSE_GAP, 1..100)
    ) {
        // Create a sparse sequence with large gaps
        let mut values = Vec::with_capacity(increments.len());
        let mut current = base;

        for inc in increments {
            current += inc;
            if current <= MAX_ID_VALUE {
                values.push(current);
            }
        }

        prop_assume!(!values.is_empty());
        roundtrip_test(&values).expect("round-trip failed");
    }

    #[test]
    fn test_roundtrip_mixed_density(
        dense_runs in prop::collection::vec((1..100u64, 1..20usize), 1..10),
        gaps in prop::collection::vec(1..10000u64, 1..10)
    ) {
        // Create sequences with mixed density patterns
        let mut values = Vec::new();
        let mut current = 1u64;

        for (i, (step, count)) in dense_runs.into_iter().enumerate() {
            // Add a gap before each dense run (except first)
            if i > 0 && i - 1 < gaps.len() {
                current += gaps[i - 1];
            }

            // Add a dense run of values
            for _ in 0..count {
                if current <= MAX_ID_VALUE {
                    values.push(current);
                    current += step;
                }
            }
        }

        let sorted_unique = to_sorted_unique(&values);
        prop_assume!(!sorted_unique.is_empty());
        roundtrip_test(&sorted_unique).expect("round-trip failed");
    }

    #[test]
    fn test_roundtrip_edge_values(
        small_values in prop::collection::vec(1..100u64, 1..50),
        large_values in prop::collection::vec((MAX_ID_VALUE - 10000)..MAX_ID_VALUE, 1..50)
    ) {
        // Combine small and large values
        let mut values = small_values;
        values.extend(large_values);

        let sorted_unique = to_sorted_unique(&values);
        prop_assume!(!sorted_unique.is_empty());
        roundtrip_test(&sorted_unique).expect("round-trip failed");
    }
}

/// Helper function to ensure test data is sorted and unique
fn to_sorted_unique(values: &[u64]) -> Vec<u64> {
    let mut set = BTreeSet::new();
    set.extend(values);
    set.into_iter().collect()
}

/// Performs the full round-trip test: package -> encode -> decode -> compare
fn roundtrip_test(values: &[u64]) -> Result<(), String> {
    // Skip empty sets (handled by prop_assume in the test functions)
    if values.is_empty() {
        return Ok(());
    }

    // Step 1: Package the values into segments
    let segmenter = BitmapSegmenter;
    let segments = segmenter.package(values).expect("segmentation failed");

    // Step 2: Encode the segments to bytes
    let encoded_bytes = segments.encode();

    // Step 3: Decode the bytes back to segments
    let decoded_segments = Segments::decode(&encoded_bytes).expect("decoding failed");

    // Step 4: Extract values from decoded segments
    let decoded_values = decoded_segments.values().collect::<Vec<_>>();

    // Step 5: Compare original and decoded lengths
    if values.len() != decoded_values.len() {
        return Err(format!(
            "mismatched lengths: original={}, decoded={}",
            values.len(),
            decoded_values.len()
        ));
    }

    // Step 6: Compare original and decoded values (in order)
    // Note: we don't use a simple equals just so that we can provide a more
    // detailed error message in case of a mismatch.
    for (idx, (original, decoded)) in values.iter().zip(decoded_values.iter()).enumerate() {
        if original != decoded {
            return Err(format!(
                "mismatch at index {}: original={}, decoded={}",
                idx, original, decoded
            ));
        }
    }

    Ok(())
}

#[test_case(&[1, 2, 3, 1000, 1001, 1002]; "dense clusters with gap")]
#[test_case(&[10, 20, 30, 10000, 10001]; "varying step sizes")]
#[test_case(&[1, u64::MAX / 2, u64::MAX / 2 + 1]; "near maximum values")]
#[test_case(&[1, 2, 3, 4, 5, 6, 7, 8]; "sequential values")]
#[test_case(&[1000, 10000, 100000, 1000000]; "logarithmic spacing")]
fn test_specific_patterns(values: &[u64]) {
    roundtrip_test(&values).expect("round-trip failed");
}

#[test]
fn test_large_sequence() {
    // Test with a large sequence to stress-test memory and performance
    let mut values = Vec::with_capacity(10_000);
    for i in 1..10_000 {
        values.push(i);
    }

    // Introduce some random larger gaps
    values.push(20_000);
    values.push(20_001);
    values.push(50_000);

    roundtrip_test(&values).expect("round-trip failed");
}

#[test]
fn test_boundary_values() {
    // Test with values that might stress LEB128 encoding boundaries
    let mut values = Vec::new();

    // Powers of 2 minus/plus small values to test encoding boundaries
    for i in 0..8 {
        let base = 1u64 << (7 * i);
        values.push(base - 1);
        values.push(base);
        values.push(base + 1);
    }

    roundtrip_test(&values).expect("round-trip failed");
}
