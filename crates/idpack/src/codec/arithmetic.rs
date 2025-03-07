//! Safe arithmetic operations for decoding compressed integer sequences.
//!
//! This module provides utility traits that simplify overflow checking during
//! value reconstruction, ensuring correct decoding without panics. These helpers
//! are particularly important for maintaining integrity when decoding highly
//! compressed data where arithmetic operations like delta reconstruction could
//! potentially overflow.

use super::SegmentDecodeError;

/// Helper for concise error handling when dealing with arithmetic operations.
///
/// Provides a clean interface for performing checked arithmetic operations and
/// converting potential overflows into meaningful decoder errors. This trait
/// is essential for maintaining decode integrity in compression algorithms that
/// use delta values, offsets, and bit manipulations.
pub trait CheckedArithmetic {
    /// Performs a checked arithmetic operation that might overflow.
    ///
    /// Wraps operations like checked_add/checked_mul with descriptive error handling,
    /// simplifying overflow detection throughout the decoding pipeline.
    ///
    /// # Parameters
    /// * `op_name` - Name of the operation for error context
    /// * `op` - The checked operation to perform, returning Option<Self>
    ///
    /// # Returns
    /// * `Ok(value)` - The operation succeeded
    /// * `Err(SegmentDecodeError)` - The operation would overflow
    fn checked_op<F>(self, op_name: &str, op: F) -> Result<Self, SegmentDecodeError>
    where
        F: FnOnce() -> Option<Self>,
        Self: Sized;
}

/// Implementation of CheckedArithmetic for u64 values.
///
/// Unsigned 64-bit integers are the primary value type in the compression system,
/// making overflow checking critical for preserving data integrity during decoding.
impl CheckedArithmetic for u64 {
    fn checked_op<F>(self, op_name: &str, op: F) -> Result<Self, SegmentDecodeError>
    where
        F: FnOnce() -> Option<Self>,
    {
        op().ok_or_else(|| {
            SegmentDecodeError::ArithmeticOverflow(format!("{} overflow: value={}", op_name, self))
        })
    }
}
