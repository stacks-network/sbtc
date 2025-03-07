//! Bit-level buffer operations for maximum compression efficiency.
//!
//! This module provides precise bit manipulation capabilities that are essential
//! for achieving optimal compression in Fixed-Width Delta encoding. By allowing
//! integers to be stored using exactly the minimum number of bits required,
//! even across byte boundaries, the BitBuffer eliminates wasted space from
//! traditional byte-aligned storage.

use super::EXTREME_BIT_WIDTH_THRESHOLD;

/// BitBuffer handles precise bit-level packing and unpacking operations
/// to achieve maximum compression across byte boundaries.
///
/// This structure maintains a buffer of bits that can be efficiently:
/// - Appended to (during encoding)
/// - Extracted from (during decoding)
/// - Flushed as complete bytes
///
/// The bit buffer is essential for the Fixed-Width Delta encoding's
/// bit-level packing, which allows using the exact minimum number of bits
/// required for each delta value.
pub struct BitBuffer {
    /// Current bit buffer contents (up to 64 bits)
    pub buffer: u64,

    /// Number of bits currently stored in the buffer
    pub bits_available: u32,
}

impl BitBuffer {
    /// Creates a new, empty bit buffer
    ///
    /// Initializes a buffer with zero bits available, ready for appending.
    ///
    /// ## Returns
    /// A new BitBuffer instance
    pub fn new() -> Self {
        Self { buffer: 0, bits_available: 0 }
    }

    /// Appends bits to the buffer
    ///
    /// Adds the specified bits to the buffer by OR'ing them into position,
    /// shifting by the current bit count to place them properly.
    ///
    /// ## Arguments
    /// * `value` - The bit value to append
    /// * `bit_count` - The number of bits to use from value
    pub fn append(&mut self, value: u64, bit_count: u8) {
        self.buffer |= value << self.bits_available;
        self.bits_available += bit_count as u32;
    }

    /// Extracts bits from the buffer
    ///
    /// Extracts the specified number of bits from the buffer with special
    /// handling for extreme bit widths to ensure precision is maintained.
    ///
    /// ## Arguments
    /// * `bit_width` - The number of bits to extract
    ///
    /// ## Returns
    /// The extracted bit value
    pub fn extract(&mut self, bit_width: u8) -> u64 {
        // Handle special cases first
        if bit_width == 64 {
            // Special case: full 64-bit value
            let value = self.buffer;
            self.buffer = 0;
            self.bits_available = 0;
            return value;
        } else if bit_width >= EXTREME_BIT_WIDTH_THRESHOLD {
            // For extreme bit widths, use more careful extraction
            let mask = (1u64 << bit_width) - 1;
            let value = self.buffer & mask;
            self.buffer = 0;
            self.bits_available = 0;
            return value;
        }

        // Normal case: extract bits and adjust buffer
        let mask = (1u64 << bit_width) - 1;
        let value = self.buffer & mask;

        if (bit_width as u32) < self.bits_available {
            // Standard case: shift out used bits
            self.buffer >>= bit_width;
            self.bits_available -= bit_width as u32;
        } else {
            // Edge case: no bits remain
            self.buffer = 0;
            self.bits_available = 0;
        }

        value
    }

    /// Flushes complete bytes from the buffer
    ///
    /// Extracts and returns all complete bytes (8-bit units) from the buffer,
    /// updating the buffer state to remove the extracted bits.
    ///
    /// ## Returns
    /// A vector of extracted bytes
    pub fn flush_bytes(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Only flush complete bytes (8 bits at a time)
        while self.bits_available >= 8 {
            // Extract the lowest 8 bits
            bytes.push((self.buffer & 0xFF) as u8);

            // Remove those bits from the buffer
            self.buffer >>= 8;
            self.bits_available -= 8;
        }

        bytes
    }

    /// Returns remaining bits as a final byte if any exist
    ///
    /// If there are any bits remaining in the buffer (less than 8),
    /// converts them to a single byte for final flushing.
    ///
    /// ## Returns
    /// A byte containing the remaining bits if any, or None if buffer is empty
    pub fn remaining_byte(&self) -> Option<u8> {
        if self.bits_available > 0 {
            Some(self.buffer as u8)
        } else {
            None
        }
    }
}
