//! # Fixed-Width Delta Encoding Type Definitions
//!
//! This module provides specialized type classifications that enable maximum compression
//! efficiency in the Fixed-Width Delta encoding strategy. These types drive the
//! selection of optimal encoding paths and enable format-detection during decoding.
//!
//! ## Type Classification System
//!
//! The type system here implements a multi-level optimization approach:
//!
//! 1. **Format Detection** - The `DecodingFormat` enum analyzes encoding flags to
//!    determine which specialized decoder path to use, avoiding unnecessary bytes
//!    by detecting optimizations like embedded bit widths and tiny sequences.
//!
//! 2. **Bit Width Classification** - The `BitWidth` enum categorizes segments into
//!    specialized encoding buckets that apply different compression techniques:
//!    * Tiny sequences (2 values) get ultra-compact encoding with no overhead
//!    * Sequential values (consecutive integers) use zero-bit width optimization
//!    * Small bit widths (1-7 bits) are embedded in flags to save a byte
//!    * Standard bit widths use efficient bit-level packing
//!    * Extreme bit widths use specialized byte-aligned encoding
//!
//! These classifications enable the encoder to select the optimal compression
//! technique for each segment pattern, resulting in minimum possible encoded size
//! with zero wasted bits.

use super::{
    EMBEDDED_BIT_WIDTH_FLAG, EMBEDDED_BIT_WIDTH_MASK, EMBEDDED_BIT_WIDTH_SHIFT, TINY_SEQUENCE_FLAG,
};

/// Decoding format identification based on encoding flags
///
/// This enum represents the different decoding paths that can be
/// taken based on the flags in the encoded segment data.
pub enum DecodingFormat {
    /// Tiny sequence format (2 values only)
    Tiny,

    /// Format with bit width embedded in flags
    EmbeddedWidth(u8),

    /// Format with explicit bit width byte
    ExplicitWidth,
}

impl DecodingFormat {
    /// Determines the decoding format from encoding flags
    ///
    /// Analyzes the flag byte to identify which optimizations were
    /// applied during encoding, to select the correct decoding path.
    ///
    /// # Arguments
    /// * `flags` - The encoding flags byte
    ///
    /// # Returns
    /// The appropriate DecodingFormat variant
    pub fn from_flags(flags: u8) -> Self {
        match (
            flags & TINY_SEQUENCE_FLAG != 0,
            flags & EMBEDDED_BIT_WIDTH_FLAG != 0,
        ) {
            (true, _) => Self::Tiny,
            (false, true) => {
                Self::EmbeddedWidth((flags & EMBEDDED_BIT_WIDTH_MASK) >> EMBEDDED_BIT_WIDTH_SHIFT)
            }
            (false, false) => Self::ExplicitWidth,
        }
    }
}

/// Bit width classification for optimal encoding selection
///
/// This enum represents the different bit width categories that determine
/// the most efficient encoding strategy to apply for maximum compression.
/// Each variant corresponds to a specific optimization technique.
pub enum BitWidth {
    /// Tiny sequence (exactly 2 values) - uses ultra-compact LEB128 delta encoding
    Tiny,

    /// Sequential values (bit width 0) - values differ by exactly 1
    Sequential,

    /// Small bit width (1-7) that can be embedded in flags byte
    Embedded(u8),

    /// Standard bit width (8-59) requiring explicit width byte
    Normal(u8),

    /// Extreme bit width (60+) requiring specialized byte-level handling
    Extreme(u8),
}
