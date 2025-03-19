//! # IDPack: Integer Set Compression Encoding
//!
//! `idpack` is an integer compression module designed to achieve byte
//! savings through automatic segmentation and multiple bitmaps.
//!
//! ## Usage Example
//!
//! ```
//! use sbtc::idpack::{BitmapSegmenter, Segmenter, Encodable};
//!
//! // Compress a sequence of integers with maximum efficiency
//! let values = vec![1, 2, 3, 50, 51, 52, 1000, 1001];
//!
//! // Segment the values with automatic encoding selection
//! let segments = BitmapSegmenter.package(&values).unwrap();
//!
//! // Encode to binary representation
//! let encoded = segments.encode().unwrap();
//!
//! println!("Compressed {} integers into {} bytes", values.len(), encoded.len());
//! ```
//!
//! ## Safety Considerations
//!
//! This library implements safeguards against memory exhaustion attacks that
//! could occur when decoding malicious inputs:
//!
//! * Input validation for semantic correctness (packaging)
//! * Safe bitmap allocation limits (decoding)
//! * Protection against excessive delta ranges (segmenting)
//!
//! ## Architecture
//!
//! * **Segmenters**: Divide integer sequences into optimally-sized segments
//! * **Segments**: Manage collections of un-encoded segments
//! * **Segment**: Represents a single packaged integer range
//! * **Codec**: Low-level encoding/decoding

mod codec;
mod segment;
mod segmenters;
mod segments;

#[cfg(test)]
mod tests;

pub use segment::Segment;
pub use segment::SegmentError;

pub use segments::Segments;
pub use segments::SegmentsError;

pub use segmenters::BitmapSegmenter;
pub use segmenters::Segmenter;
pub use segmenters::SegmenterError;

pub use codec::Decodable;
pub use codec::DecodeError;
pub use codec::Encodable;

/// Maximum allocation limit in bytes (1MB) for a single bitmap payload for
/// preventing memory allocation attacks while allowing sufficient space for
/// optimal compression operations. This limit has no effect on the number of
/// segments or number of values to be decoded.
pub const ALLOC_BYTES_LIMIT: u32 = 1 << 20; // 1MB = 2^20 bytes
