//! # IDPack: Maximum Compression Integer Set Encoding
//!
//! `idpack` is a high-efficiency integer compression library designed to
//! achieve maximum byte savings through automatic segmentation and optimal
//! encoding selection. The library specializes in compressing sorted sets of
//! unsigned 64-bit integers by intelligently splitting them into segments and
//! applying the most efficient encoding strategy for each segment.
//!
//! ## Core Compression Strategies
//!
//! * **Bitmap Encoding**: Represents dense integer sequences as bit flags in a
//!   bitmap, with special optimizations for tiny ranges (embedded bitmaps)
//!   
//! * **Single Value**: Special-case optimization for isolated values with zero
//!   payload overhead
//!
//! ## Core Segmentation Strategies
//!
//! * **Bitmap Segmenter**: Splits sequences into segments optimized for bitmap
//!   encoding
//!
//! ## Usage Example
//!
//! ```
//! use idpack::{BitmapSegmenter, Segmenter, Encodable};
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
//! * Input validation for size limits
//! * Safe bitmap allocation limits
//! * Protection against excessive delta ranges
//!
//! ## Architecture
//!
//! * **Segmenters**: Divide integer sequences into optimally-sized segments
//! * **Segments**: Manage collections of un-encoded segments
//! * **Segment**: Represents a single encoded integer range
//! * **Codec**: Low-level encoding/decoding strategies

mod codec;
mod segment;
mod segmenters;
mod segments;

pub use segment::Error as SegmentError;
pub use segment::Segment;
pub use segment::SegmentEncoding;

pub use segments::Segments;

pub use segmenters::BitmapSegmenter;
pub use segmenters::Error as SegmenterError;
pub use segmenters::Segmenter;

pub use codec::Decodable;
pub use codec::Encodable;
pub use codec::Error as CodecError;
pub use codec::SegmentDecodeError as DecodeError;
pub use codec::SegmentEncodeError as EncodeError;

/// Maximum allocation limit in bytes (1MB) for preventing memory allocation attacks
/// while allowing sufficient space for optimal compression operations.
pub const ALLOC_BYTES_LIMIT: u32 = 1 << 20; // 1MB = 2^20 bytes
