mod codec;
mod leb128;
mod segment;
mod segmenter;
mod segments;

pub use segment::Error as SegmentError;
pub use segment::Segment;
pub use segment::SegmentEncoding;

pub use segments::Segments;

pub use codec::Decodable;
pub use codec::Encodable;
pub use codec::Error as CodecError;
pub use codec::SegmentDecodeError as DecodeError;
pub use codec::SegmentEncodeError as EncodeError;

/// Maximum allocation limit in bytes (1MB) for preventing memory allocation attacks
/// while allowing sufficient space for optimal compression operations.
pub const ALLOC_BYTES_LIMIT: u32 = 1 << 20; // 1MB = 2^20 bytes
