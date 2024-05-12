//! # Canonical encoding and decoding for the sBTC signer
//!
//! The purpose of this module is to define how to encode and decode
//! signer messages as byte sequences.
//!
//! This is achieved by
//!
//! 1. Providing the `Encode` and `Decode` traits, defining the encode and decode
//!    methods we intend to use throughout the signer.
//! 2. Implementing these traits for any type implementing `serde::Serialize` and `serde::de::DeserializeOwned`
//!    using `bincode` as the encoding format.
//!
//! ## Examples
//!
//! ### Encoding a string slice and decoding it as a string
//!
//! ```
//! use sbtc_signer::codec::{Encode, Decode};
//!
//! let message = "Encode me";
//!
//! // `.encode_to_vec()` provided by the `Encode` trait
//! let encoded = message.encode_to_vec().unwrap();
//!
//! // `.decode()` provided by the `Decode` trait
//! let decoded = String::decode(encoded.as_slice()).unwrap();
//!
//! assert_eq!(decoded, message);
//! ```

use std::io;

/// Provides a method for encoding an object into a writer using a canonical serialization format.
///
/// This trait is designed to be implemented by types that need to serialize their data into a byte stream
/// in a standardized format, primarily to ensure consistency across different components of the signer system.
///
/// The trait includes a generic method for writing to any output that implements `io::Write`, as well as
/// a convenience method for encoding directly to a byte vector.
pub trait Encode: Sized {
    /// Encodes the calling object into a writer.
    ///
    /// # Arguments
    /// * `writer` - A mutable reference to an object implementing `io::Write` where the encoded bytes will be written.
    ///
    /// # Returns
    /// A `Result` which is `Ok` if the encoding succeeded, or an `Error` if it failed.
    fn encode<W: io::Write>(self, writer: W) -> Result<(), Error>;

    /// Encodes the calling object into a vector of bytes.
    ///
    /// # Returns
    /// A `Result` containing either the vector of bytes if the encoding was successful, or an `Error` if it failed.
    fn encode_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buff = Vec::new();
        self.encode(&mut buff)?;
        Ok(buff)
    }
}

/// Provides a method for decoding an object from a reader using a canonical deserialization format.
///
/// This trait is intended for types that need to reconstruct themselves from a byte stream, ensuring
/// that objects across the signer system are restored from bytes uniformly.
///
/// It includes a generic method for reading from any input that implements `io::Read`, as well as
/// a convenience method for decoding from a byte slice.
pub trait Decode: Sized {
    /// Decodes an object from a reader in a canonical format.
    ///
    /// # Arguments
    /// * `reader` - An object implementing `io::Read` from which the bytes will be read.
    ///
    /// # Returns
    /// A `Result` which is `Ok` containing the decoded object, or an `Error` if decoding failed.
    fn decode<R: io::Read>(reader: R) -> Result<Self, Error>;
}

impl<T: serde::Serialize> Encode for &T {
    fn encode<W: io::Write>(self, writer: W) -> Result<(), Error> {
        bincode::serialize_into(writer, self)
    }
}

impl<T: serde::de::DeserializeOwned> Decode for T {
    fn decode<R: io::Read>(reader: R) -> Result<Self, Error> {
        bincode::deserialize_from(reader)
    }
}

pub type Error = bincode::Error;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_should_be_able_to_encode_and_decode_correctly() {
        let message = "Article 107: A Bro never leaves another Bro hanging";

        let encoded = message.encode_to_vec().unwrap();

        let decoded = String::decode(encoded.as_slice()).unwrap();

        assert_eq!(decoded, message);
    }
}
