//! # Canonical encoding and decoding for the sBTC signer
//!
//! This module defines encoding and decoding methods for messages in the signer.
//! The primary purpose of these utilities is to facilitate convenient serialization and deserialization
//! of messages that need to be exchanged between signers over a network.
//!
//! The module provides two main traits, `Encode` and `Decode`, which
//! denote the canonical serialization format for any types implementing these traits.
//!
//! While thiese traits permit custom serialization implementations, this module also provides
//! blanket implementations for any type that implements `serde::Serialize` and `serde::de::DeserializeOwned`,
//! using [Bincode](https://docs.rs/bincode/1.3.3/bincode/).
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
//! // `.decode_to_bytes()` provided by the `Decode` trait
//! let decoded = String::decode_from_bytes(&encoded).unwrap();
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

    /// Decodes an object from a byte slice.
    ///
    /// This is a convenience method that uses the `decode` method internally to deserialize the object
    /// from a slice of bytes, facilitating easier handling of raw byte data.
    ///
    /// # Arguments
    /// * `bytes` - A byte slice from which the object should be decoded.
    ///
    /// # Returns
    /// A `Result` which is `Ok` containing the decoded object, or an `Error` if decoding failed.
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }
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

        let decoded = String::decode_from_bytes(&encoded).unwrap();

        assert_eq!(decoded, message);
    }
}
