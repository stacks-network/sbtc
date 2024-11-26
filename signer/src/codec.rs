//! # Canonical encoding and decoding for the sBTC signer
//!
//! The purpose of this module is to define how to encode and decode
//! signer messages as byte sequences.
//!
//! This is achieved by
//!
//! 1. Providing the `Encode` and `Decode` traits, defining the encode and decode
//!    methods we intend to use throughout the signer.
//! 2. Implementing these traits for any type implementing `ProtoSerializable` defined in here.
//!
//! ## Examples
//!
//! ### Encoding a string slice and decoding it as a string
//!
//! ```
//! use signer::codec::{Encode, Decode};
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

use crate::error::Error;
use prost::Message as _;

/// Utility trait to specify mapping between internal types and proto counterparts. The implementation of `Encode` and `Decode` for a type `T` implementing `ProtoSerializable` assume `T: Into<Message> + TryFrom<Message>`.
/// ```
/// impl ProtoSerializable for PublicKey {
///    type Message = proto::PublicKey;
/// }
/// ```
pub trait ProtoSerializable {
    /// The proto message type used for conversions
    type Message: ::prost::Message + Default;
}

/// Provides a method for encoding an object into a writer using a canonical serialization format.
///
/// This trait is designed to be implemented by types that need to serialize their data into a byte stream
/// in a standardized format, primarily to ensure consistency across different components of the signer system.
pub trait Encode: Sized {
    /// Encodes the calling object into a vector of bytes.
    ///
    /// # Returns
    /// The vector of bytes.
    /// TODO: change to &self
    fn encode_to_vec(self) -> Vec<u8>;
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

impl<T> Encode for T
where
    T: ProtoSerializable + Clone,
    T: Into<<T as ProtoSerializable>::Message>,
{
    fn encode_to_vec(self) -> Vec<u8> {
        let message: <Self as ProtoSerializable>::Message = self.into();
        prost::Message::encode_to_vec(&message)
    }
}

impl<T> Decode for T
where
    T: ProtoSerializable + Clone,
    T: TryFrom<<T as ProtoSerializable>::Message, Error = Error>,
{
    fn decode<R: io::Read>(mut reader: R) -> Result<Self, Error> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(CodecError::DecodeIOError)?;

        let message =
            <<T as ProtoSerializable>::Message>::decode(&*buf).map_err(CodecError::DecodeError)?;

        T::try_from(message)
    }
}

/// The error used in the [`Encode`] and [`Decode`] trait.
#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeError(#[source] ::prost::DecodeError),
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeIOError(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use fake::Dummy as _;
    use rand::SeedableRng as _;

    use crate::{keys::PublicKey, proto};

    use super::*;

    impl ProtoSerializable for PublicKey {
        type Message = proto::PublicKey;
    }

    #[test]
    fn public_key_should_be_able_to_encode_and_decode_correctly() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let message = PublicKey::dummy_with_rng(&fake::Faker, &mut rng);

        let encoded = message.encode_to_vec();

        let decoded = <PublicKey as Decode>::decode(encoded.as_slice()).unwrap();

        assert_eq!(decoded, message);
    }
}
