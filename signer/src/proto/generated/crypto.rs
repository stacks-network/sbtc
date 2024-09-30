// This file is @generated by prost-build.
/// / A type representing a 256-bit integer.
#[derive(Copy)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Uint256 {
    /// These are the 64 bits of the 256-bit integer from bits 0-63.
    #[prost(fixed64, tag = "1")]
    pub bits_part0: u64,
    /// These are the 64 bits of the 256-bit integer from bits 64-127.
    #[prost(fixed64, tag = "2")]
    pub bits_part1: u64,
    /// These are the 64 bits of the 256-bit integer from bits 128-191.
    #[prost(fixed64, tag = "3")]
    pub bits_part2: u64,
    /// These are the 64 bits of the 256-bit integer from bits 192-255.
    #[prost(fixed64, tag = "4")]
    pub bits_part3: u64,
}
/// / Represents a public key type for the secp256k1 elliptic curve.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    /// The x-coordinate of the public key.
    #[prost(message, optional, tag = "1")]
    pub x_only_public_key: ::core::option::Option<Uint256>,
    /// Represents the parity bit of the public key. True means the parity is
    /// odd, while false means the parity is even.
    #[prost(bool, tag = "2")]
    pub parity_is_odd: bool,
}
/// This is a recoverable signature representation. It is nonstandard and
/// defined by the libsecp256k1 library.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoverableSignature {
    /// These are the first 256-bits of the 64 byte signature part, so bits 0-255.
    #[prost(message, optional, tag = "1")]
    pub lower_bits: ::core::option::Option<Uint256>,
    /// These are the last 256-bits of the 64 byte signature part, so bits 256-511.
    #[prost(message, optional, tag = "2")]
    pub upper_bits: ::core::option::Option<Uint256>,
    /// A tag used for recovering the public key from a compact signature. It
    /// must be one of the values 0-3.
    #[prost(int32, tag = "3")]
    pub recovery_id: i32,
}