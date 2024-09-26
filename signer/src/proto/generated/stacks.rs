// This file is @generated by prost-build.
/// The id for a transaction on the bitcoin blockchain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinTxid {
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<super::crypto::Uint256>,
}
/// A bitcoin block hash.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinBlockHash {
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<super::crypto::Uint256>,
}
/// A pointer to a specific output in a bitcoin transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutPoint {
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<BitcoinTxid>,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
}
/// Represents a standard address on the Stacks blockchain
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksAddress {
    /// The consensus serialized bytes of the Stacks address defined in
    /// SIP-005.
    #[prost(bytes = "vec", tag = "1")]
    pub address: ::prost::alloc::vec::Vec<u8>,
}
/// This type maps to the StacksBlockId in the stackslib Rust crate.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksBlockId {
    #[prost(message, optional, tag = "1")]
    pub block_id: ::core::option::Option<super::crypto::Uint256>,
}
/// The protobuf representation of the clarity::vm::types::PrincipalData
/// type. It represents either a standard Stacks Address or a contract
/// address.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksPrincipal {
    /// The consensus serialized bytes of the Stacks PrincipalData.
    #[prost(bytes = "vec", tag = "1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// The id for a transaction on the stacks blockchain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksTxid {
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<super::crypto::Uint256>,
}
