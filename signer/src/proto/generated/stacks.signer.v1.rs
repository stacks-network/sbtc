// This file is @generated by prost-build.
/// Represents a decision to accept or reject a deposit request.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignerDepositDecision {
    /// The bitcoin transaction ID of the transaction containing the deposit
    /// request. It must be 32 bytes.
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<super::super::super::bitcoin::BitcoinTxid>,
    /// Index of the deposit request UTXO.
    #[prost(uint32, tag = "2")]
    pub output_index: u32,
    /// Whether or not the signer has accepted the deposit request.
    #[prost(bool, tag = "3")]
    pub accepted: bool,
}
/// Represents a decision to accept or reject a deposit request.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignerWithdrawDecision {
    /// ID of the withdraw request.
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    /// The Stacks block ID of the Stacks block containing the request. It
    /// must be 32 bytes.
    #[prost(message, optional, tag = "2")]
    pub block_id: ::core::option::Option<super::super::StacksBlockId>,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    #[prost(message, optional, tag = "3")]
    pub txid: ::core::option::Option<super::super::StacksTxid>,
    /// Whether or not the signer has accepted the withdrawal request.
    #[prost(bool, tag = "4")]
    pub accepted: bool,
}
/// Represents an acknowledgment of a signed Bitcoin transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinTransactionSignAck {
    /// The ID of the acknowledged transaction.
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<super::super::super::bitcoin::BitcoinTxid>,
}
/// Represents a signature of a Stacks transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksTransactionSignature {
    /// Id of the signed transaction.
    #[prost(message, optional, tag = "1")]
    pub txid: ::core::option::Option<super::super::StacksTxid>,
    /// A recoverable ECDSA signature over the transaction.
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<
        super::super::super::crypto::RecoverableSignature,
    >,
}
/// Represents a request to sign a Bitcoin transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinTransactionSignRequest {
    /// The transaction.
    #[prost(bytes = "vec", tag = "1")]
    pub tx: ::prost::alloc::vec::Vec<u8>,
    /// The aggregate key used to sign the transaction,
    #[prost(message, optional, tag = "2")]
    pub aggregate_key: ::core::option::Option<super::super::super::crypto::PublicKey>,
}
/// Represents a request to sign a Stacks transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksTransactionSignRequest {
    /// The aggregate public key that will sign the transaction.
    #[prost(message, optional, tag = "1")]
    pub aggregate_key: ::core::option::Option<super::super::super::crypto::PublicKey>,
    /// The nonce to use for the transaction.
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    /// The transaction fee in microSTX.
    #[prost(uint64, tag = "3")]
    pub tx_fee: u64,
    /// The expected digest of the transaction than needs to be signed. It's
    /// essentially a hash of the contract call struct, the nonce, the tx_fee
    /// and a few other things.
    #[prost(message, optional, tag = "4")]
    pub digest: ::core::option::Option<super::super::super::crypto::Uint256>,
    /// The contract call transaction to sign.
    #[prost(
        oneof = "stacks_transaction_sign_request::ContractCall",
        tags = "5, 6, 7, 8"
    )]
    pub contract_call: ::core::option::Option<
        stacks_transaction_sign_request::ContractCall,
    >,
}
/// Nested message and enum types in `StacksTransactionSignRequest`.
pub mod stacks_transaction_sign_request {
    /// The contract call transaction to sign.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContractCall {
        /// The `complete-deposit` contract call
        #[prost(message, tag = "5")]
        CompleteDeposit(super::CompleteDeposit),
        /// The `accept-withdrawal-request` contract call
        #[prost(message, tag = "6")]
        AcceptWithdrawal(super::AcceptWithdrawal),
        /// The `reject-withdrawal-request` contract call
        #[prost(message, tag = "7")]
        RejectWithdrawal(super::RejectWithdrawal),
        /// The `rotate-keys-wrapper` contract call
        #[prost(message, tag = "8")]
        RotateKeys(super::RotateKeys),
    }
}
/// For making a `complete-deposit` contract call in the sbtc-deposit
/// smart contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompleteDeposit {
    /// The outpoint of the bitcoin UTXO that was spent as a deposit for
    /// sBTC.
    #[prost(message, optional, tag = "1")]
    pub outpoint: ::core::option::Option<super::super::super::bitcoin::OutPoint>,
    /// The amount of sats swept in by the signers when they moved in the
    /// above UTXO.
    #[prost(uint64, tag = "2")]
    pub amount: u64,
    /// The address where the newly minted sBTC will be deposited.
    #[prost(message, optional, tag = "3")]
    pub recipient: ::core::option::Option<super::super::StacksPrincipal>,
    /// The address that deployed the sBTC smart contract containing the
    /// complete-deposit contract call.
    #[prost(message, optional, tag = "4")]
    pub deployer: ::core::option::Option<super::super::StacksAddress>,
    /// The transaction ID for the sweep transaction that moved the deposit
    /// UTXO into the signers' UTXO. One of the inputs to the sweep
    /// transaction must be the above `outpoint`.
    #[prost(message, optional, tag = "5")]
    pub sweep_txid: ::core::option::Option<super::super::super::bitcoin::BitcoinTxid>,
    /// The block hash of the bitcoin block that contains a sweep
    /// transaction with the above `outpoint` as one of its inputs.
    #[prost(message, optional, tag = "6")]
    pub sweep_block_hash: ::core::option::Option<
        super::super::super::bitcoin::BitcoinBlockHash,
    >,
    /// The block height associated with the above bitcoin block hash.
    #[prost(uint64, tag = "7")]
    pub sweep_block_height: u64,
}
/// For making a `accept-withdrawal-request` contract call in the
/// sbtc-withdrawal smart contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcceptWithdrawal {
    /// The ID of the withdrawal request generated by the
    /// `initiate-withdrawal-request` function in the sbtc-withdrawal smart
    /// contract.
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    /// The outpoint of the bitcoin UTXO that was spent to fulfill the
    /// withdrawal request.
    #[prost(message, optional, tag = "2")]
    pub outpoint: ::core::option::Option<super::super::super::bitcoin::OutPoint>,
    /// This is the assessed transaction fee for fulfilling the withdrawal
    /// request.
    #[prost(uint64, tag = "3")]
    pub tx_fee: u64,
    /// A bitmap of how the signers voted. The length of the list must be less
    /// than or equal to 128. Here, we assume that a true implies that the
    /// associated signer voted *against* the withdrawal.
    #[prost(bool, repeated, tag = "4")]
    pub signer_bitmap: ::prost::alloc::vec::Vec<bool>,
    /// The address that deployed the contract.
    #[prost(message, optional, tag = "5")]
    pub deployer: ::core::option::Option<super::super::StacksAddress>,
    /// The block hash of the bitcoin block that contains a sweep
    /// transaction with the above `outpoint` as one of its outputs.
    #[prost(message, optional, tag = "6")]
    pub sweep_block_hash: ::core::option::Option<
        super::super::super::bitcoin::BitcoinBlockHash,
    >,
    /// The block height associated with the above bitcoin block hash.
    #[prost(uint64, tag = "7")]
    pub sweep_block_height: u64,
}
/// For making a `reject-withdrawal-request` contract call in the
/// sbtc-withdrawal smart contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectWithdrawal {
    /// The ID of the withdrawal request generated by the
    /// `initiate-withdrawal-request` function in the sbtc-withdrawal smart
    /// contract.
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    /// A bitmap of how the signers voted. The length of the list must be less
    /// than or equal to 128. Here, we assume that a true implies that the
    /// associated signer voted *against* the withdrawal.
    #[prost(bool, repeated, tag = "2")]
    pub signer_bitmap: ::prost::alloc::vec::Vec<bool>,
    /// The address that deployed the smart contract.
    #[prost(message, optional, tag = "3")]
    pub deployer: ::core::option::Option<super::super::StacksAddress>,
}
/// For making a `rotate-keys-wrapper` contract call in the
/// `sbtc-bootstrap-signers` smart contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RotateKeys {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    #[prost(message, repeated, tag = "1")]
    pub new_keys: ::prost::alloc::vec::Vec<super::super::super::crypto::PublicKey>,
    /// The aggregate key created by combining the above public keys.
    #[prost(message, optional, tag = "2")]
    pub aggregate_key: ::core::option::Option<super::super::super::crypto::PublicKey>,
    /// The address that deployed the contract.
    #[prost(message, optional, tag = "3")]
    pub deployer: ::core::option::Option<super::super::StacksAddress>,
    /// The number of signatures required for the multi-sig wallet.
    #[prost(uint32, tag = "4")]
    pub signatures_required: u32,
}
