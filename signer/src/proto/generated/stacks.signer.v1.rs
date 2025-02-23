// This file is @generated by prost-build.
/// An identifier for a withdrawal request, comprised of the Stacks
/// transaction ID, the Stacks block ID that included the transaction, and
/// the request-id generated by the clarity contract for the withdrawal
/// request.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct QualifiedRequestId {
    /// The ID that was generated in the clarity contract call for the
    /// withdrawal request.
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    /// The txid that generated the request.
    #[prost(message, optional, tag = "2")]
    pub txid: ::core::option::Option<super::super::StacksTxid>,
    /// The Stacks block ID that includes the transaction that generated
    /// the request.
    #[prost(message, optional, tag = "3")]
    pub block_hash: ::core::option::Option<super::super::StacksBlockId>,
}
/// Describes the fees for a transaction.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct Fees {
    /// The total fee paid in sats for the transaction.
    #[prost(uint64, tag = "1")]
    pub total: u64,
    /// The fee rate paid in sats per virtual byte.
    #[prost(double, tag = "2")]
    pub rate: f64,
}
/// Represents a decision to accept or reject a deposit request.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct SignerDepositDecision {
    /// The bitcoin outpoint that uniquely identifies the deposit request.
    #[prost(message, optional, tag = "1")]
    pub outpoint: ::core::option::Option<super::super::super::bitcoin::OutPoint>,
    /// This specifies whether the sending signer's blocklist client blocked
    /// the deposit request. `true` here means the blocklist client did not
    /// block the request.
    #[prost(bool, tag = "2")]
    pub can_accept: bool,
    /// This specifies whether the sending signer can provide signature shares
    /// for the associated deposit request.
    #[prost(bool, tag = "3")]
    pub can_sign: bool,
}
/// Represents a decision to accept or reject a withdrawal request.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct SignerWithdrawalDecision {
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
/// Represents a signature of a Stacks transaction.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
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
/// Represents a request to sign a Stacks transaction.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StacksTransactionSignRequest {
    /// This is the bitcoin aggregate key that was output from DKG. It is used
    /// to identify the signing set for the transaction.
    #[prost(message, optional, tag = "1")]
    pub aggregate_key: ::core::option::Option<super::super::super::crypto::PublicKey>,
    /// The nonce to use for the transaction.
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    /// The transaction fee in microSTX.
    #[prost(uint64, tag = "3")]
    pub tx_fee: u64,
    /// The transaction ID of the associated contract call transaction.
    #[prost(message, optional, tag = "4")]
    pub txid: ::core::option::Option<super::super::StacksTxid>,
    /// The contract transaction to sign.
    #[prost(
        oneof = "stacks_transaction_sign_request::ContractTx",
        tags = "5, 6, 7, 8, 9"
    )]
    pub contract_tx: ::core::option::Option<stacks_transaction_sign_request::ContractTx>,
}
/// Nested message and enum types in `StacksTransactionSignRequest`.
pub mod stacks_transaction_sign_request {
    /// The contract transaction to sign.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContractTx {
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
        /// Ssmart contract deployment
        #[prost(enumeration = "super::SmartContract", tag = "9")]
        SmartContract(i32),
    }
}
/// For making a `complete-deposit` contract call in the sbtc-deposit
/// smart contract.
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
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcceptWithdrawal {
    /// The ID of the withdrawal request generated by the
    /// `initiate-withdrawal-request` function in the sbtc-withdrawal smart
    /// contract along with the transaction ID of the transaction that
    /// generated the request and block hash of the Stacks block that
    /// confirmed the transaction.
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<QualifiedRequestId>,
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
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectWithdrawal {
    /// The ID of the withdrawal request generated by the
    /// `initiate-withdrawal-request` function in the sbtc-withdrawal smart
    /// contract along with the transaction ID of the transaction that
    /// generated the request and block hash of the Stacks block that
    /// confirmed the transaction.
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<QualifiedRequestId>,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SmartContract {
    Unspecified = 0,
    /// The sbtc-registry contract. This contract needs to be deployed
    /// before any other contract.
    SbtcRegistry = 1,
    /// The sbtc-token contract. This contract needs to be deployed right
    /// after the sbtc-registry contract.
    SbtcToken = 2,
    /// The sbtc-deposit contract. Can be deployed after the sbtc-token
    /// contract.
    SbtcDeposit = 3,
    /// The sbtc-withdrawal contract. Can be deployed after the sbtc-token
    /// contract.
    SbtcWithdrawal = 4,
    /// The sbtc-bootstrap-signers contract. Can be deployed after the
    /// sbtc-token contract.
    SbtcBootstrap = 5,
}
impl SmartContract {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "SMART_CONTRACT_UNSPECIFIED",
            Self::SbtcRegistry => "SMART_CONTRACT_SBTC_REGISTRY",
            Self::SbtcToken => "SMART_CONTRACT_SBTC_TOKEN",
            Self::SbtcDeposit => "SMART_CONTRACT_SBTC_DEPOSIT",
            Self::SbtcWithdrawal => "SMART_CONTRACT_SBTC_WITHDRAWAL",
            Self::SbtcBootstrap => "SMART_CONTRACT_SBTC_BOOTSTRAP",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SMART_CONTRACT_UNSPECIFIED" => Some(Self::Unspecified),
            "SMART_CONTRACT_SBTC_REGISTRY" => Some(Self::SbtcRegistry),
            "SMART_CONTRACT_SBTC_TOKEN" => Some(Self::SbtcToken),
            "SMART_CONTRACT_SBTC_DEPOSIT" => Some(Self::SbtcDeposit),
            "SMART_CONTRACT_SBTC_WITHDRAWAL" => Some(Self::SbtcWithdrawal),
            "SMART_CONTRACT_SBTC_BOOTSTRAP" => Some(Self::SbtcBootstrap),
            _ => None,
        }
    }
}
/// Messages exchanged between signers
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignerMessage {
    /// / The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    #[prost(message, optional, tag = "1")]
    pub bitcoin_chain_tip: ::core::option::Option<
        super::super::super::bitcoin::BitcoinBlockHash,
    >,
    /// The message payload
    #[prost(oneof = "signer_message::Payload", tags = "2, 3, 4, 5, 8, 10, 11")]
    pub payload: ::core::option::Option<signer_message::Payload>,
}
/// Nested message and enum types in `SignerMessage`.
pub mod signer_message {
    /// The message payload
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        /// / A decision related to signer deposit
        #[prost(message, tag = "2")]
        SignerDepositDecision(super::SignerDepositDecision),
        /// A decision related to signer withdrawal
        #[prost(message, tag = "3")]
        SignerWithdrawalDecision(super::SignerWithdrawalDecision),
        /// A request to sign a Stacks transaction
        #[prost(message, tag = "4")]
        StacksTransactionSignRequest(super::StacksTransactionSignRequest),
        /// A signature of a Stacks transaction
        #[prost(message, tag = "5")]
        StacksTransactionSignature(super::StacksTransactionSignature),
        /// Contains all variants for DKG and WSTS signing rounds
        #[prost(message, tag = "8")]
        WstsMessage(super::WstsMessage),
        /// Information about a new sweep transaction
        #[prost(message, tag = "10")]
        BitcoinPreSignRequest(super::BitcoinPreSignRequest),
        /// Represents an acknowledgment of a BitcoinPreSignRequest
        #[prost(message, tag = "11")]
        BitcoinPreSignAck(super::BitcoinPreSignAck),
    }
}
/// A wsts message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WstsMessage {
    /// The wsts message
    #[prost(oneof = "wsts_message::Inner", tags = "2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub inner: ::core::option::Option<wsts_message::Inner>,
    #[prost(oneof = "wsts_message::Id", tags = "12, 13, 14")]
    pub id: ::core::option::Option<wsts_message::Id>,
}
/// Nested message and enum types in `WstsMessage`.
pub mod wsts_message {
    /// The wsts message
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        /// Tell signers to begin DKG by sending DKG public shares
        #[prost(message, tag = "2")]
        DkgBegin(super::super::super::super::crypto::wsts::DkgBegin),
        /// Send DKG public shares
        #[prost(message, tag = "3")]
        SignerDkgPublicShares(
            super::super::super::super::crypto::wsts::SignerDkgPublicShares,
        ),
        /// Tell signers to send DKG private shares
        #[prost(message, tag = "4")]
        DkgPrivateBegin(super::super::super::super::crypto::wsts::DkgPrivateBegin),
        /// Send DKG private shares
        #[prost(message, tag = "5")]
        DkgPrivateShares(super::super::super::super::crypto::wsts::DkgPrivateShares),
        /// Tell signers to compute shares and send DKG end
        #[prost(message, tag = "6")]
        DkgEndBegin(super::super::super::super::crypto::wsts::DkgEndBegin),
        /// Tell coordinator that DKG is complete
        #[prost(message, tag = "7")]
        DkgEnd(super::super::super::super::crypto::wsts::DkgEnd),
        /// Tell signers to send signing nonces
        #[prost(message, tag = "8")]
        NonceRequest(super::super::super::super::crypto::wsts::NonceRequest),
        /// Tell coordinator signing nonces
        #[prost(message, tag = "9")]
        NonceResponse(super::super::super::super::crypto::wsts::NonceResponse),
        /// Tell signers to construct signature shares
        #[prost(message, tag = "10")]
        SignatureShareRequest(
            super::super::super::super::crypto::wsts::SignatureShareRequest,
        ),
        /// Tell coordinator signature shares
        #[prost(message, tag = "11")]
        SignatureShareResponse(
            super::super::super::super::crypto::wsts::SignatureShareResponse,
        ),
    }
    #[derive(Clone, Copy, PartialEq, ::prost::Oneof)]
    pub enum Id {
        /// If this WSTS message is related to a Bitcoin signing round, this field
        /// will be set to the related Bitcoin transaction ID.
        #[prost(message, tag = "12")]
        Sweep(super::super::super::super::bitcoin::BitcoinTxid),
        /// If this WSTS message is related to a rotate-keys transaction, this field
        /// will be set to the _new_ aggregate public key being verified.
        #[prost(message, tag = "13")]
        DkgVerification(super::super::super::super::crypto::PublicKey),
        /// If this WSTS message is related to a DKG round, this field will be set
        /// to the 32-byte id determined based on the coordinator public key and
        /// block hash, set by the coordinator.
        #[prost(message, tag = "14")]
        Dkg(super::super::super::super::crypto::Uint256),
    }
}
/// Wraps an inner type with a public key and a signature,
/// allowing easy verification of the integrity of the inner data.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signed {
    /// A signature over the hash of the inner structure.
    #[prost(message, optional, tag = "1")]
    pub signature: ::core::option::Option<super::super::super::crypto::EcdsaSignature>,
    /// The public key of the signer that generated the signature.
    #[prost(message, optional, tag = "2")]
    pub signer_public_key: ::core::option::Option<
        super::super::super::crypto::PublicKey,
    >,
    /// The signed structure.
    #[prost(message, optional, tag = "3")]
    pub signer_message: ::core::option::Option<SignerMessage>,
}
/// Information about a new Bitcoin block sign request
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinPreSignRequest {
    /// The set of sBTC request identifiers. This contains each of the
    /// requests for the entire transaction package. Each element in the
    /// vector corresponds to the requests that will be included in a
    /// single bitcoin transaction.
    #[prost(message, repeated, tag = "1")]
    pub request_package: ::prost::alloc::vec::Vec<TxRequestIds>,
    /// The current market fee rate in sat/vByte.
    #[prost(double, tag = "2")]
    pub fee_rate: f64,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    #[prost(message, optional, tag = "3")]
    pub last_fees: ::core::option::Option<Fees>,
}
/// Represents an acknowledgment of a BitcoinPreSignRequest.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct BitcoinPreSignAck {}
/// This type is a container for all deposits and withdrawals that are part
/// of a transaction package.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxRequestIds {
    /// The deposit requests associated with the inputs in the transaction.
    #[prost(message, repeated, tag = "1")]
    pub deposits: ::prost::alloc::vec::Vec<super::super::super::bitcoin::OutPoint>,
    /// The withdrawal requests associated with the outputs in the current
    /// transaction.
    #[prost(message, repeated, tag = "2")]
    pub withdrawals: ::prost::alloc::vec::Vec<QualifiedRequestId>,
}
