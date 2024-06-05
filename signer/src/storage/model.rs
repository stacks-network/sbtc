//! Database models for the signer.

use fake::faker::time::en::DateTimeAfter;

/// Bitcoin block.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinBlock {
    /// Block hash.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub block_hash: BitcoinBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub parent_hash: BitcoinBlockHash,
    /// Stacks block confirmed by this block.
    #[dummy(default)]
    pub confirms: Option<StacksBlockHash>,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// Stacks block.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct StacksBlock {
    /// Block hash.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub block_hash: StacksBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub parent_hash: StacksBlockHash,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// Deposit request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositRequest {
    /// Transaction ID of the deposit request transaction.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub txid: BitcoinTxId,
    /// Index of the deposit request UTXO.
    pub output_index: usize,
    /// Script spendable by the sBTC signers.
    pub spend_script: Bytes,
    /// Script spendable by the depositor.
    pub reclaim_script: Bytes,
    /// The address of which the sBTC should be minted,
    /// can be a smart contract address.
    pub recipient: StacksAddress,
    /// The amount deposited.
    pub amount: i64,
    /// The maximum portion of the deposited amount that may
    /// be used to pay for transaction fees.
    pub max_fee: i64,
    /// The addresses of the input UTXOs funding the deposit request.
    #[dummy(expr = "fake::vec![String; 1..8]")]
    pub sender_addresses: Vec<BitcoinAddress>,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// A signer acknowledging a deposit request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositSigner {
    /// TxID of the deposit request.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub txid: BitcoinTxId,
    /// Ouput index of the deposit request.
    pub output_index: usize,
    /// Public key of the signer.
    pub signer_pub_key: PubKey,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// Withdraw request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawRequest {
    /// Request ID of the withdraw request.
    pub request_id: i64,
    /// Stacks block hash of the withdraw request.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub block_hash: StacksBlockHash,
    /// The address that shuld receive the BTC withdrawal.
    pub recipient: BitcoinAddress,
    /// The amount to withdraw.
    pub amount: i64,
    /// The maximum portion of the withdrawn amount that may
    /// be used to pay for transaction fees.
    pub max_fee: i64,
    /// The address that initiated the request.
    pub sender_address: StacksAddress,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// A signer acknowledging a withdrawal request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawSigner {
    /// Request ID of the withdraw request.
    pub request_id: i64,
    /// Stacks block hash of the withdraw request.
    #[dummy(expr = "fake::vec![u8; 32]")]
    pub block_hash: StacksBlockHash,
    /// Public key of the signer.
    pub signer_pub_key: PubKey,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// A connection between a bitcoin block and a bitcoin transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTransaction {
    /// Transaction ID.
    pub txid: BitcoinTxId,
    /// The block in which the transaction exists.
    pub block_hash: BitcoinBlockHash,
}

/// A raw transaction on either Bitcoin or Stacks.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct Transaction {
    /// Transaction ID.
    pub txid: Bytes,
    /// Encoded transaction.
    pub tx: Bytes,
    /// The type of the transaction.
    pub tx_type: TransactionType,
    /// The time this transaction entry was created by the signer.
    #[dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")]
    pub created_at: time::OffsetDateTime,
}

/// The types of transactions the signer is interested in.
#[derive(Debug, Clone, PartialEq, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "sbtc_signer.transaction_type", rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum TransactionType {
    /// An sBTC transaction on Bitcoin.
    SbtcTransaction,
    /// A deposit request transaction on Bitcoin.
    DepositRequest,
    /// A withdraw request transaction on Stacks.
    WithdrawRequest,
    /// A deposit accept transaction on Stacks.
    DepositAccept,
    /// A withdraw accept transaction on Stacks.
    WithdrawAccept,
    /// A withdraw reject transaction on Stacks.
    WithdrawReject,
    /// A update signer set call on Stacks.
    UpdateSignerSet,
    /// A set aggregate key call on Stacks.
    SetAggregateKey,
}

/// A stacks transaction

/// Bitcoin block hash
pub type BitcoinBlockHash = Vec<u8>;
/// Stacks block hash
pub type StacksBlockHash = Vec<u8>;
/// Bitcoin transaction ID
pub type BitcoinTxId = Vec<u8>;
/// Arbitrary bytes
pub type Bytes = Vec<u8>;
/// Secp256k1 Pubkey in compressed form
pub type PubKey = [u8; 33];
/// Bitcoin address
pub type BitcoinAddress = String;
/// Stacks address
pub type StacksAddress = String;
