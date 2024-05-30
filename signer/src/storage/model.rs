//! Database models for the signer.

/// Bitcoin block.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinBlock {
    /// Block hash.
    pub block_hash: BitcoinBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    pub parent_hash: BitcoinBlockHash,
    /// Stacks block confirmed by this block.
    pub confirms: Option<StacksBlockHash>,
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// Stacks block.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct StacksBlock {
    /// Block hash.
    pub block_hash: StacksBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    pub parent_hash: StacksBlockHash,
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// Deposit request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositRequest {
    /// Transaction ID of the deposit request transaction.
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
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// A signer acknowledging a deposit request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositSigner {
    /// TxID of the deposit request.
    pub txid: BitcoinTxId,
    /// Ouput index of the deposit request.
    pub output_index: usize,
    /// Public key of the signer.
    pub signer_pub_key: Bytes,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// Withdraw request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawRequest {
    /// Request ID of the withdraw request.
    pub request_id: i64,
    /// Stacks block hash of the withdraw request.
    pub block_hash: StacksBlockHash,
    /// The address that shuld receive the BTC withdrawal.
    pub recipient: BitcoinAddress,
    /// The amount to withdraw.
    pub amount: i64,
    /// The maximum portion of the withdrawn amount that may
    /// be used to pay for transaction fees.
    pub max_fee: i64,
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// A signer acknowledging a withdrawal request.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawSigner {
    /// Request ID of the withdraw request.
    pub request_id: i64,
    /// Stacks block hash of the withdraw request.
    pub block_hash: StacksBlockHash,
    /// Public key of the signer.
    pub signer_pub_key: Bytes,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    pub created_at: time::PrimitiveDateTime,
}

/// A transaction on either Bitcoin or Stacks
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct Transaction {
    txid: Bytes,
    tx: Bytes,
    tx_type: TransactionType,
}

/// The types of transactions the signer is interested in.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum TransactionType {
    /// An sBTC transaction on Bitcoin.
    SbtcTransaction,
    /// A withdraw accept transaction on Stacks.
    WithdrawAccept,
    /// A withdraw reject transaction on Stacks.
    WithdrawReject,
    /// A deposit accept transaction on Stacks.
    DepositAccept,
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
/// Bitcoin address
pub type BitcoinAddress = String;
/// Stacks address
pub type StacksAddress = String;
