//! Database models for the signer.

use std::ops::Range;

use bitcoin::hashes::Hash as _;
use bitcoin::Address;
use bitcoin::Network;
use rand::seq::IteratorRandom as _;
use sbtc::deposits::Deposit;

#[cfg(feature = "testing")]
use fake::faker::time::en::DateTimeAfter;

/// Bitcoin block.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinBlock {
    /// Block hash.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub block_hash: BitcoinBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub parent_hash: BitcoinBlockHash,
    /// Stacks block confirmed by this block.
    #[cfg_attr(feature = "testing", dummy(default))]
    pub confirms: Vec<StacksBlockHash>,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// Stacks block.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct StacksBlock {
    /// Block hash.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub block_hash: StacksBlockHash,
    /// Block height.
    pub block_height: i64,
    /// Hash of the parent block.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub parent_hash: StacksBlockHash,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// Deposit request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositRequest {
    /// Transaction ID of the deposit request transaction.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub txid: BitcoinTxId,
    /// Index of the deposit request UTXO.
    #[cfg_attr(feature = "testing", dummy(faker = "0..100"))]
    pub output_index: i32,
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
    #[cfg_attr(feature = "testing", dummy(faker = "BitcoinAddresses(1..5)"))]
    pub sender_addresses: Vec<BitcoinAddress>,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// Used to for fine-grained control of generating fake testing addresses.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct BitcoinAddresses(Range<usize>);

#[cfg(feature = "testing")]
impl fake::Dummy<BitcoinAddresses> for Vec<String> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &BitcoinAddresses, rng: &mut R) -> Self {
        let num_addresses = config.0.clone().choose(rng).unwrap_or(1);
        std::iter::repeat_with(|| secp256k1::Keypair::new_global(rng))
            .take(num_addresses)
            .map(|kp| {
                let pk = bitcoin::CompressedPublicKey(kp.public_key());
                Address::p2wpkh(&pk, Network::Regtest).to_string()
            })
            .collect()
    }
}

impl DepositRequest {
    /// Create me from a full deposit.
    pub fn from_deposit(deposit: &Deposit, network: Network) -> Self {
        let tx_input_iter = deposit.tx.input.iter();
        // It's most likely the case that each of the inputs "come" from
        // the same Address, so we filter out duplicates.
        let sender_addresses: std::collections::HashSet<String> = tx_input_iter
            .flat_map(|tx_in| {
                Address::from_script(&tx_in.script_sig, network)
                    .inspect_err(|err| tracing::warn!("could not create address: {err}"))
                    .map(|address| address.to_string())
            })
            .collect();
        Self {
            txid: deposit.info.outpoint.txid.to_byte_array().to_vec(),
            output_index: deposit.info.outpoint.vout as i32,
            spend_script: deposit.info.deposit_script.to_bytes(),
            reclaim_script: deposit.info.reclaim_script.to_bytes(),
            recipient: deposit.info.recipient.to_string(),
            amount: deposit.info.amount as i64,
            max_fee: deposit.info.max_fee as i64,
            sender_addresses: sender_addresses.into_iter().collect(),
            created_at: time::OffsetDateTime::now_utc(),
        }
    }
}

/// A signer acknowledging a deposit request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositSigner {
    /// TxID of the deposit request.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub txid: BitcoinTxId,
    /// Output index of the deposit request.
    #[cfg_attr(feature = "testing", dummy(faker = "0..100"))]
    pub output_index: i32,
    /// Public key of the signer.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub signer_pub_key: PubKey,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// Withdraw request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawRequest {
    /// Request ID of the withdrawal request.
    pub request_id: i32,
    /// Stacks block hash of the withdrawal request.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub block_hash: StacksBlockHash,
    /// The address that should receive the BTC withdrawal.
    pub recipient: BitcoinAddress,
    /// The amount to withdraw.
    pub amount: i64,
    /// The maximum portion of the withdrawn amount that may
    /// be used to pay for transaction fees.
    pub max_fee: i64,
    /// The address that initiated the request.
    pub sender_address: StacksAddress,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// A signer acknowledging a withdrawal request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawSigner {
    /// Request ID of the withdrawal request.
    pub request_id: i32,
    /// Stacks block hash of the withdrawal request.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub block_hash: StacksBlockHash,
    /// Public key of the signer.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub signer_pub_key: PubKey,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
    /// The time this block entry was created by the signer.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH)")
    )]
    pub created_at: time::OffsetDateTime,
}

/// A connection between a bitcoin block and a bitcoin transaction.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinTransaction {
    /// Transaction ID.
    pub txid: BitcoinTxId,
    /// The block in which the transaction exists.
    pub block_hash: BitcoinBlockHash,
}

/// A connection between a bitcoin block and a bitcoin transaction.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct StacksTransaction {
    /// Transaction ID.
    pub txid: StacksTxId,
    /// The block in which the transaction exists.
    pub block_hash: StacksBlockHash,
}

/// For writing to the stacks_transactions or bitcoin_transactions table.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionIds {
    /// Transaction IDs.
    pub tx_ids: Vec<Vec<u8>>,
    /// The blocks in which the transactions exist.
    pub block_hashes: Vec<Vec<u8>>,
}

/// A raw transaction on either Bitcoin or Stacks.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct Transaction {
    /// Transaction ID.
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub txid: Bytes,
    /// Encoded transaction.
    pub tx: Bytes,
    /// The type of the transaction.
    pub tx_type: TransactionType,
    /// The block id of the stacks block that includes this transaction
    #[cfg_attr(feature = "testing", dummy(expr = "fake::vec![u8; 32]"))]
    pub block_hash: Bytes,
}

/// Persisted DKG shares
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct EncryptedDkgShares {
    /// The aggregate key for these shares
    pub aggregate_key: PubKey,
    /// The tweaked aggregate key for these shares
    pub tweaked_aggregate_key: PubKey,
    /// The `scriptPubKey` for the aggregate public key.
    pub script_pubkey: Bytes,
    /// The encrypted DKG shares
    pub encrypted_shares: Bytes,
    /// The time this entry was created by the signer.
    pub created_at: time::OffsetDateTime,
}

/// The types of transactions the signer is interested in.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type, strum::Display)]
#[sqlx(type_name = "sbtc_signer.transaction_type", rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
#[strum(serialize_all = "snake_case")]
pub enum TransactionType {
    /// An sBTC transaction on Bitcoin.
    SbtcTransaction,
    /// A deposit request transaction on Bitcoin.
    DepositRequest,
    /// A withdrawal request transaction on Stacks.
    WithdrawRequest,
    /// A deposit accept transaction on Stacks.
    DepositAccept,
    /// A withdrawal accept transaction on Stacks.
    WithdrawAccept,
    /// A withdraw reject transaction on Stacks.
    WithdrawReject,
    /// An update signer set call on Stacks.
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
/// Stacks transaction ID
pub type StacksTxId = Vec<u8>;
/// Arbitrary bytes
pub type Bytes = Vec<u8>;
/// Secp256k1 Pubkey in compressed form
pub type PubKey = Vec<u8>;
/// Bitcoin address
pub type BitcoinAddress = String;
/// Stacks address
pub type StacksAddress = String;
