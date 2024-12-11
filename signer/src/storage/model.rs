//! Database models for the signer.

use std::collections::BTreeSet;
use std::ops::Deref;

use bitvec::array::BitArray;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use clarity::vm::types::PrincipalData;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;

use crate::bitcoin::utxo;
use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::InputValidationResult;
use crate::bitcoin::validation::WithdrawalValidationResult;
use crate::block_observer::Deposit;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;

use std::collections::BTreeMap;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash as EventsBitcoinBlockHash;
use bitcoin::OutPoint;
use bitcoin::PubkeyHash;
use bitcoin::ScriptBuf;
use bitcoin::ScriptHash;
use bitcoin::Txid as BitcoinTxid;
use bitcoin::WitnessProgram;
use bitcoin::WitnessVersion;
use blockstack_lib::burnchains::Txid as StacksTxid;
use clarity::vm::types::CharType;
use clarity::vm::types::SequenceData;
use clarity::vm::types::TupleData;
use clarity::vm::ClarityName;
use clarity::vm::Value as ClarityValue;
use secp256k1::PublicKey as EventsPublicKey;

/// Represents a single transaction which is part of a sweep transaction package
/// which has been broadcast to the Bitcoin network.
#[derive(Debug, Clone, PartialEq, PartialOrd, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SweepTransaction {
    /// The Bitcoin transaction id.
    pub txid: BitcoinTxId,
    /// The transaction id of the signer UTXO consumed by this transaction.
    pub signer_prevout_txid: BitcoinTxId,
    /// The index of the signer UTXO consumed by this transaction.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub signer_prevout_output_index: u32,
    /// The amount of the signer UTXO consumed by this transaction.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u64"))]
    pub signer_prevout_amount: u64,
    /// The public key of the signer UTXO consumed by this transaction.
    pub signer_prevout_script_pubkey: ScriptPubKey,
    /// The total **output** amount of this transaction.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u64"))]
    pub amount: u64,
    /// The fee paid for this transaction.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u64"))]
    pub fee: u64,
    /// The virtual size of this transaction (in bytes).
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub vsize: u32,
    /// The Bitcoin block hash at which this transaction was created.
    pub created_at_block_hash: BitcoinBlockHash,
    /// The market fee rate at the time of this transaction.
    pub market_fee_rate: f64,
    /// List of deposits which were swept-in by this transaction.
    #[sqlx(skip)]
    pub swept_deposits: Vec<SweptDeposit>,
    /// List of withdrawals which were swept-out by this transaction.
    #[sqlx(skip)]
    pub swept_withdrawals: Vec<SweptWithdrawal>,
}

impl SweepTransaction {
    /// Return the outpoint of the signer's UTXO consumed by this transaction.
    pub fn signer_prevout_outpoint(&self) -> bitcoin::OutPoint {
        bitcoin::OutPoint {
            txid: self.signer_prevout_txid.into(),
            vout: self.signer_prevout_output_index,
        }
    }
}

impl From<&crate::message::SweepTransactionInfo> for SweepTransaction {
    fn from(info: &crate::message::SweepTransactionInfo) -> Self {
        Self {
            txid: info.txid.into(),
            signer_prevout_txid: info.signer_prevout_txid.into(),
            signer_prevout_output_index: info.signer_prevout_output_index,
            signer_prevout_amount: info.signer_prevout_amount,
            signer_prevout_script_pubkey: info.signer_prevout_script_pubkey.clone().into(),
            amount: info.amount,
            fee: info.fee,
            vsize: info.vsize,
            market_fee_rate: info.market_fee_rate,
            created_at_block_hash: info.created_at_block_hash.into(),
            swept_deposits: info.swept_deposits.iter().map(Into::into).collect(),
            swept_withdrawals: info.swept_withdrawals.iter().map(Into::into).collect(),
        }
    }
}

impl utxo::GetFees for Vec<SweepTransaction> {
    /// Return the total fee of all the transactions in the vector.
    fn get_fees(&self) -> Result<Option<Fees>, Error> {
        // If there are no transactions then we have no basis for calculation,
        // so we return `None`.
        if self.is_empty() {
            return Ok(None);
        }

        // This should never realistically happen in prod, but we do
        // checked-math to ensure that we don't panic in case of overflow.
        let total: u64 = self
            .iter()
            .map(|tx| tx.fee)
            .try_fold(0u64, |acc, fee| acc.checked_add(fee))
            .ok_or(Error::ArithmeticOverflow)?;

        // This should never realistically happen in prod either.
        let total_size: u64 = self
            .iter()
            .map(|tx| tx.vsize as u64)
            .try_fold(0u64, |acc, size| acc.checked_add(size))
            .ok_or(Error::ArithmeticOverflow)?;

        // This should never realistically happen in prod either.
        if total_size == 0 {
            return Err(Error::DivideByZero);
        }

        let fees = Some(Fees {
            total,
            rate: total as f64 / total_size as f64,
        });

        Ok(fees)
    }
}

/// Represents a single deposit which has been swept-in by a sweep transaction.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SweptDeposit {
    /// The index of the deposit input in the sBTC sweep transaction.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub input_index: u32,
    /// The Bitcoin txid of the deposit request UTXO being swept-in by this
    /// transaction.
    pub deposit_request_txid: BitcoinTxId,
    /// The Bitcoin output index of the deposit request UTXO being swept-in by
    /// this transaction.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub deposit_request_output_index: u32,
}

impl From<SweptDeposit> for bitcoin::OutPoint {
    fn from(deposit: SweptDeposit) -> Self {
        bitcoin::OutPoint {
            txid: deposit.deposit_request_txid.into(),
            vout: deposit.deposit_request_output_index,
        }
    }
}

impl From<&crate::message::SweptDeposit> for SweptDeposit {
    fn from(deposit: &crate::message::SweptDeposit) -> Self {
        Self {
            input_index: deposit.input_index,
            deposit_request_txid: deposit.deposit_request_txid.into(),
            deposit_request_output_index: deposit.deposit_request_output_index,
        }
    }
}

/// A bitcoin transaction output (TXO) relevant for the sBTC signers.
///
/// This object can have a few different meanings, all of them identified
/// by the output_type:
/// 1. Whether a TXO was created by someone other than the signers as a
///    donation.
/// 2. Whether this is the signers' TXO with all of the swept in funds.
/// 3. Whether it is an `OP_RETURN` output.
/// 4. Whether this is a withdrawal output.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct TxOutput {
    /// The Bitcoin transaction id.
    pub txid: BitcoinTxId,
    /// The index of the output in the sBTC sweep transaction.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub output_index: u32,
    /// The scriptPubKey locking the output.
    pub script_pubkey: ScriptPubKey,
    /// The amount created in the output.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "1_000_000..1_000_000_000"))]
    pub amount: u64,
    /// The scriptPubKey locking the output.
    pub output_type: TxOutputType,
}

/// A bitcoin transaction output being spent as an input in a transaction.
///
/// This object can have two different meanings: whether or not this is a
/// deposit output being swept in.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct TxPrevout {
    /// The ID of the transaction spending the output.
    pub txid: BitcoinTxId,
    /// The ID of the bitcoin transaction that created the output being
    /// spent.
    pub prevout_txid: BitcoinTxId,
    /// The output index in the transaction that created the output that is
    /// being spent.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub prevout_output_index: u32,
    /// The scriptPubKey locking the output.
    pub script_pubkey: ScriptPubKey,
    /// The amount locked in the output.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "1_000_000..1_000_000_000"))]
    pub amount: u64,
    /// The type prevout we are referring to.
    pub prevout_type: TxPrevoutType,
}

/// Represents a single withdrawal which has been swept-out by a sweep
/// transaction.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SweptWithdrawal {
    /// The index of the withdrawal output in the sBTC sweep transaction.
    #[sqlx(try_from = "i32")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub output_index: u32,
    /// The public request id of the withdrawal request serviced by this
    /// transaction.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i64::MAX as u64"))]
    pub withdrawal_request_id: u64,
    /// The Stacks block hash of the Stacks block which included the withdrawal
    /// request transaction.
    pub withdrawal_request_block_hash: StacksBlockHash,
}

impl From<&crate::message::SweptWithdrawal> for SweptWithdrawal {
    fn from(withdrawal: &crate::message::SweptWithdrawal) -> Self {
        Self {
            output_index: withdrawal.output_index,
            withdrawal_request_id: withdrawal.withdrawal_request_id,
            withdrawal_request_block_hash: withdrawal.withdrawal_request_block_hash.into(),
        }
    }
}

/// Bitcoin block.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinBlock {
    /// Block hash.
    pub block_hash: BitcoinBlockHash,
    /// Block height.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..i64::MAX as u64"))]
    pub block_height: u64,
    /// Hash of the parent block.
    pub parent_hash: BitcoinBlockHash,
}

impl From<&bitcoin::Block> for BitcoinBlock {
    fn from(block: &bitcoin::Block) -> Self {
        BitcoinBlock {
            block_hash: block.block_hash().into(),
            block_height: block
                .bip34_block_height()
                .expect("Failed to get block height"),
            parent_hash: block.header.prev_blockhash.into(),
        }
    }
}

impl From<bitcoin::Block> for BitcoinBlock {
    fn from(block: bitcoin::Block) -> Self {
        BitcoinBlock::from(&block)
    }
}

/// Stacks block.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct StacksBlock {
    /// Block hash.
    pub block_hash: StacksBlockHash,
    /// Block height.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "0..u32::MAX as u64"))]
    pub block_height: u64,
    /// Hash of the parent block.
    pub parent_hash: StacksBlockHash,
    /// The bitcoin block this stacks block is build upon (matching consensus hash)
    pub bitcoin_anchor: BitcoinBlockHash,
}

impl StacksBlock {
    /// Construct a StacksBlock from a NakamotoBlock and its bitcoin anchor
    pub fn from_nakamoto_block(block: &NakamotoBlock, bitcoin_anchor: &BitcoinBlockHash) -> Self {
        Self {
            block_hash: block.block_id().into(),
            block_height: block.header.chain_length,
            parent_hash: block.header.parent_block_id.into(),
            bitcoin_anchor: *bitcoin_anchor,
        }
    }
}

/// Deposit request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositRequest {
    /// Transaction ID of the deposit request transaction.
    pub txid: BitcoinTxId,
    /// Index of the deposit request UTXO.
    #[cfg_attr(feature = "testing", dummy(faker = "0..100"))]
    #[sqlx(try_from = "i32")]
    pub output_index: u32,
    /// Script spendable by the sBTC signers.
    pub spend_script: Bytes,
    /// Script spendable by the depositor.
    pub reclaim_script: Bytes,
    /// The address of which the sBTC should be minted,
    /// can be a smart contract address.
    pub recipient: StacksPrincipal,
    /// The amount in the deposit UTXO.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "1_000_000..1_000_000_000"))]
    pub amount: u64,
    /// The maximum portion of the deposited amount that may
    /// be used to pay for transaction fees.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..100_000"))]
    pub max_fee: u64,
    /// The relative lock time in the reclaim script.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "3..u16::MAX as u32"))]
    pub lock_time: u32,
    /// The public key used in the deposit script. The signers public key
    /// is for Schnorr signatures.
    pub signers_public_key: PublicKeyXOnly,
    /// The addresses of the input UTXOs funding the deposit request.
    #[cfg_attr(
        feature = "testing",
        dummy(faker = "crate::testing::dummy::BitcoinAddresses(1..5)")
    )]
    pub sender_script_pub_keys: Vec<ScriptPubKey>,
}

impl From<Deposit> for DepositRequest {
    fn from(deposit: Deposit) -> Self {
        let tx_input_iter = deposit.tx_info.vin.into_iter();
        // It's most likely the case that each of the inputs "came" from
        // the same Address, so we filter out duplicates.
        let sender_script_pub_keys: BTreeSet<ScriptPubKey> = tx_input_iter
            .map(|tx_in| tx_in.prevout.script_pub_key.script.into())
            .collect();

        Self {
            txid: deposit.info.outpoint.txid.into(),
            output_index: deposit.info.outpoint.vout,
            spend_script: deposit.info.deposit_script.to_bytes(),
            reclaim_script: deposit.info.reclaim_script.to_bytes(),
            recipient: deposit.info.recipient.into(),
            amount: deposit.info.amount,
            max_fee: deposit.info.max_fee,
            lock_time: deposit.info.lock_time.to_consensus_u32(),
            signers_public_key: deposit.info.signers_public_key.into(),
            sender_script_pub_keys: sender_script_pub_keys.into_iter().collect(),
        }
    }
}

impl DepositRequest {
    /// Return the outpoint associated with the deposit request.
    pub fn outpoint(&self) -> bitcoin::OutPoint {
        bitcoin::OutPoint {
            txid: self.txid.into(),
            vout: self.output_index,
        }
    }
}

/// A signer acknowledging a deposit request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct DepositSigner {
    /// TxID of the deposit request.
    pub txid: BitcoinTxId,
    /// Output index of the deposit request.
    #[cfg_attr(feature = "testing", dummy(faker = "0..100"))]
    #[sqlx(try_from = "i32")]
    pub output_index: u32,
    /// Public key of the signer.
    pub signer_pub_key: PublicKey,
    /// Signals if the signer will sign for this request if able.
    pub can_accept: bool,
    /// This specifies whether the indicated signer_pub_key can sign for
    /// the associated deposit request.
    pub can_sign: bool,
}

/// Withdraw request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawalRequest {
    /// Request ID of the withdrawal request. These are supposed to be
    /// unique, but there can be duplicates if there is a reorg that
    /// affects a transaction that calls the initiate-withdrawal-request
    /// public function.
    #[sqlx(try_from = "i64")]
    pub request_id: u64,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub txid: StacksTxId,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    pub block_hash: StacksBlockHash,
    /// The address that should receive the BTC withdrawal.
    pub recipient: ScriptPubKey,
    /// The amount to withdraw.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..1_000_000_000"))]
    pub amount: u64,
    /// The maximum portion of the withdrawn amount that may
    /// be used to pay for transaction fees.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..10000"))]
    pub max_fee: u64,
    /// The address that initiated the request.
    pub sender_address: StacksPrincipal,
}

impl WithdrawalRequest {
    /// Return the identifier for the withdrawal request.
    pub fn qualified_id(&self) -> QualifiedRequestId {
        QualifiedRequestId {
            request_id: self.request_id,
            txid: self.txid,
            block_hash: self.block_hash,
        }
    }
}

/// A signer acknowledging a withdrawal request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct WithdrawalSigner {
    /// Request ID of the withdrawal request.
    #[sqlx(try_from = "i64")]
    pub request_id: u64,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub txid: StacksTxId,
    /// Stacks block hash of the withdrawal request.
    pub block_hash: StacksBlockHash,
    /// Public key of the signer.
    pub signer_pub_key: PublicKey,
    /// Signals if the signer is prepared to sign for this request.
    pub is_accepted: bool,
}

impl WithdrawalSigner {
    /// Return the identifier for the withdrawal request.
    pub fn qualified_id(&self) -> QualifiedRequestId {
        QualifiedRequestId {
            request_id: self.request_id,
            txid: self.txid,
            block_hash: self.block_hash,
        }
    }
}

/// A connection between a bitcoin block and a bitcoin transaction.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
pub struct BitcoinTxRef {
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
    pub tx_ids: Vec<[u8; 32]>,
    /// The blocks in which the transactions exist.
    pub block_hashes: Vec<[u8; 32]>,
}

/// A raw transaction on either Bitcoin or Stacks.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct Transaction {
    /// Transaction ID.
    pub txid: [u8; 32],
    /// Encoded transaction.
    pub tx: Bytes,
    /// The type of the transaction.
    pub tx_type: TransactionType,
    /// The block id of the stacks block that includes this transaction
    pub block_hash: [u8; 32],
}

/// A deposit request with a response bitcoin transaction that has been
/// confirmed.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SweptDepositRequest {
    /// The transaction ID of the bitcoin transaction that swept in the
    /// funds into the signers' UTXO.
    pub sweep_txid: BitcoinTxId,
    /// The block id of the bitcoin block that includes the sweep
    /// transaction.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The block height of the block referenced by the `sweep_block_hash`.
    #[sqlx(try_from = "i64")]
    pub sweep_block_height: u64,
    /// Transaction ID of the deposit request transaction.
    pub txid: BitcoinTxId,
    /// Index of the deposit request UTXO.
    #[cfg_attr(feature = "testing", dummy(faker = "0..100"))]
    #[sqlx(try_from = "i32")]
    pub output_index: u32,
    /// The address of which the sBTC should be minted,
    /// can be a smart contract address.
    pub recipient: StacksPrincipal,
    /// The amount in the deposit UTXO.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "1_000_000..1_000_000_000"))]
    pub amount: u64,
    /// The maximum portion of the deposited amount that may
    /// be used to pay for transaction fees.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..100_000"))]
    pub max_fee: u64,
}

impl SweptDepositRequest {
    /// The OutPoint of the actual deposit
    pub fn deposit_outpoint(&self) -> bitcoin::OutPoint {
        bitcoin::OutPoint {
            txid: self.txid.into(),
            vout: self.output_index,
        }
    }
}

/// Withdraw request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SweptWithdrawalRequest {
    /// The transaction ID of the bitcoin transaction that swept out the
    /// funds to the intended recipient.
    pub sweep_txid: BitcoinTxId,
    /// The block id of the stacks block that includes this sweep
    /// transaction.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The block height of the block that includes the sweep transaction.
    #[sqlx(try_from = "i64")]
    pub sweep_block_height: u64,
    /// Request ID of the withdrawal request. These are supposed to be
    /// unique, but there can be duplicates if there is a reorg that
    /// affects a transaction that calls the `initiate-withdrawal-request`
    /// public function.
    #[sqlx(try_from = "i64")]
    pub request_id: u64,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub txid: StacksTxId,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    pub block_hash: StacksBlockHash,
    /// The ScriptPubKey that should receive the BTC withdrawal.
    pub recipient: ScriptPubKey,
    /// The amount of satoshis to withdraw.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..1_000_000_000"))]
    pub amount: u64,
    /// The maximum amount that may be spent as for the bitcoin miner
    /// transaction fee.
    #[sqlx(try_from = "i64")]
    #[cfg_attr(feature = "testing", dummy(faker = "100..10000"))]
    pub max_fee: u64,
    /// The stacks address that initiated the request. This is populated
    /// using `tx-sender`.
    pub sender_address: StacksPrincipal,
}

/// Persisted DKG shares
///
/// This struct represents the output of a successful run of distributed
/// key generation (DKG) that was run by a set of signers.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct EncryptedDkgShares {
    /// The aggregate key for these shares
    pub aggregate_key: PublicKey,
    /// The tweaked aggregate key for these shares
    pub tweaked_aggregate_key: PublicKey,
    /// The `scriptPubKey` for the aggregate public key.
    pub script_pubkey: ScriptPubKey,
    /// The encrypted DKG shares
    pub encrypted_private_shares: Bytes,
    /// The public DKG shares
    pub public_shares: Bytes,
    /// The set of public keys that were a party to the DKG.
    pub signer_set_public_keys: Vec<PublicKey>,
    /// The threshold number of signature shares required to generate a
    /// Schnorr signature.
    ///
    /// In WSTS each signer may contribute a fixed portion of a single
    /// signature. This value specifies the total number of portions
    /// (shares) that are needed in order to construct a signature.
    #[sqlx(try_from = "i32")]
    pub signature_share_threshold: u16,
}

/// Persisted public DKG shares from other signers
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct RotateKeysTransaction {
    /// Transaction ID.
    pub txid: StacksTxId,
    /// The address that deployed the contract.
    pub address: StacksPrincipal,
    /// The aggregate key for these shares.
    ///
    /// TODO(511): maybe make the aggregate key private. Set it using the
    /// `signer_set`, ensuring that it cannot drift from the given keys.
    pub aggregate_key: PublicKey,
    /// The public keys of the signers.
    pub signer_set: Vec<PublicKey>,
    /// The number of signatures required for the multi-sig wallet.
    #[sqlx(try_from = "i32")]
    pub signatures_required: u16,
}

/// A struct containing how a signer voted for a deposit or withdrawal
/// request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SignerVote {
    /// The public key of the signer that cast the vote.
    pub signer_public_key: PublicKey,
    /// How the signer voted for a transaction. None is returned if we do
    /// not have a record of how the signer voted
    pub is_accepted: Option<bool>,
}

/// How the signers voted on a thing.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SignerVotes(Vec<SignerVote>);

impl Deref for SignerVotes {
    type Target = [SignerVote];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<SignerVote>> for SignerVotes {
    fn from(mut votes: Vec<SignerVote>) -> Self {
        votes.sort_by_key(|vote| vote.signer_public_key);
        SignerVotes(votes)
    }
}

impl From<&SignerVotes> for BitArray<[u8; 16]> {
    fn from(votes: &SignerVotes) -> BitArray<[u8; 16]> {
        let mut signer_bitmap = BitArray::ZERO;
        votes
            .iter()
            .enumerate()
            .take(signer_bitmap.len().min(crate::MAX_KEYS as usize))
            .for_each(|(index, vote)| {
                // The BitArray::<[u8; 16]>::set function panics if the
                // index is out of bounds but that cannot be the case here
                // because we only take 128 values.
                //
                // Note that the signer bitmap here is true for votes
                // *against*, and a missing vote is an implicit vote
                // against.
                signer_bitmap.set(index, !vote.is_accepted.unwrap_or(false));
            });

        signer_bitmap
    }
}

impl From<SignerVotes> for BitArray<[u8; 16]> {
    fn from(votes: SignerVotes) -> BitArray<[u8; 16]> {
        Self::from(&votes)
    }
}

/// The types of transactions the signer is interested in.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type, strum::Display)]
#[sqlx(type_name = "transaction_type", rename_all = "snake_case")]
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
    /// A rotate keys call on Stacks.
    RotateKeys,
    /// A donation to signers aggregated key on Bitcoin.
    Donation,
}

/// The types of Bitcoin transaction input or outputs that the signer may
/// be interested in.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type, strum::Display)]
#[sqlx(type_name = "output_type", rename_all = "snake_case")]
#[derive(serde::Serialize, serde::Deserialize)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum TxOutputType {
    /// An output created by the signers as the TXO containing all of the
    /// swept funds.
    SignersOutput,
    /// The `OP_RETURN` TXO created by the signers containing data about
    /// the sweep transaction.
    SignersOpReturn,
    /// A UTXO created by the signers as a response to a withdrawal
    /// request.
    Withdrawal,
    /// A donation to signers aggregated key.
    Donation,
}

/// The types of Bitcoin transaction input or outputs that the signer may
/// be interested in.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type, strum::Display)]
#[sqlx(type_name = "prevout_type", rename_all = "snake_case")]
#[derive(serde::Serialize, serde::Deserialize)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum TxPrevoutType {
    /// An output controled by the signers spent as an input.
    SignersInput,
    /// A deposit request TXO being spent as an input
    Deposit,
}

/// An identifier for a withdrawal request, comprised of the Stacks
/// transaction ID, the Stacks block ID that included the transaction, and
/// the request-id generated by the clarity contract for the withdrawal
/// request.
///
/// We need all three IDs because a transaction can be included in more
/// than one stacks block (because of reorgs), and a transaction can
/// generate more than one withdrawal request, so we need the request-id.
///
/// A request-id and a Stacks Block ID is enough to uniquely identify the
/// request, but we add in the transaction ID for completeness.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedRequestId {
    /// The ID that was generated in the clarity contract call for the
    /// withdrawal request.
    pub request_id: u64,
    /// The txid that generated the request.
    pub txid: StacksTxId,
    /// The Stacks block ID that includes the transaction that generated
    /// the request.
    pub block_hash: StacksBlockHash,
}

/// A bitcoin transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTx(bitcoin::Transaction);

impl Deref for BitcoinTx {
    type Target = bitcoin::Transaction;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<bitcoin::Transaction> for BitcoinTx {
    fn from(value: bitcoin::Transaction) -> Self {
        Self(value)
    }
}

impl From<BitcoinTx> for bitcoin::Transaction {
    fn from(value: BitcoinTx) -> Self {
        value.0
    }
}

/// The bitcoin transaction ID
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTxId(bitcoin::Txid);

impl Deref for BitcoinTxId {
    type Target = bitcoin::Txid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BitcoinTxId {
    /// Return the inner bytes for the block hash
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.to_byte_array()
    }
}

impl From<bitcoin::Txid> for BitcoinTxId {
    fn from(value: bitcoin::Txid) -> Self {
        Self(value)
    }
}

impl From<BitcoinTxId> for bitcoin::Txid {
    fn from(value: BitcoinTxId) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for BitcoinTxId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bitcoin::Txid::from_byte_array(bytes))
    }
}

impl std::fmt::Display for BitcoinTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Bitcoin block hash
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinBlockHash(bitcoin::BlockHash);

impl BitcoinBlockHash {
    /// Return the inner bytes for the block hash
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.to_byte_array()
    }
}

impl AsRef<[u8; 32]> for BitcoinBlockHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl Deref for BitcoinBlockHash {
    type Target = bitcoin::BlockHash;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<bitcoin::BlockHash> for BitcoinBlockHash {
    fn from(value: bitcoin::BlockHash) -> Self {
        Self(value)
    }
}

impl From<&BitcoinBlockHash> for bitcoin::BlockHash {
    fn from(value: &BitcoinBlockHash) -> Self {
        value.0
    }
}

impl From<BitcoinBlockHash> for bitcoin::BlockHash {
    fn from(value: BitcoinBlockHash) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for BitcoinBlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bitcoin::BlockHash::from_byte_array(bytes))
    }
}

impl From<BurnchainHeaderHash> for BitcoinBlockHash {
    fn from(value: BurnchainHeaderHash) -> Self {
        let mut bytes = value.into_bytes();
        bytes.reverse();
        bytes.into()
    }
}

impl From<BitcoinBlockHash> for BurnchainHeaderHash {
    fn from(value: BitcoinBlockHash) -> Self {
        let mut bytes = value.to_byte_array();
        bytes.reverse();
        BurnchainHeaderHash(bytes)
    }
}

impl std::fmt::Display for BitcoinBlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A struct that references a specific bitcoin block is identifier and its
/// position in the blockchain.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinBlockRef {
    /// The height of the block in the bitcoin blockchain.
    pub block_height: u64,
    /// Bitcoin block hash. It uniquely identifies the bitcoin block.
    pub block_hash: BitcoinBlockHash,
}

impl From<BitcoinBlock> for BitcoinBlockRef {
    fn from(value: BitcoinBlock) -> Self {
        Self::from(&value)
    }
}

impl From<&BitcoinBlock> for BitcoinBlockRef {
    fn from(value: &BitcoinBlock) -> Self {
        Self {
            block_hash: value.block_hash,
            block_height: value.block_height,
        }
    }
}

/// The Stacks block ID. This is different from the block header hash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StacksBlockHash(StacksBlockId);

impl Deref for StacksBlockHash {
    type Target = StacksBlockId;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<StacksBlockId> for StacksBlockHash {
    fn from(value: StacksBlockId) -> Self {
        Self(value)
    }
}

impl From<StacksBlockHash> for StacksBlockId {
    fn from(value: StacksBlockHash) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for StacksBlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(StacksBlockId(bytes))
    }
}

impl std::fmt::Display for StacksBlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Stacks transaction ID
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StacksTxId(blockstack_lib::burnchains::Txid);

impl std::fmt::Display for StacksTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for StacksTxId {
    type Target = blockstack_lib::burnchains::Txid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<blockstack_lib::burnchains::Txid> for StacksTxId {
    fn from(value: blockstack_lib::burnchains::Txid) -> Self {
        Self(value)
    }
}

impl From<StacksTxId> for blockstack_lib::burnchains::Txid {
    fn from(value: StacksTxId) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for StacksTxId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(blockstack_lib::burnchains::Txid(bytes))
    }
}

/// A stacks address. It can be either a smart contract address or a
/// standard address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StacksPrincipal(PrincipalData);

impl Deref for StacksPrincipal {
    type Target = PrincipalData;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for StacksPrincipal {
    type Err = Error;
    fn from_str(literal: &str) -> Result<Self, Self::Err> {
        let principal = PrincipalData::parse(literal).map_err(Error::ParsePrincipalData)?;
        Ok(Self(principal))
    }
}

impl From<PrincipalData> for StacksPrincipal {
    fn from(value: PrincipalData) -> Self {
        Self(value)
    }
}

impl From<StacksPrincipal> for PrincipalData {
    fn from(value: StacksPrincipal) -> Self {
        value.0
    }
}

impl Ord for StacksPrincipal {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self.0, &other.0) {
            (PrincipalData::Contract(x), PrincipalData::Contract(y)) => x.cmp(y),
            (PrincipalData::Standard(x), PrincipalData::Standard(y)) => x.cmp(y),
            (PrincipalData::Standard(x), PrincipalData::Contract(y)) => {
                x.cmp(&y.issuer).then(std::cmp::Ordering::Less)
            }
            (PrincipalData::Contract(x), PrincipalData::Standard(y)) => {
                x.issuer.cmp(y).then(std::cmp::Ordering::Greater)
            }
        }
    }
}

impl PartialOrd for StacksPrincipal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A ScriptPubkey of a UTXO.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptPubKey(bitcoin::ScriptBuf);

impl Deref for ScriptPubKey {
    type Target = bitcoin::ScriptBuf;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<bitcoin::ScriptBuf> for ScriptPubKey {
    fn from(value: bitcoin::ScriptBuf) -> Self {
        Self(value)
    }
}

impl From<ScriptPubKey> for bitcoin::ScriptBuf {
    fn from(value: ScriptPubKey) -> Self {
        value.0
    }
}

impl ScriptPubKey {
    /// Converts byte vector into script.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        bitcoin::ScriptBuf::from_bytes(bytes).into()
    }
}

/// Arbitrary bytes
pub type Bytes = Vec<u8>;

/// A signature hash for a bitcoin transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigHash(bitcoin::TapSighash);

impl Deref for SigHash {
    type Target = bitcoin::TapSighash;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<bitcoin::TapSighash> for SigHash {
    fn from(value: bitcoin::TapSighash) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SigHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The sighash and enough metadata to piece together what happened.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinTxSigHash {
    /// The transaction ID of the bitcoin transaction that sweeps funds
    /// into and/or out of the signers' UTXO.
    pub txid: BitcoinTxId,
    /// The bitcoin chain tip when the sign request was submitted. This is
    /// used to ensure that we do not sign for more than one transaction
    /// containing inputs
    pub chain_tip: BitcoinBlockHash,
    /// The txid that created the output that is being spent.
    pub prevout_txid: BitcoinTxId,
    /// The index of the vout from the transaction that created this
    /// output.
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub prevout_output_index: u32,
    /// The sighash associated with the prevout.
    pub sighash: SigHash,
    /// The type of prevout that we are dealing with.
    pub prevout_type: TxPrevoutType,
    /// The result of validation that was done on the input. For deposits,
    /// this specifies whether validation succeeded and the first condition
    /// that failed during validation. The signers' input is always valid,
    /// since it is unconfirmed.
    pub validation_result: InputValidationResult,
    /// Whether the transaction is valid. A transaction is invalid if any
    /// of the inputs or outputs failed validation.
    pub is_valid_tx: bool,
    /// Whether the signer will participate in a signing round for the
    /// sighash.
    pub will_sign: bool,
}

/// An output that was created due to a withdrawal request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct BitcoinWithdrawalOutput {
    /// The ID of the transaction that includes this withdrawal output.
    pub bitcoin_txid: BitcoinTxId,
    /// The bitcoin chain tip when the sign request was submitted. This is
    /// used to ensure that we do not sign for more than one transaction
    /// containing inputs
    pub bitcoin_chain_tip: BitcoinBlockHash,
    /// The index of the referenced output in the transaction's outputs.
    #[cfg_attr(feature = "testing", dummy(faker = "0..i32::MAX as u32"))]
    pub output_index: u32,
    /// The request ID of the withdrawal request. These increment for each
    /// withdrawal, but there can be duplicates if there is a reorg that
    /// affects a transaction that calls the `initiate-withdrawal-request`
    /// public function.
    #[cfg_attr(feature = "testing", dummy(faker = "0..i64::MAX as u64"))]
    pub request_id: u64,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub stacks_txid: StacksTxId,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    pub stacks_block_hash: StacksBlockHash,
    /// The outcome of validation of the withdrawal request.
    pub validation_result: WithdrawalValidationResult,
    /// Whether the transaction is valid. A transaction is invalid if any
    /// of the inputs or outputs failed validation.
    pub is_valid_tx: bool,
}

/// This is the event that is emitted from the `complete-withdrawal-accept`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalAcceptEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// This is the outpoint for the bitcoin transaction that serviced the
    /// request.
    pub outpoint: OutPoint,
    /// This is the fee that was spent to the bitcoin miners to confirm the
    /// withdrawal request.
    pub fee: u64,
    /// The bitcoin block hash where the sweep transaction was included.
    pub sweep_block_hash: EventsBitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// withdrawal request.
    pub sweep_txid: BitcoinTxid,
}

impl From<sbtc::events::WithdrawalAcceptEvent> for WithdrawalAcceptEvent {
    fn from(sbtc_event: sbtc::events::WithdrawalAcceptEvent) -> WithdrawalAcceptEvent {
        let sweep_hash = EventsBitcoinBlockHash::from(BitcoinBlockHash::from(
            *sbtc_event.sweep_block_hash.as_bytes(),
        ));
        let txid = StacksTxid::from(sbtc_event.txid.0);
        WithdrawalAcceptEvent {
            txid,
            block_id: sbtc_event.block_id,
            request_id: sbtc_event.request_id,
            signer_bitmap: BitArray::new(sbtc_event.signer_bitmap.to_le_bytes()),
            outpoint: sbtc_event.outpoint,
            fee: sbtc_event.fee,
            sweep_block_hash: sweep_hash,
            sweep_block_height: sbtc_event.sweep_block_height,
            sweep_txid: sbtc_event.sweep_txid,
        }
    }
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct CompletedDepositEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the amount of sBTC to mint to the intended recipient.
    pub amount: u64,
    /// This is the outpoint of the original bitcoin deposit transaction.
    pub outpoint: OutPoint,
    /// The bitcoin block hash where the sweep transaction was included.
    pub sweep_block_hash: EventsBitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// deposit.
    pub sweep_txid: BitcoinTxid,
}

impl From<sbtc::events::CompletedDepositEvent> for CompletedDepositEvent {
    fn from(sbtc_event: sbtc::events::CompletedDepositEvent) -> CompletedDepositEvent {
        let sweep_hash = EventsBitcoinBlockHash::from(BitcoinBlockHash::from(
            *sbtc_event.sweep_block_hash.as_bytes(),
        ));
        let txid = StacksTxid::from(sbtc_event.txid.0);
        CompletedDepositEvent {
            txid,
            block_id: sbtc_event.block_id,
            amount: sbtc_event.amount,
            outpoint: sbtc_event.outpoint,
            sweep_block_hash: sweep_hash,
            sweep_block_height: sbtc_event.sweep_block_height,
            sweep_txid: sbtc_event.sweep_txid,
        }
    }
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalCreateEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// This is the amount of sBTC that is locked and requested to be
    /// withdrawal as sBTC.
    pub amount: u64,
    /// This is the principal who has their sBTC locked up.
    pub sender: PrincipalData,
    /// This is the address to send the BTC to when fulfilling the
    /// withdrawal request.
    pub recipient: ScriptBuf,
    /// This is the maximum amount of BTC "spent" to the miners for the
    /// transaction fee.
    pub max_fee: u64,
    /// The block height of the bitcoin blockchain when the stacks
    /// transaction that emitted this event was executed.
    pub block_height: u64,
}

/// This is the event that is emitted from the `complete-withdrawal-reject`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalRejectEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of user created the withdrawal
    /// request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
}

/// An error when trying to parse an sBTC event into a concrete type.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// This error is thrown when trying to convert an u128 into some other
    /// smaller type. It should never be thrown
    #[error("Could not convert an integer in clarity event into the expected integer {0}")]
    ClarityIntConversion(#[source] std::num::TryFromIntError),
    /// This is a slice conversion that happens when generating an address
    /// from validated user inputs. It shouldn't happen since we validate
    /// the user's inputs in the contract call.
    #[error("slice conversion failed: {0}")]
    ClaritySliceConversion(#[source] std::array::TryFromSliceError),
    /// This happens when we attempt to create s String from the raw bytes
    /// returned in a Clarity [`Value`](clarity::vm::Value).
    #[error("Could not convert ASCII or UTF8 bytes into a String: {0}")]
    ClarityStringConversion(#[source] std::string::FromUtf8Error),
    /// This can only be thrown when the number of bytes for a txid or
    /// block hash field is not exactly equal to 32. This should never occur.
    #[error("Could not convert a hash in clarity event into the expected hash {0}")]
    ClarityHashConversion(#[source] bitcoin::hashes::FromSliceError),
    /// This error is thrown when trying to convert a public key from a
    /// Clarity buffer into a proper public key. It should never be thrown.
    #[error("Could not convert a public key in clarity event into the expected public key {0}")]
    ClarityPublicKeyConversion(#[source] secp256k1::Error),
    /// This should never happen, but happens when one of the given topics
    /// is not on the list of expected topics.
    #[error("Got an unexpected event topic: {0}")]
    ClarityUnexpectedEventTopic(String),
    /// This happens when we expect one clarity variant but got another.
    #[error("Got an unexpected clarity value: {0:?}; {1}")]
    ClarityUnexpectedValue(ClarityValue, TxInfo),
    /// This should never happen, since  our witness programs are under the
    /// maximum length.
    #[error("tried to create an invalid witness program {0}")]
    InvalidWitnessProgram(#[source] bitcoin::witness_program::Error),
    /// This a programmer error bug that should never be thrown.
    #[error("The field {0} was missing from the print event for topic; {1}")]
    TupleEventField(&'static str, TxInfo),
    /// This should never happen, we check the version in the smart
    /// contract.
    #[error("the given raw recipient is unexpected. version: {0:?}, hashbytes: {1:?} ")]
    UnhandledRecipient(Vec<u8>, Vec<u8>),
}

/// The print events emitted by the sbtc-registry clarity smart contract.
#[derive(Debug)]
pub enum RegistryEvent {
    /// For the `completed-deposit` topic
    CompletedDeposit(CompletedDepositEvent),
    /// For the `withdrawal-accept` topic
    WithdrawalAccept(WithdrawalAcceptEvent),
    /// For the `withdrawal-reject` topic
    WithdrawalReject(WithdrawalRejectEvent),
    /// For the `withdrawal-create` topic
    WithdrawalCreate(WithdrawalCreateEvent),
    /// For the `key-rotation` topic
    KeyRotation(KeyRotationEvent),
}

impl RegistryEvent {
    /// Transform the [`ClarityValue`] from the sbtc-registry event into a
    /// proper type.
    pub fn try_new(value: ClarityValue, tx_info: TxInfo) -> Result<Self, EventError> {
        match value {
            ClarityValue::Tuple(TupleData { data_map, .. }) => {
                let mut event_map = RawTupleData::new(data_map, tx_info);
                // Lucky for us, each sBTC print event in the sbtc-registry
                // smart contract has a topic. We use that to match on what
                // to expect when decomposing the event from a
                // [`ClarityValue`] into a proper type.
                let topic = event_map.remove_string("topic")?;

                match topic.as_str() {
                    "completed-deposit" => event_map.completed_deposit(),
                    "withdrawal-accept" => event_map.withdrawal_accept(),
                    "withdrawal-create" => event_map.withdrawal_create(),
                    "withdrawal-reject" => event_map.withdrawal_reject(),
                    "key-rotation" => event_map.key_rotation(),
                    _ => Err(EventError::ClarityUnexpectedEventTopic(topic)),
                }
            }
            value => Err(EventError::ClarityUnexpectedValue(value, tx_info)),
        }
    }
}

/// A type that points to a transaction in a stacks block.
#[derive(Debug, Copy, Clone)]
pub struct TxInfo {
    /// The transaction ID
    pub txid: StacksTxid,
    /// The globally unique stacks block identifier.
    pub block_id: StacksBlockId,
}

impl std::fmt::Display for TxInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "txid: {}, block_id: {}", self.txid, self.block_id)
    }
}

/// This is the event that is emitted from the `rotate-keys`
/// public function in the sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    pub new_keys: Vec<EventsPublicKey>,
    /// The address that deployed the contract.
    pub new_address: PrincipalData,
    /// The new aggregate key created by combining the above public keys.
    pub new_aggregate_pubkey: EventsPublicKey,
    /// The number of signatures required for the multi-sig wallet.
    pub new_signature_threshold: u16,
}

#[derive(Debug)]
struct RawTupleData {
    data_map: BTreeMap<ClarityName, ClarityValue>,
    tx_info: TxInfo,
}

impl RawTupleData {
    fn new(data_map: BTreeMap<ClarityName, ClarityValue>, tx_info: TxInfo) -> Self {
        Self { data_map, tx_info }
    }
    /// Extract the u128 value from the given field
    fn remove_u128(&mut self, field: &'static str) -> Result<u128, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::UInt(val)) => Ok(val),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the buff value from the given field
    fn remove_buff(&mut self, field: &'static str) -> Result<Vec<u8>, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::Buffer(buf))) => Ok(buf.data),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the principal value from the given field
    fn remove_principal(&mut self, field: &'static str) -> Result<PrincipalData, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Principal(principal)) => Ok(principal),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the string value from the given field
    fn remove_string(&mut self, field: &'static str) -> Result<String, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::String(CharType::ASCII(ascii)))) => {
                String::from_utf8(ascii.data).map_err(EventError::ClarityStringConversion)
            }
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the tuple value from the given field
    fn remove_tuple(&mut self, field: &'static str) -> Result<Self, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Tuple(TupleData { data_map, .. })) => {
                Ok(Self::new(data_map, self.tx_info))
            }
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }

    /// Extract the list value from the given field
    fn remove_list(&mut self, field: &'static str) -> Result<Vec<ClarityValue>, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::List(list))) => Ok(list.data),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }

    /// This function is for transforming the print events of the
    /// complete-deposit function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for complete-deposit calls are structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "completed-deposit",
    ///   bitcoin-txid: (buff 32),
    ///   output-index: uint,
    ///   amount: uint
    ///   burn-hash: (buff 32),
    ///   burn-height: uint,
    ///   sweep-txid: (buff 32),
    /// })
    /// ```
    ///
    /// The above event is emitted after the indicated amount of sBTC has
    /// been emitted to the recipient.
    fn completed_deposit(mut self) -> Result<RegistryEvent, EventError> {
        let amount = self.remove_u128("amount")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;
        let mut sweep_block_hash = self.remove_buff("burn-hash")?;
        let sweep_block_height = self.remove_u128("burn-height")?;
        let sweep_txid = self.remove_buff("sweep-txid")?;

        // The `sweep_block_hash` we receive is reversed, so we reverse it here
        // so that we store it in an ordering consistent with the rest of our db.
        sweep_block_hash.reverse();

        Ok(RegistryEvent::CompletedDeposit(CompletedDepositEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            amount: u64::try_from(amount).map_err(EventError::ClarityIntConversion)?,
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`]
                // in a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes)
                    .map_err(EventError::ClarityHashConversion)?,
                // This shouldn't actually error, we cast u32s to u128s
                // before making the contract call, and that is the value
                // that gets emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            sweep_block_hash: EventsBitcoinBlockHash::from_slice(&sweep_block_hash)
                .map_err(EventError::ClarityHashConversion)?,
            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,
            sweep_txid: BitcoinTxid::from_slice(&sweep_txid)
                .map_err(EventError::ClarityHashConversion)?,
        }))
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-accept` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `create-withdrawal-request` calls are structured
    /// like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-create",
    ///   amount: uint,
    ///   request-id: uint,
    ///   sender: principal,
    ///   recipient: { version: (buff 1), hashbytes: (buff 32) },
    ///   block-height: uint,
    ///   max-fee: uint,
    /// })
    /// ```
    fn withdrawal_create(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let amount = self.remove_u128("amount")?;
        let max_fee = self.remove_u128("max-fee")?;
        let block_height = self.remove_u128("block-height")?;
        let sender = self.remove_principal("sender")?;
        let recipient = self.remove_tuple("recipient")?;

        Ok(RegistryEvent::WithdrawalCreate(WithdrawalCreateEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error, practically speaking. Each withdrawal
            // request increments the integer by one, so we'd have to do many
            // orders of magnitude more requests than there are bitcoin
            // transactions, ever.
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            amount: u64::try_from(amount).map_err(EventError::ClarityIntConversion)?,
            max_fee: u64::try_from(max_fee).map_err(EventError::ClarityIntConversion)?,
            block_height: u64::try_from(block_height).map_err(EventError::ClarityIntConversion)?,
            recipient: recipient.try_into_script_pub_key()?,
            sender,
        }))
    }

    /// This function takes in a recipient as a Clarity Value and returns a
    /// bitcoin address, where the clarity value is:
    /// ```clarity
    /// { version: (buff 1), hashbytes: (buff 32) }
    /// ```
    /// This function gives a breakdown of the acceptable inputs for the
    /// recipient in the `initiate-withdrawal-request` contract call. The
    /// permissible values and their meaning closely tracks the meaning of
    /// [`PoxAddress`](blockstack_lib::chainstate::stacks::address::PoxAddress)es
    /// in stacks core. This meaning is summarized as:
    ///
    /// ```text
    /// version == 0x00 and (len hashbytes) == 20 => P2PKH
    /// version == 0x01 and (len hashbytes) == 20 => P2SH
    /// version == 0x02 and (len hashbytes) == 20 => P2SH-P2WPKH
    /// version == 0x03 and (len hashbytes) == 20 => P2SH-P2WSH
    /// version == 0x04 and (len hashbytes) == 20 => P2WPKH
    /// version == 0x05 and (len hashbytes) == 32 => P2WSH
    /// version == 0x06 and (len hashbytes) == 32 => P2TR
    /// ```
    ///
    /// Also see <https://docs.stacks.co/clarity/functions#get-burn-block-info>
    ///
    /// Below is a detailed breakdown of bitcoin address types and how they
    /// map to the clarity value. In what follows below, the network used
    /// for the human-readable parts is inherited from the network of the
    /// underlying transaction itself (basically, on stacks mainnet we send
    /// to mainnet bitcoin addresses and similarly on stacks testnet we
    /// send to bitcoin testnet addresses).
    ///
    /// ## P2PKH
    ///
    /// Generally speaking, Pay-to-Public-Key-Hash addresses are formed by
    /// taking the Hash160 of the public key, prefixing it with one byte
    /// (0x00 on mainnet and 0x6F on testing) and then base58 encoding the
    /// result.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x00 and the `hashbytes` is the
    /// Hash160 of the public key.
    ///
    ///
    /// ## P2SH, P2SH-P2WPKH, and P2SH-P2WSH
    ///
    /// Pay-to-script-hash-* addresses are formed by taking the Hash160 of
    /// the locking script, prefixing it with one byte (0x05 on mainnet and
    /// 0xC4 on testnet) and base58 encoding the result. The difference
    /// between them lies with the locking script. For P2SH-P2WPKH
    /// addresses, the locking script is:
    /// ```text
    /// 0 || <Hash160 of the compressed public key>
    /// ```
    /// For P2SH-P2WSH addresses, the locking script is:
    /// ```text
    /// 0 || <sha256 of the redeem script>
    /// ```
    /// And for P2SH addresses you get to choose the locking script in its
    /// entirety.
    ///
    /// Again, after you construct the locking script you take its Hash160,
    /// prefix it with one byte and base58 encode it to form the address.
    /// To specify these address types in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x01, 0x02, and 0x03 (for P2SH,
    /// P2SH-P2WPKH, and P2SH-P2WSH respectively) with the `hashbytes` is
    /// the Hash160 of the locking script.
    ///
    ///
    /// ## P2WPKH
    ///
    /// Pay-to-witness-public-key-hash addresses are formed by creating a
    /// witness program made entirely of the Hash160 of the compressed
    /// public key.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x04 and the `hashbytes` is the
    /// Hash160 of the compressed public key.
    ///
    ///
    /// ## P2WSH
    ///
    /// Pay-to-witness-script-hash addresses are formed by taking a witness
    /// program that is compressed entirely of the SHA256 of the redeem
    /// script.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x05 and the `hashbytes` is the
    /// SHA256 of the redeem script.
    ///
    ///
    /// ## P2TR
    ///
    /// Pay-to-taproot addresses are formed by "tweaking" the x-coordinate
    /// of a public key with a merkle tree. The result of the tweak is used
    /// as the witness program for the address.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x06 and the `hashbytes` is the
    /// "tweaked" public key.
    fn try_into_script_pub_key(mut self) -> Result<ScriptBuf, EventError> {
        let version = self.remove_buff("version")?;
        let hash_bytes_buf = self.remove_buff("hashbytes")?;
        let hash_bytes = hash_bytes_buf.as_slice();

        match version.as_slice() {
            // version == 0x00 and (len hashbytes) == 20 => P2PKH
            [0x00] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(EventError::ClaritySliceConversion)?;
                let pubkey_hash = PubkeyHash::from_byte_array(bytes);
                Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
            }
            // ```
            // version == 0x01 and (len hashbytes) == 20 => P2SH
            // version == 0x02 and (len hashbytes) == 20 => P2SH-P2WPKH
            // version == 0x03 and (len hashbytes) == 20 => P2SH-P2WSH
            // ```
            //
            // In these cases we assume the `hashbytes` is the Hash160 of
            // the redeem script.
            [0x01] | [0x02] | [0x03] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(EventError::ClaritySliceConversion)?;
                let script_hash = ScriptHash::from_byte_array(bytes);
                Ok(ScriptBuf::new_p2sh(&script_hash))
            }
            // version == 0x04 and (len hashbytes) == 20 => P2WPKH
            [0x04] if hash_bytes.len() == 20 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // version == 0x05 and (len hashbytes) == 32 => P2WSH
            [0x05] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // version == 0x06 and (len hashbytes) == 32 => P2TR
            [0x06] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V1, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // We make sure that the version and hash byte lengths conform
            // to the above expectations in the smart contract, so this
            // should never happen.
            _ => Err(EventError::UnhandledRecipient(version, hash_bytes_buf)),
        }
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-accept` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `complete-withdrawal-accept` calls are
    /// structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-accept",
    ///   request-id: uint,
    ///   bitcoin-txid: (buff 32),
    ///   signer-bitmap: uint,
    ///   bitcoin-index: uint,
    ///   fee: uint,
    ///   burn-hash: (buff 32),
    ///   burn-height: uint,
    ///   sweep-txid: (buff 32),
    /// })
    /// ```
    fn withdrawal_accept(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;
        let fee = self.remove_u128("fee")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;
        let mut sweep_block_hash = self.remove_buff("burn-hash")?;
        let sweep_block_height = self.remove_u128("burn-height")?;
        let sweep_txid = self.remove_buff("sweep-txid")?;

        // The `sweep_block_hash` we receive is reversed, so we reverse it here
        // so that we store it in an ordering consistent with the rest of our db.
        sweep_block_hash.reverse();

        Ok(RegistryEvent::WithdrawalAccept(WithdrawalAcceptEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`] in
                // a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes)
                    .map_err(EventError::ClarityHashConversion)?,
                // This shouldn't actually error, we cast u32s to u128s before
                // making the contract call, and that is the value that gets
                // emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            fee: u64::try_from(fee).map_err(EventError::ClarityIntConversion)?,

            sweep_block_hash: EventsBitcoinBlockHash::from_slice(&sweep_block_hash)
                .map_err(EventError::ClarityHashConversion)?,

            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,

            sweep_txid: BitcoinTxid::from_slice(&sweep_txid)
                .map_err(EventError::ClarityHashConversion)?,
        }))
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-reject` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `complete-withdrawal-reject` calls are structured
    /// like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-reject",
    ///   request-id: uint,
    ///   signer-bitmap: uint,
    /// })
    /// ```
    ///
    /// The above event is emitted after the locked sBTC has been unlocked back
    /// to the account that initiated the request.
    fn withdrawal_reject(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;

        Ok(RegistryEvent::WithdrawalReject(WithdrawalRejectEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
        }))
    }

    /// This function is for transforming the print events of the
    /// `rotate-keys` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `rotate-keys` calls are structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "key-rotation",
    ///   new-keys: (list 128 (buff 33))
    ///   new-address: principal
    ///   new-aggregate-pubkey: (buff 33)
    ///   new-signature-threshold: uint
    /// })
    /// ```
    ///
    /// The above event is emitted after the keys for the multi-sig wallet
    /// have been rotated.
    fn key_rotation(mut self) -> Result<RegistryEvent, EventError> {
        let new_keys = self
            .remove_list("new-keys")?
            .into_iter()
            .map(|val| match val {
                ClarityValue::Sequence(SequenceData::Buffer(buf)) => {
                    EventsPublicKey::from_slice(&buf.data)
                        .map_err(EventError::ClarityPublicKeyConversion)
                }
                _ => Err(EventError::ClarityUnexpectedValue(val, self.tx_info)),
            })
            .collect::<Result<Vec<EventsPublicKey>, EventError>>()?;

        let new_address = self.remove_principal("new-address")?;
        let new_aggregate_pubkey = self.remove_buff("new-aggregate-pubkey")?;
        let new_signature_threshold = self.remove_u128("new-signature-threshold")?;

        Ok(RegistryEvent::KeyRotation(KeyRotationEvent {
            new_keys,
            new_address,
            new_aggregate_pubkey: EventsPublicKey::from_slice(&new_aggregate_pubkey)
                .map_err(EventError::ClarityPublicKeyConversion)?,
            new_signature_threshold: u16::try_from(new_signature_threshold)
                .map_err(EventError::ClarityIntConversion)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use fake::Fake;
    use rand::SeedableRng;
    use test_case::test_case;

    use crate::bitcoin::utxo::GetFees;

    use super::*;

    #[test]
    fn conversion_bitcoin_header_hashes() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);

        let block_hash: BitcoinBlockHash = fake::Faker.fake_with_rng(&mut rng);
        let stacks_hash = BurnchainHeaderHash::from(block_hash);
        let round_trip = BitcoinBlockHash::from(stacks_hash);
        assert_eq!(block_hash, round_trip);

        let stacks_hash = BurnchainHeaderHash(fake::Faker.fake_with_rng(&mut rng));
        let block_hash = BitcoinBlockHash::from(stacks_hash);
        let round_trip = BurnchainHeaderHash::from(block_hash);
        assert_eq!(stacks_hash, round_trip);
    }

    #[test_case(&[(1000, 500)], Some(Fees { total: 500, rate: 0.5 }))]
    #[test_case(&[(1000, 500), (2000, 1000)], Some(Fees { total: 1500, rate: 0.5 }))]
    #[test_case(&[(1000, 250), (2000, 1000)], Some(Fees { total: 1250, rate: 0.4166666666666667 }))]
    #[test_case(&[(1000, 125), (1250, 125), (1500, 175)], Some(Fees { total: 425, rate: 0.11333333333333333 }))]
    #[test_case(&[], None)]
    fn get_sweep_transaction_package_fees(sweeps: &[(u32, u64)], expected: Option<Fees>) {
        // (vsize, fee)
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);

        let mut sweep_txs = vec![];
        for (vsize, fee) in sweeps {
            let tx = SweepTransaction {
                vsize: *vsize,
                fee: *fee,
                ..fake::Faker.fake_with_rng(&mut rng)
            };
            sweep_txs.push(tx);
        }

        let fees = sweep_txs.get_fees().expect("failed to calculate fees");

        assert_eq!(fees, expected);
    }

    #[test]
    fn get_sweep_transaction_package_overflows() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);

        let mut sweep_txs = vec![];
        (0..3).for_each(|_| {
            let tx = SweepTransaction {
                fee: u64::MAX,
                vsize: 1,
                ..fake::Faker.fake_with_rng(&mut rng)
            };
            sweep_txs.push(tx);
        });

        let fees = sweep_txs.get_fees();
        assert!(matches!(fees, Err(Error::ArithmeticOverflow)));
    }

    #[test]
    fn get_sweep_transaction_package_divide_by_zero() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);

        let mut sweep_txs = vec![];
        (0..3).for_each(|_| {
            let tx = SweepTransaction {
                fee: 1,
                vsize: 0,
                ..fake::Faker.fake_with_rng(&mut rng)
            };
            sweep_txs.push(tx);
        });

        let fees = sweep_txs.get_fees();
        assert!(matches!(fees, Err(Error::DivideByZero)));
    }
}
