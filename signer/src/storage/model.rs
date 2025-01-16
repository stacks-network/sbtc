//! Database models for the signer.

use std::collections::BTreeSet;
use std::ops::Deref;

use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use clarity::vm::types::PrincipalData;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;

use crate::bitcoin::rpc::BitcoinBlockHeader;
use crate::bitcoin::validation::InputValidationResult;
use crate::bitcoin::validation::WithdrawalValidationResult;
use crate::block_observer::Deposit;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;

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

impl From<BitcoinBlockHeader> for BitcoinBlock {
    fn from(header: BitcoinBlockHeader) -> Self {
        BitcoinBlock {
            block_hash: header.hash.into(),
            block_height: header.height,
            parent_hash: header.previous_block_hash.into(),
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
    /// An output controlled by the signers spent as an input.
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

/// This trait adds a function for converting a type into bytes to
/// little-endian byte order. This is because stacks-core expects
/// bitcoin block hashes to be in little-endian byte order when evaluating
/// some clarity functions.
///
/// Both [`bitcoin::BlockHash`] and [`bitcoin::Txid`] are hash types that
/// store bytes as SHA256 output, which is in big-endian order. Stacks-core
/// stores hashes in little-endian byte order[2], implying that clarity
/// functions, like `get-burn-block-info?`, return bitcoin block hashes in
/// little-endian byte order. Note that Bitcoin-core transmits hashes in
/// big-endian byte order[1] through the RPC interface, but the wire and
/// zeromq interfaces transmit hashes in little-endian order[3].
///
/// [^1]: See the Note in
///     <https://github.com/bitcoin/bitcoin/blob/62bd61de110b057cbfd6e31e4d0b727d93119c72/doc/zmq.md>.
/// [^2]: <https://github.com/stacks-network/stacks-core/blob/70d24ea179840763c2335870d0965b31b37685d6/stacks-common/src/types/chainstate.rs#L427-L432>
/// [^3]: <https://developer.bitcoin.org/reference/block_chain.html#block-chain>
///       <https://developer.bitcoin.org/reference/p2p_networking.html>
/// <https://learnmeabitcoin.com/technical/general/byte-order/>
pub trait ToLittleEndianOrder: Sized {
    /// Return the bytes in little-endian order.
    fn to_le_bytes(&self) -> [u8; 32];
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

impl ToLittleEndianOrder for BitcoinTxId {
    fn to_le_bytes(&self) -> [u8; 32] {
        self.deref().to_le_bytes()
    }
}

impl ToLittleEndianOrder for bitcoin::Txid {
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = self.to_byte_array();
        bytes.reverse();
        bytes
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

impl ToLittleEndianOrder for BitcoinBlockHash {
    fn to_le_bytes(&self) -> [u8; 32] {
        self.deref().to_le_bytes()
    }
}

impl ToLittleEndianOrder for bitcoin::BlockHash {
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = self.to_byte_array();
        bytes.reverse();
        bytes
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
        BurnchainHeaderHash(value.to_le_bytes())
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
    /// The signers' aggregate key that is locking the output that is being
    /// spent.
    pub aggregate_key: PublicKeyXOnly,
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

impl From<sbtc::events::StacksTxid> for StacksTxId {
    fn from(value: sbtc::events::StacksTxid) -> Self {
        Self(blockstack_lib::burnchains::Txid(value.0))
    }
}

impl From<sbtc::events::CompletedDepositEvent> for CompletedDepositEvent {
    fn from(sbtc_event: sbtc::events::CompletedDepositEvent) -> CompletedDepositEvent {
        let sweep_hash = BitcoinBlockHash::from(sbtc_event.sweep_block_hash);
        let txid = StacksTxId::from(sbtc_event.txid.0);
        CompletedDepositEvent {
            txid,
            block_id: sbtc_event.block_id.into(),
            amount: sbtc_event.amount,
            outpoint: sbtc_event.outpoint,
            sweep_block_hash: sweep_hash,
            sweep_block_height: sbtc_event.sweep_block_height,
            sweep_txid: sbtc_event.sweep_txid.into(),
        }
    }
}

impl From<sbtc::events::WithdrawalAcceptEvent> for WithdrawalAcceptEvent {
    fn from(sbtc_event: sbtc::events::WithdrawalAcceptEvent) -> WithdrawalAcceptEvent {
        WithdrawalAcceptEvent {
            txid: sbtc_event.txid.into(),
            block_id: sbtc_event.block_id.into(),
            request_id: sbtc_event.request_id,
            signer_bitmap: BitArray::new(sbtc_event.signer_bitmap.to_le_bytes()),
            outpoint: sbtc_event.outpoint,
            fee: sbtc_event.fee,
            sweep_block_hash: sbtc_event.sweep_block_hash.into(),
            sweep_block_height: sbtc_event.sweep_block_height,
            sweep_txid: sbtc_event.sweep_txid.into(),
        }
    }
}

impl From<sbtc::events::WithdrawalRejectEvent> for WithdrawalRejectEvent {
    fn from(sbtc_event: sbtc::events::WithdrawalRejectEvent) -> WithdrawalRejectEvent {
        WithdrawalRejectEvent {
            txid: sbtc_event.txid.into(),
            block_id: sbtc_event.block_id.into(),
            request_id: sbtc_event.request_id,
            signer_bitmap: BitArray::new(sbtc_event.signer_bitmap.to_le_bytes()),
        }
    }
}

impl From<sbtc::events::WithdrawalCreateEvent> for WithdrawalCreateEvent {
    fn from(sbtc_event: sbtc::events::WithdrawalCreateEvent) -> WithdrawalCreateEvent {
        WithdrawalCreateEvent {
            txid: sbtc_event.txid.into(),
            block_id: sbtc_event.block_id.into(),
            request_id: sbtc_event.request_id,
            amount: sbtc_event.amount,
            sender: sbtc_event.sender.into(),
            recipient: sbtc_event.recipient.into(),
            max_fee: sbtc_event.max_fee,
            block_height: sbtc_event.block_height,
        }
    }
}

impl From<sbtc::events::KeyRotationEvent> for KeyRotationEvent {
    fn from(sbtc_event: sbtc::events::KeyRotationEvent) -> KeyRotationEvent {
        KeyRotationEvent {
            new_keys: sbtc_event
                .new_keys
                .into_iter()
                .map(|key| key.into())
                .collect(),
            new_address: sbtc_event.new_address.into(),
            new_aggregate_pubkey: sbtc_event.new_aggregate_pubkey.into(),
            new_signature_threshold: sbtc_event.new_signature_threshold,
        }
    }
}

/// This is the event that is emitted from the `rotate-keys`
/// public function in the sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    pub new_keys: Vec<PublicKey>,
    /// The address that deployed the contract.
    pub new_address: StacksPrincipal,
    /// The new aggregate key created by combining the above public keys.
    pub new_aggregate_pubkey: PublicKey,
    /// The number of signatures required for the multi-sig wallet.
    pub new_signature_threshold: u16,
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct CompletedDepositEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxId,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockHash,
    /// This is the amount of sBTC to mint to the intended recipient.
    pub amount: u64,
    /// This is the outpoint of the original bitcoin deposit transaction.
    pub outpoint: OutPoint,
    /// The bitcoin block hash where the sweep transaction was included.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// deposit.
    pub sweep_txid: BitcoinTxId,
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalCreateEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxId,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockHash,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// This is the amount of sBTC that is locked and requested to be
    /// withdrawal as sBTC.
    pub amount: u64,
    /// This is the principal who has their sBTC locked up.
    pub sender: StacksPrincipal,
    /// This is the address to send the BTC to when fulfilling the
    /// withdrawal request.
    pub recipient: ScriptPubKey,
    /// This is the maximum amount of BTC "spent" to the miners for the
    /// transaction fee.
    pub max_fee: u64,
    /// The block height of the bitcoin blockchain when the stacks
    /// transaction that emitted this event was executed.
    pub block_height: u64,
}
/// This is the event that is emitted from the `complete-withdrawal-accept`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalAcceptEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxId,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockHash,
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
    pub sweep_block_hash: BitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// withdrawal request.
    pub sweep_txid: BitcoinTxId,
}

/// This is the event that is emitted from the `complete-withdrawal-reject`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalRejectEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxId,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockHash,
    /// This is the unique identifier of user created the withdrawal
    /// request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
}

#[cfg(test)]
mod tests {
    use fake::Fake;
    use rand::SeedableRng;

    use sbtc::events::FromLittleEndianOrder;

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

    #[test]
    fn endian_conversion() {
        let block_hash: BitcoinBlockHash = fake::Faker.fake_with_rng(&mut rand::rngs::OsRng);
        let block_hash = bitcoin::BlockHash::from(block_hash);
        let round_trip = bitcoin::BlockHash::from_le_bytes(block_hash.to_le_bytes());

        assert_eq!(block_hash, round_trip);

        let block_hash: BitcoinTxId = fake::Faker.fake_with_rng(&mut rand::rngs::OsRng);
        let block_hash = bitcoin::Txid::from(block_hash);
        let round_trip = bitcoin::Txid::from_le_bytes(block_hash.to_le_bytes());

        assert_eq!(block_hash, round_trip);
    }
}
