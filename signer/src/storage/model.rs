//! Database models for the signer.

use std::collections::BTreeSet;
use std::ops::Deref;

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
use std::collections::BTreeMap;

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

/// This trait adds a function for converting bytes from little-endian byte
/// order into a bitcoin hash types. This is because the signers convert
/// [`bitcoin::Txid`] and [`bitcoin::BlockHash`] bytes into little-endian
/// order before submitting contract calls.
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
pub trait FromLittleEndianOrder: Sized {
    /// Convert bytes expressed in little-endian order to the type;
    fn from_le_bytes(bytes: [u8; 32]) -> Self;
}

impl FromLittleEndianOrder for bitcoin::Txid {
    fn from_le_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        bitcoin::Txid::from_byte_array(bytes)
    }
}

impl FromLittleEndianOrder for bitcoin::BlockHash {
    fn from_le_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        bitcoin::BlockHash::from_byte_array(bytes)
    }
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
    #[error("unexpected improper hash byte length, received {0} bytes")]
    ClarityHashByteLength(usize),
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
        let txid_bytes = <[u8; 32]>::try_from(self.remove_buff("bitcoin-txid")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_txid = <[u8; 32]>::try_from(self.remove_buff("sweep-txid")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_block_hash = <[u8; 32]>::try_from(self.remove_buff("burn-hash")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_block_height = self.remove_u128("burn-height")?;

        Ok(RegistryEvent::CompletedDeposit(CompletedDepositEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            amount: u64::try_from(amount).map_err(EventError::ClarityIntConversion)?,
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`]
                // in a contract call.
                txid: BitcoinTxid::from_le_bytes(txid_bytes),
                // This shouldn't actually error, we cast u32s to u128s
                // before making the contract call, and that is the value
                // that gets emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            sweep_block_hash: EventsBitcoinBlockHash::from_le_bytes(sweep_block_hash),
            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,
            sweep_txid: BitcoinTxid::from_le_bytes(sweep_txid),
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
        let txid_bytes = <[u8; 32]>::try_from(self.remove_buff("bitcoin-txid")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_txid = <[u8; 32]>::try_from(self.remove_buff("sweep-txid")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_block_hash = <[u8; 32]>::try_from(self.remove_buff("burn-hash")?)
            .map_err(|bytes| EventError::ClarityHashByteLength(bytes.len()))?;
        let sweep_block_height = self.remove_u128("burn-height")?;

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
                txid: BitcoinTxid::from_le_bytes(txid_bytes),
                // This shouldn't actually error, we cast u32s to u128s before
                // making the contract call, and that is the value that gets
                // emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            fee: u64::try_from(fee).map_err(EventError::ClarityIntConversion)?,

            sweep_block_hash: EventsBitcoinBlockHash::from_le_bytes(sweep_block_hash),

            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,

            sweep_txid: BitcoinTxid::from_le_bytes(sweep_txid),
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
    use std::sync::LazyLock;

    use bitcoin::key::CompressedPublicKey;
    use bitcoin::key::TweakedPublicKey;
    use bitvec::field::BitField as _;
    use clarity::vm::types::ListData;
    use clarity::vm::types::ListTypeData;
    use clarity::vm::types::BUFF_33;
    use rand::rngs::OsRng;
    use secp256k1::SECP256K1;

    use fake::Fake;
    use rand::SeedableRng;

    use super::*;

    use test_case::test_case;

    const TX_INFO: TxInfo = TxInfo {
        txid: StacksTxid([0; 32]),
        block_id: StacksBlockId([0; 32]),
    };

    #[test]
    fn signer_bitmap_conversion() {
        // This test checks that converting from an integer to the bitmap
        // works the way that we expect.
        let bitmap_number: u128 = 3;
        let bitmap: BitArray<[u8; 16]> = BitArray::new(bitmap_number.to_le_bytes());

        assert_eq!(bitmap.load_le::<u128>(), bitmap_number);

        // This is basically a test of the same thing as the above, except
        // that we explicitly create the signer bitmap.
        let mut bitmap: BitArray<[u8; 16]> = BitArray::ZERO;
        bitmap.set(0, true);
        bitmap.set(1, true);

        assert_eq!(bitmap.load_le::<u128>(), bitmap_number);
    }

    #[test]
    fn complete_deposit_event() {
        let amount = 123654789;
        let event = [
            (ClarityName::from("amount"), ClarityValue::UInt(amount)),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (ClarityName::from("output-index"), ClarityValue::UInt(3)),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("completed-deposit".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("burn-hash"),
                ClarityValue::buff_from(vec![2; 32]).unwrap(),
            ),
            (ClarityName::from("burn-height"), ClarityValue::UInt(139)),
            (
                ClarityName::from("sweep-txid"),
                ClarityValue::buff_from(vec![3; 32]).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::CompletedDeposit(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, 3);
                assert_eq!(
                    event.sweep_block_hash,
                    EventsBitcoinBlockHash::from_byte_array([2; 32])
                );
                assert_eq!(event.sweep_block_height, 139);
                assert_eq!(event.sweep_txid, BitcoinTxid::from_byte_array([3; 32]));
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn create_withdrawal_event() {
        let amount = 24681012;
        let request_id = 1;
        let sender = PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap();
        let block_height = 139;
        let max_fee = 369;
        let recipient_address = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0; 20]));
        let recipient = vec![
            (
                ClarityName::from("version"),
                ClarityValue::buff_from_byte(0),
            ),
            (
                ClarityName::from("hashbytes"),
                ClarityValue::buff_from(vec![0; 20]).unwrap(),
            ),
        ];
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(13579),
            ),
            (ClarityName::from("max-fee"), ClarityValue::UInt(max_fee)),
            (ClarityName::from("output-index"), ClarityValue::UInt(2)),
            (ClarityName::from("amount"), ClarityValue::UInt(amount)),
            (
                ClarityName::from("block-height"),
                ClarityValue::UInt(block_height),
            ),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (
                ClarityName::from("sender"),
                ClarityValue::Principal(sender.clone()),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-create".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("recipient"),
                ClarityValue::Tuple(TupleData::from_data(recipient).unwrap()),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalCreate(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.block_height, block_height as u64);
                assert_eq!(event.max_fee, max_fee as u64);
                assert_eq!(event.sender, sender.into());
                assert_eq!(event.recipient, recipient_address);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn accept_withdrawal_event() {
        let request_id = 1;
        let bitmap = 13579;
        let fee = 369;
        let vout = 20;
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(bitmap),
            ),
            (ClarityName::from("fee"), ClarityValue::UInt(fee)),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (ClarityName::from("output-index"), ClarityValue::UInt(vout)),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-accept".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("burn-hash"),
                ClarityValue::buff_from(vec![2; 32]).unwrap(),
            ),
            (ClarityName::from("burn-height"), ClarityValue::UInt(139)),
            (
                ClarityName::from("sweep-txid"),
                ClarityValue::buff_from(vec![3; 32]).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalAccept(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, vout as u32);
                assert_eq!(event.fee, fee as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
                assert_eq!(
                    event.sweep_block_hash,
                    EventsBitcoinBlockHash::from_byte_array([2; 32])
                );
                assert_eq!(event.sweep_block_height, 139);
                assert_eq!(event.sweep_txid, BitcoinTxid::from_byte_array([3; 32]));
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn reject_withdrawal_event() {
        let request_id = 1;
        let bitmap = 13579;
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(bitmap),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-reject".as_bytes().to_vec())
                    .unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalReject(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn test_key_rotation_event() {
        let new_keys: Vec<EventsPublicKey> = (0..3)
            .map(|_| SECP256K1.generate_keypair(&mut OsRng).1)
            .collect();
        let new_address =
            PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap();
        let new_aggregate_pubkey = SECP256K1.generate_keypair(&mut OsRng).1;
        let new_signature_threshold = 2;

        let event = [
            (
                ClarityName::from("new-keys"),
                ClarityValue::Sequence(SequenceData::List(ListData {
                    data: new_keys
                        .iter()
                        .map(|key| ClarityValue::buff_from(key.serialize().into()).unwrap())
                        .collect(),
                    type_signature: ListTypeData::new_list(BUFF_33.clone(), 128)
                        .expect("Expected list"),
                })),
            ),
            (
                ClarityName::from("new-address"),
                ClarityValue::Principal(new_address.clone()),
            ),
            (
                ClarityName::from("new-aggregate-pubkey"),
                ClarityValue::buff_from(new_aggregate_pubkey.serialize().into()).unwrap(),
            ),
            (
                ClarityName::from("new-signature-threshold"),
                ClarityValue::UInt(new_signature_threshold as u128),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("key-rotation".as_bytes().to_vec()).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::KeyRotation(event) => {
                assert_eq!(event.new_keys, new_keys);
                assert_eq!(event.new_address, new_address);
                assert_eq!(event.new_aggregate_pubkey, new_aggregate_pubkey);
                assert_eq!(event.new_signature_threshold, new_signature_threshold);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    // Just a random public key to make the test case definitions below a
    // little tidier.
    static PUBLIC_KEY: LazyLock<CompressedPublicKey> = LazyLock::new(|| {
        CompressedPublicKey(secp256k1::SecretKey::new(&mut OsRng).public_key(SECP256K1))
    });

    // A "tweaked" public key that is used to make the test case
    // definition below a little easier on the eyes.
    static TWEAKED_PUBLIC_KEY: LazyLock<TweakedPublicKey> =
        LazyLock::new(|| TweakedPublicKey::dangerous_assume_tweaked((*PUBLIC_KEY).into()));

    // A helper function for creating "P2SH-P2WPKH" and "P2SH-P2WSH" script
    // hashes.
    fn new_p2sh_segwit<T: AsRef<bitcoin::script::PushBytes>>(data: T) -> ScriptHash {
        ScriptBuf::builder()
            .push_int(0)
            .push_slice(data)
            .into_script()
            .script_hash()
    }

    impl RawTupleData {
        fn new_recipient<const N: usize>(version: u8, hash: [u8; N]) -> Self {
            let recipient = [
                (
                    ClarityName::from("version"),
                    ClarityValue::buff_from_byte(version),
                ),
                (
                    ClarityName::from("hashbytes"),
                    ClarityValue::buff_from(hash.to_vec()).unwrap(),
                ),
            ]
            .into_iter()
            .collect();

            RawTupleData::new(recipient, TX_INFO)
        }
    }

    #[test_case(
        0x00,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        ScriptBuf::new_p2pkh(&PUBLIC_KEY.pubkey_hash());
    "P2PKH")]
    #[test_case(
        0x01,
        ScriptHash::from(ScriptBuf::new_op_return([1; 5])).to_byte_array(),
        ScriptBuf::new_p2sh(&ScriptBuf::new_op_return([1; 5]).script_hash());
    "P2SH")]
    #[test_case(
        0x02,
        new_p2sh_segwit(PUBLIC_KEY.wpubkey_hash()).to_byte_array(),
        ScriptBuf::new_p2sh(&new_p2sh_segwit(PUBLIC_KEY.wpubkey_hash()));
    "P2SH-P2WPKH")]
    #[test_case(
        0x03,
        new_p2sh_segwit(ScriptBuf::new_op_return([1; 5]).wscript_hash()).to_byte_array(),
        ScriptBuf::new_p2sh(&new_p2sh_segwit(ScriptBuf::new_op_return([1; 5]).wscript_hash()));
    "P2SH-P2WSH")]
    #[test_case(
        0x04,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        ScriptBuf::new_p2wpkh(&PUBLIC_KEY.wpubkey_hash());
    "P2WPKH")]
    #[test_case(
        0x05,
        ScriptBuf::new_op_return([1; 5]).wscript_hash().to_byte_array(),
        ScriptBuf::new_p2wsh(&ScriptBuf::new_op_return([1; 5]).wscript_hash());
    "P2WSH")]
    #[test_case(
        0x06,
        TWEAKED_PUBLIC_KEY.serialize(),
        ScriptBuf::new_p2tr_tweaked(*TWEAKED_PUBLIC_KEY);
    "P2TR")]
    fn recipient_to_script_pub_key<const N: usize>(version: u8, hash: [u8; N], script: ScriptBuf) {
        // For these tests, we show what is expected for the hashbytes for
        // each of the address types and check that the result of the
        // `RawTupleData::try_into_script_pub_key` function matches what
        // the corresponding ScriptBuf function would return.
        //
        // First make a clarity tuple from the input data.
        let map = RawTupleData::new_recipient(version, hash);
        // Now test the function output matches what we expect.
        let actual_script_pub_key = map.try_into_script_pub_key().unwrap();
        assert_eq!(actual_script_pub_key, script);
    }

    #[test_case(0x06, [1; 33]; "hash 33 bytes P2TR")]
    #[test_case(0x06, [1; 20]; "hash 20 bytes P2TR")]
    #[test_case(0x07, [1; 20]; "incorrect version 1")]
    #[test_case(0x07, [1; 32]; "incorrect version 2")]
    #[test_case(0x05, [1; 20]; "bad p2wsh hash length")]
    #[test_case(0x00, [1; 32]; "bad p2pkh 1")]
    #[test_case(0x00, [1; 21]; "bad p2pkh 2")]
    fn bad_recipient_cases<const N: usize>(version: u8, hash: [u8; N]) {
        // For these tests, we show what is unexpected lengths in the
        // hashbytes leads to the `RawTupleData::try_into_script_pub_key`
        // returning an error.
        let map = RawTupleData::new_recipient(version, hash);
        let res = map.try_into_script_pub_key();
        assert!(res.is_err());
    }

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
