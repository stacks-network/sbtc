//! Utilities for generating dummy values on external types

use std::collections::BTreeMap;
use std::ops::Range;

use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TapSighash;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::{nakamoto, stacks};
use clarity::util::secp256k1::Secp256k1PublicKey;
use fake::Dummy;
use fake::Fake;
use fake::Faker;
use p256k1::point::Point;
use p256k1::scalar::Scalar;
use polynomial::Polynomial;
use rand::seq::IteratorRandom as _;
use rand::Rng;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::SECP256K1;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use stacks_common::types::chainstate::StacksAddress;
use wsts::common::Nonce;
use wsts::common::PolyCommitment;
use wsts::common::PublicNonce;
use wsts::common::SignatureShare;
use wsts::common::TupleProof;
use wsts::net::BadPrivateShare;
use wsts::net::DkgBegin;
use wsts::net::DkgEnd;
use wsts::net::DkgEndBegin;
use wsts::net::DkgFailure;
use wsts::net::DkgPrivateBegin;
use wsts::net::DkgPrivateShares;
use wsts::net::DkgPublicShares;
use wsts::net::DkgStatus;
use wsts::net::NonceRequest;
use wsts::net::NonceResponse;
use wsts::net::SignatureShareRequest;
use wsts::net::SignatureShareResponse;
use wsts::net::SignatureType;
use wsts::traits::PartyState;
use wsts::traits::SignerState;

use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::TxRequestIds;
use crate::codec::Encode;
use crate::ecdsa::Signed;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::keys::SignerScriptPubKey as _;
use crate::message::BitcoinPreSignAck;
use crate::message::BitcoinPreSignRequest;
use crate::message::SignerMessage;
use crate::stacks::contracts::AcceptWithdrawalV1;
use crate::stacks::contracts::CompleteDepositV1;
use crate::stacks::contracts::RejectWithdrawalV1;
use crate::stacks::contracts::RotateKeysV1;
use crate::storage::model;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTx;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::CompletedDepositEvent;
use crate::storage::model::EncryptedDkgShares;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::RotateKeysTransaction;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::SigHash;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;
use crate::storage::model::WithdrawalAcceptEvent;
use crate::storage::model::WithdrawalCreateEvent;
use crate::storage::model::WithdrawalRejectEvent;

/// Dummy block
pub fn block<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
    height: i64,
) -> bitcoin::Block {
    let max_number_of_transactions = 20;

    let number_of_transactions = (rng.next_u32() % max_number_of_transactions) as usize;

    let mut txdata: Vec<bitcoin::Transaction> = std::iter::repeat_with(|| tx(config, rng))
        .take(number_of_transactions)
        .collect();

    txdata.insert(0, coinbase_tx(config, rng, height));

    let header = bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: block_hash(config, rng),
        merkle_root: merkle_root(config, rng),
        time: config.fake_with_rng(rng),
        bits: bitcoin::CompactTarget::from_consensus(config.fake_with_rng(rng)),
        nonce: config.fake_with_rng(rng),
    };

    bitcoin::Block { header, txdata }
}

/// Dummy txid
pub fn txid<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> bitcoin::Txid {
    let bytes: [u8; 32] = config.fake_with_rng(rng);
    bitcoin::Txid::from_byte_array(bytes)
}

/// Dummy transaction
pub fn tx<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> bitcoin::Transaction {
    let max_input_size = 50;
    let max_output_size = 50;

    let input_size = (rng.next_u32() % max_input_size) as usize;
    let output_size = (rng.next_u32() % max_output_size) as usize;

    let input = std::iter::repeat_with(|| txin(config, rng))
        .take(input_size)
        .collect();
    let output = std::iter::repeat_with(|| txout(config, rng))
        .take(output_size)
        .collect();

    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output,
    }
}

/// Dummy transaction input
pub fn txin<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> bitcoin::TxIn {
    bitcoin::TxIn {
        previous_output: bitcoin::OutPoint::new(txid(config, rng), config.fake_with_rng(rng)),
        sequence: bitcoin::Sequence::ZERO,
        script_sig: bitcoin::ScriptBuf::new(),
        witness: bitcoin::witness::Witness::new(),
    }
}

/// Dummy transaction output
pub fn txout<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> bitcoin::TxOut {
    bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(config.fake_with_rng(rng)),
        script_pubkey: bitcoin::ScriptBuf::new(),
    }
}

/// Dummy block hash
pub fn block_hash<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> bitcoin::BlockHash {
    bitcoin::BlockHash::from_byte_array(config.fake_with_rng(rng))
}

/// Dummy merkle root
pub fn merkle_root<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> bitcoin::TxMerkleNode {
    bitcoin::TxMerkleNode::from_byte_array(config.fake_with_rng(rng))
}

/// Dummy stacks block
pub fn stacks_block<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> nakamoto::NakamotoBlock {
    let max_number_of_transactions = 20;

    let number_of_transactions = (rng.next_u32() % max_number_of_transactions) as usize;

    let txs = std::iter::repeat_with(|| stacks_tx(config, rng))
        .take(number_of_transactions)
        .collect();

    let header = nakamoto::NakamotoBlockHeader::empty();

    nakamoto::NakamotoBlock { header, txs }
}

/// Dummy stacks transaction
pub fn stacks_tx<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> stacks::StacksTransaction {
    stacks::StacksTransaction {
        version: stacks::TransactionVersion::Testnet,
        chain_id: config.fake_with_rng(rng),
        auth: stacks::TransactionAuth::from_p2sh(&[], 0).unwrap(),
        anchor_mode: stacks::TransactionAnchorMode::Any,
        post_condition_mode: stacks::TransactionPostConditionMode::Allow,
        post_conditions: Vec::new(),
        payload: stacks::TransactionPayload::new_smart_contract(
            fake::faker::name::en::FirstName().fake_with_rng(rng),
            fake::faker::lorem::en::Paragraph(3..5)
                .fake_with_rng::<String, _>(rng)
                .as_str(),
            None,
        )
        .unwrap(),
    }
}

/// Dummy stacks transaction ID
pub fn stacks_txid<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> blockstack_lib::burnchains::Txid {
    blockstack_lib::burnchains::Txid(config.fake_with_rng(rng))
}

/// Dummy signature
pub fn recoverable_signature<R>(config: &fake::Faker, rng: &mut R) -> RecoverableSignature
where
    R: rand::RngCore + ?Sized,
{
    // Represent the signed message.
    let digest: [u8; 32] = config.fake_with_rng(rng);
    let msg = secp256k1::Message::from_digest(digest);
    PrivateKey::new(rng).sign_ecdsa_recoverable(&msg)
}

/// Encrypted dummy DKG shares
pub fn encrypted_dkg_shares<R: rand::RngCore + rand::CryptoRng>(
    _config: &fake::Faker,
    rng: &mut R,
    signer_private_key: &[u8; 32],
    group_key: PublicKey,
) -> model::EncryptedDkgShares {
    let party_state = wsts::traits::PartyState {
        polynomial: None,
        private_keys: vec![],
        nonce: wsts::common::Nonce::random(rng),
    };

    let signer_state = wsts::traits::SignerState {
        id: 0,
        key_ids: vec![1],
        num_keys: 1,
        num_parties: 1,
        threshold: 1,
        group_key: group_key.into(),
        parties: vec![(0, party_state)],
    };

    let encoded = signer_state.encode_to_vec();

    let encrypted_private_shares =
        wsts::util::encrypt(signer_private_key, &encoded, rng).expect("failed to encrypt");
    let public_shares: BTreeMap<u32, wsts::net::DkgPublicShares> = BTreeMap::new();
    let public_shares = public_shares.encode_to_vec();

    model::EncryptedDkgShares {
        aggregate_key: group_key,
        encrypted_private_shares,
        public_shares,
        tweaked_aggregate_key: group_key.signers_tweaked_pubkey().unwrap(),
        script_pubkey: group_key.signers_script_pubkey().into(),
        signer_set_public_keys: vec![fake::Faker.fake_with_rng(rng)],
        signature_share_threshold: 1,
    }
}

/// Coinbase transaction with random block height.
///
/// Block heights below 17 are encoded differently which messes with the
/// block height decoding
fn coinbase_tx<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
    block_height: i64,
) -> bitcoin::Transaction {
    let coinbase_script = bitcoin::script::Builder::new()
        .push_int(block_height)
        .into_script();

    let mut coinbase_tx = tx(config, rng);
    let mut coinbase_input = txin(config, rng);
    coinbase_input.script_sig = coinbase_script;
    coinbase_tx.input = vec![coinbase_input];

    coinbase_tx
}

impl fake::Dummy<fake::Faker> for PublicKey {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &fake::Faker, rng: &mut R) -> Self {
        let sk = secp256k1::SecretKey::new(rng);
        Self::from(secp256k1::PublicKey::from_secret_key_global(&sk))
    }
}

impl fake::Dummy<fake::Faker> for PublicKeyXOnly {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &fake::Faker, rng: &mut R) -> Self {
        let pk: PublicKey = fake::Faker.fake_with_rng(rng);
        Self::from(secp256k1::XOnlyPublicKey::from(pk))
    }
}

/// Used to for fine-grained control of generating fake testing addresses.
#[derive(Debug)]
pub struct BitcoinAddresses(pub Range<usize>);

impl fake::Dummy<BitcoinAddresses> for Vec<ScriptPubKey> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &BitcoinAddresses, rng: &mut R) -> Self {
        let num_addresses = config.0.clone().choose(rng).unwrap_or(1);
        std::iter::repeat_with(|| fake::Faker.fake_with_rng(rng))
            .take(num_addresses)
            .collect()
    }
}

impl fake::Dummy<fake::Faker> for WithdrawalAcceptEvent {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let bitmap = rng.next_u64() as u128;
        WithdrawalAcceptEvent {
            txid: config.fake_with_rng(rng),
            block_id: config.fake_with_rng(rng),
            request_id: rng.next_u32() as u64,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
            outpoint: OutPoint {
                txid: txid(config, rng),
                vout: rng.next_u32(),
            },
            fee: rng.next_u32() as u64,
            sweep_block_hash: config.fake_with_rng(rng),
            sweep_block_height: rng.next_u32() as u64,
            sweep_txid: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for WithdrawalRejectEvent {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let bitmap = rng.next_u64() as u128;
        WithdrawalRejectEvent {
            txid: config.fake_with_rng(rng),
            block_id: config.fake_with_rng(rng),
            request_id: rng.next_u32() as u64,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
        }
    }
}

impl fake::Dummy<fake::Faker> for WithdrawalCreateEvent {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        WithdrawalCreateEvent {
            txid: config.fake_with_rng(rng),
            block_id: config.fake_with_rng(rng),
            request_id: rng.next_u32() as u64,
            amount: rng.next_u32() as u64,
            sender: config.fake_with_rng(rng),
            recipient: config.fake_with_rng::<ScriptPubKey, _>(rng),
            max_fee: rng.next_u32() as u64,
            block_height: rng.next_u32() as u64,
        }
    }
}

impl fake::Dummy<fake::Faker> for CompletedDepositEvent {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        CompletedDepositEvent {
            txid: config.fake_with_rng(rng),
            block_id: config.fake_with_rng(rng),
            outpoint: OutPoint {
                txid: txid(config, rng),
                vout: rng.next_u32(),
            },
            amount: rng.next_u32() as u64,
            sweep_block_hash: config.fake_with_rng(rng),
            sweep_block_height: rng.next_u32() as u64,
            sweep_txid: config.fake_with_rng(rng),
        }
    }
}

/// A struct for configuring the signing set of a randomly generated
/// [`RotateKeysTransaction`] that has an aggregate key formed from the
/// randomly generated public keys.
pub struct SignerSetConfig {
    /// The number of signers in the signing set.
    pub num_keys: u16,
    /// The number of signatures required
    pub signatures_required: u16,
}

impl fake::Dummy<SignerSetConfig> for RotateKeysTransaction {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &SignerSetConfig, rng: &mut R) -> Self {
        let signer_set: Vec<PublicKey> = std::iter::repeat_with(|| fake::Faker.fake_with_rng(rng))
            .take(config.num_keys as usize)
            .collect();

        let address = StacksPrincipal::from(clarity::vm::types::PrincipalData::from(
            StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                &AddressHashMode::SerializeP2SH,
                config.signatures_required as usize,
                &signer_set
                    .iter()
                    .map(Secp256k1PublicKey::from)
                    .collect::<Vec<_>>(),
            )
            .expect("failed to create StacksAddress"),
        ));

        RotateKeysTransaction {
            txid: fake::Faker.fake_with_rng(rng),
            address,
            aggregate_key: fake::Faker.fake_with_rng(rng),
            signer_set,
            signatures_required: config.signatures_required,
        }
    }
}

impl fake::Dummy<SignerSetConfig> for EncryptedDkgShares {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &SignerSetConfig, rng: &mut R) -> Self {
        let signer_set_public_keys: Vec<PublicKey> =
            std::iter::repeat_with(|| fake::Faker.fake_with_rng(rng))
                .take(config.num_keys as usize)
                .collect();
        let aggregate_key = PublicKey::combine_keys(&signer_set_public_keys).unwrap();
        EncryptedDkgShares {
            aggregate_key: PublicKey::combine_keys(&signer_set_public_keys).unwrap(),
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
            script_pubkey: aggregate_key.signers_script_pubkey().into(),
            encrypted_private_shares: Vec::new(),
            public_shares: Vec::new(),
            signer_set_public_keys,
            signature_share_threshold: config.signatures_required,
        }
    }
}

impl fake::Dummy<fake::Faker> for BitcoinTxId {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        From::<[u8; 32]>::from(config.fake_with_rng(rng))
    }
}

impl fake::Dummy<fake::Faker> for BitcoinBlockHash {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        From::<[u8; 32]>::from(config.fake_with_rng(rng))
    }
}

impl fake::Dummy<fake::Faker> for StacksBlockHash {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        From::<[u8; 32]>::from(config.fake_with_rng(rng))
    }
}

impl fake::Dummy<fake::Faker> for StacksTxId {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        From::<[u8; 32]>::from(config.fake_with_rng(rng))
    }
}

impl fake::Dummy<fake::Faker> for StacksPrincipal {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pubkey = stacks_common::util::secp256k1::Secp256k1PublicKey::from(&public_key);
        let address = StacksAddress::p2pkh(false, &pubkey);
        StacksPrincipal::from(clarity::vm::types::PrincipalData::from(address))
    }
}

impl fake::Dummy<fake::Faker> for ScriptPubKey {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pk = bitcoin::CompressedPublicKey(public_key.into());
        let script_pubkey = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        ScriptPubKey::from(script_pubkey)
    }
}

impl fake::Dummy<fake::Faker> for SigHash {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        TapSighash::from_byte_array(config.fake_with_rng(rng)).into()
    }
}

/// A struct to aid in the generation of bitcoin deposit transactions.
///
/// BitcoinTx is created with this config, then it will have a UTXO that is
/// locked with a valid deposit scriptPubKey
#[derive(Debug, Clone, Copy, fake::Dummy)]
pub struct DepositTxConfig {
    /// The public key of the signer.
    pub aggregate_key: PublicKey,
    /// The amount of the deposit
    #[dummy(faker = "2000..1_000_000_000")]
    pub amount: u64,
    /// The max fee of the deposit
    #[dummy(faker = "1000..1_000_000_000")]
    pub max_fee: u64,
    /// The lock-time of the deposit. The value here cannot have the 32nd
    /// bit set to 1 or the else the [`ReclaimScriptInputs::try_new`]
    /// function will return an error.
    #[dummy(faker = "2..250")]
    pub lock_time: u32,
}

impl fake::Dummy<DepositTxConfig> for BitcoinTx {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &DepositTxConfig, rng: &mut R) -> Self {
        let deposit = DepositScriptInputs {
            signers_public_key: config.aggregate_key.into(),
            recipient: fake::Faker.fake_with_rng::<StacksPrincipal, _>(rng).into(),
            max_fee: config.max_fee.min(config.amount),
        };
        let deposit_script = deposit.deposit_script();
        // This is the part of the reclaim script that the user controls.
        let reclaim_script = ScriptBuf::builder()
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();

        let reclaim = ReclaimScriptInputs::try_new(config.lock_time, reclaim_script).unwrap();
        let reclaim_script = reclaim.reclaim_script();

        let deposit_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                sequence: bitcoin::Sequence::ZERO,
                script_sig: ScriptBuf::new(),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(config.amount),
                script_pubkey: sbtc::deposits::to_script_pubkey(deposit_script, reclaim_script),
            }],
        };

        Self::from(deposit_tx)
    }
}

impl fake::Dummy<fake::Faker> for BitcoinTx {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let deposit_config: DepositTxConfig = config.fake_with_rng(rng);
        deposit_config.fake_with_rng(rng)
    }
}

impl fake::Dummy<DepositTxConfig> for model::Transaction {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &DepositTxConfig, rng: &mut R) -> Self {
        let mut tx = Vec::new();

        let bitcoin_tx: BitcoinTx = config.fake_with_rng(rng);
        bitcoin_tx
            .consensus_encode(&mut tx)
            .expect("In-memory writers never fail");

        model::Transaction {
            tx,
            txid: bitcoin_tx.compute_txid().to_byte_array(),
            tx_type: model::TransactionType::DepositRequest,
            block_hash: fake::Faker.fake_with_rng(rng),
        }
    }
}

/// A struct to aid in the generation of bitcoin sweep transactions.
///
/// BitcoinTx is created with this config, then it will have a UTXO that is
/// locked with a valid scriptPubKey that the signers can spend.
#[derive(Debug, Clone)]
pub struct SweepTxConfig {
    /// The public key of the signers.
    pub aggregate_key: PublicKey,
    /// The amount of the signers UTXO afterwards.
    pub amounts: std::ops::Range<u64>,
    /// The outpoints to use as inputs.
    pub inputs: Vec<OutPoint>,
    /// The outputs to include as withdrawals.
    pub outputs: Vec<(u64, ScriptPubKey)>,
}

impl fake::Dummy<SweepTxConfig> for BitcoinTx {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &SweepTxConfig, rng: &mut R) -> Self {
        let internal_key = config.aggregate_key.into();
        let outpoints = config.inputs.iter().copied();

        let first_output = TxOut {
            value: Amount::from_sat(config.amounts.clone().choose(rng).unwrap_or_default()),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, internal_key, None),
        };
        let script_pubkey = if config.outputs.is_empty() {
            ScriptBuf::new_op_return([0; 21])
        } else {
            ScriptBuf::new_op_return([0; 41])
        };
        let second_output = TxOut {
            value: Amount::ZERO,
            script_pubkey,
        };
        let outputs = config.outputs.iter().map(|(amount, script_pub_key)| TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: script_pub_key.clone().into(),
        });

        let sweep_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: outpoints
                .map(|previous_output| TxIn {
                    previous_output,
                    sequence: bitcoin::Sequence::ZERO,
                    script_sig: ScriptBuf::new(),
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output: std::iter::once(first_output)
                .chain([second_output])
                .chain(outputs)
                .collect(),
        };

        Self::from(sweep_tx)
    }
}

impl fake::Dummy<SweepTxConfig> for model::Transaction {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &SweepTxConfig, rng: &mut R) -> Self {
        let mut tx = Vec::new();

        let bitcoin_tx: BitcoinTx = config.fake_with_rng(rng);
        bitcoin_tx.consensus_encode(&mut tx).unwrap();

        model::Transaction {
            tx,
            txid: bitcoin_tx.compute_txid().to_byte_array(),
            tx_type: model::TransactionType::SbtcTransaction,
            block_hash: fake::Faker.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for Signed<SignerMessage> {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let pk: PrivateKey = PrivateKey::new(rng);
        let digest: [u8; 32] = config.fake_with_rng(rng);
        Signed {
            inner: config.fake_with_rng(rng),
            signature: pk.sign_ecdsa(&secp256k1::Message::from_digest(digest)),
            signer_public_key: PublicKey::from_private_key(&pk),
        }
    }
}

impl fake::Dummy<fake::Faker> for CompleteDepositV1 {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pubkey = stacks_common::util::secp256k1::Secp256k1PublicKey::from(&public_key);
        let address = StacksAddress::p2pkh(false, &pubkey);

        CompleteDepositV1 {
            outpoint: OutPoint {
                txid: txid(config, rng),
                vout: rng.next_u32(),
            },
            amount: config.fake_with_rng(rng),
            recipient: config.fake_with_rng::<StacksPrincipal, R>(rng).into(),
            deployer: address,
            sweep_txid: config.fake_with_rng(rng),
            sweep_block_hash: config.fake_with_rng(rng),
            sweep_block_height: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for AcceptWithdrawalV1 {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pubkey = stacks_common::util::secp256k1::Secp256k1PublicKey::from(&public_key);
        let address = StacksAddress::p2pkh(false, &pubkey);

        AcceptWithdrawalV1 {
            request_id: config.fake_with_rng(rng),
            outpoint: OutPoint {
                txid: txid(config, rng),
                vout: rng.next_u32(),
            },
            tx_fee: config.fake_with_rng(rng),
            signer_bitmap: BitArray::new(config.fake_with_rng(rng)),
            deployer: address,
            sweep_block_hash: config.fake_with_rng(rng),
            sweep_block_height: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for RejectWithdrawalV1 {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pubkey = stacks_common::util::secp256k1::Secp256k1PublicKey::from(&public_key);
        let address = StacksAddress::p2pkh(false, &pubkey);

        RejectWithdrawalV1 {
            request_id: config.fake_with_rng(rng),
            signer_bitmap: BitArray::new(config.fake_with_rng(rng)),
            deployer: address,
        }
    }
}

impl fake::Dummy<fake::Faker> for RotateKeysV1 {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let pubkey = stacks_common::util::secp256k1::Secp256k1PublicKey::from(&public_key);
        let address = StacksAddress::p2pkh(false, &pubkey);

        RotateKeysV1 {
            new_keys: config.fake_with_rng(rng),
            aggregate_key: config.fake_with_rng(rng),
            deployer: address,
            signatures_required: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for QualifiedRequestId {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        QualifiedRequestId {
            request_id: config.fake_with_rng(rng),
            txid: config.fake_with_rng(rng),
            block_hash: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for TxRequestIds {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let take = (0..20).fake_with_rng(rng);
        let deposits = std::iter::repeat_with(|| OutPoint {
            txid: txid(config, rng),
            vout: rng.next_u32(),
        })
        .take(take)
        .collect();

        TxRequestIds {
            deposits,
            withdrawals: fake::vec![QualifiedRequestId; 0..20],
        }
    }
}

impl fake::Dummy<fake::Faker> for Fees {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        Fees {
            total: config.fake_with_rng(rng),
            rate: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for BitcoinPreSignRequest {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        BitcoinPreSignRequest {
            request_package: fake::vec![TxRequestIds; 0..20],
            fee_rate: config.fake_with_rng(rng),
            last_fees: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for BitcoinPreSignAck {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(_config: &fake::Faker, _rng: &mut R) -> Self {
        BitcoinPreSignAck {}
    }
}
/// A struct to help with creating dummy values for testing
pub struct Unit;

impl Dummy<Unit> for bitcoin::OutPoint {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        let bytes: [u8; 32] = Faker.fake_with_rng(rng);
        let txid = bitcoin::Txid::from_byte_array(bytes);
        let vout: u32 = Faker.fake_with_rng(rng);
        bitcoin::OutPoint { txid, vout }
    }
}

impl Dummy<Unit> for RecoverableSignature {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        let private_key = PrivateKey::new(rng);
        let msg = secp256k1::Message::from_digest([0; 32]);
        private_key.sign_ecdsa_recoverable(&msg)
    }
}

impl Dummy<Unit> for secp256k1::ecdsa::Signature {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        let private_key = PrivateKey::new(rng);
        let msg = secp256k1::Message::from_digest([0; 32]);
        private_key.sign_ecdsa(&msg)
    }
}

impl Dummy<Unit> for StacksAddress {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        let public_key: PublicKey = Faker.fake_with_rng(rng);
        let pubkey = public_key.into();
        let mainnet: bool = Faker.fake_with_rng(rng);
        StacksAddress::p2pkh(mainnet, &pubkey)
    }
}

impl Dummy<Unit> for Scalar {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        let number: [u8; 32] = Faker.fake_with_rng(rng);
        p256k1::scalar::Scalar::from(number)
    }
}

impl Dummy<Unit> for Point {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        Point::from(config.fake_with_rng::<Scalar, R>(rng))
    }
}

impl Dummy<Unit> for Polynomial<Scalar> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, _: &mut R) -> Self {
        Polynomial::new(
            fake::vec![[u8; 32]; 0..=15]
                .into_iter()
                .map(p256k1::scalar::Scalar::from)
                .collect(),
        )
    }
}

impl Dummy<Unit> for (u32, Scalar) {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        (Faker.fake_with_rng(rng), config.fake_with_rng(rng))
    }
}

impl Dummy<Unit> for DkgBegin {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        DkgBegin {
            dkg_id: Faker.fake_with_rng(rng),
        }
    }
}
impl Dummy<Unit> for DkgPrivateBegin {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        DkgPrivateBegin {
            dkg_id: Faker.fake_with_rng(rng),
            signer_ids: Faker.fake_with_rng(rng),
            key_ids: Faker.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for Vec<(u32, hashbrown::HashMap<u32, Vec<u8>>)> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, _: &mut R) -> Self {
        fake::vec![u32; 0..16]
            .into_iter()
            .map(|v| (v, fake::vec![(u32, Vec<u8>); 0..16].into_iter().collect()))
            .collect()
    }
}

impl Dummy<Unit> for DkgPrivateShares {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        DkgPrivateShares {
            dkg_id: Faker.fake_with_rng(rng),
            signer_id: Faker.fake_with_rng(rng),
            shares: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for DkgEndBegin {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        DkgEndBegin {
            dkg_id: Faker.fake_with_rng(rng),
            signer_ids: Faker.fake_with_rng(rng),
            key_ids: Faker.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for TupleProof {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        TupleProof {
            R: config.fake_with_rng(rng),
            rB: config.fake_with_rng(rng),
            z: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for BadPrivateShare {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        BadPrivateShare {
            shared_key: config.fake_with_rng(rng),
            tuple_proof: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for hashbrown::HashMap<u32, BadPrivateShare> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        fake::vec![u32; 0..20]
            .into_iter()
            .map(|v| (v, config.fake_with_rng(rng)))
            .collect()
    }
}

impl Dummy<Unit> for hashbrown::HashSet<u32> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, _: &mut R) -> Self {
        fake::vec![u32; 0..20].into_iter().collect()
    }
}

impl Dummy<Unit> for DkgStatus {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        match rng.gen_range(0..6usize) {
            0 => DkgStatus::Success,
            1 => DkgStatus::Failure(DkgFailure::BadState),
            2 => DkgStatus::Failure(DkgFailure::MissingPublicShares(config.fake_with_rng(rng))),
            3 => DkgStatus::Failure(DkgFailure::BadPublicShares(config.fake_with_rng(rng))),
            4 => DkgStatus::Failure(DkgFailure::MissingPrivateShares(config.fake_with_rng(rng))),
            5 => DkgStatus::Failure(DkgFailure::BadPrivateShares(config.fake_with_rng(rng))),
            _ => unreachable!(),
        }
    }
}

impl Dummy<Unit> for DkgEnd {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        DkgEnd {
            dkg_id: Faker.fake_with_rng(rng),
            signer_id: Faker.fake_with_rng(rng),
            status: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for SignatureType {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        match rng.gen_range(0..3usize) {
            0 => SignatureType::Frost,
            1 => SignatureType::Schnorr,
            2 => SignatureType::Taproot(if rng.gen_bool(0.5) {
                None
            } else {
                Some(Faker.fake_with_rng(rng))
            }),
            _ => unreachable!(),
        }
    }
}

impl Dummy<Unit> for NonceRequest {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        NonceRequest {
            dkg_id: Faker.fake_with_rng(rng),
            sign_id: Faker.fake_with_rng(rng),
            sign_iter_id: Faker.fake_with_rng(rng),
            message: Faker.fake_with_rng(rng),
            signature_type: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for PublicNonce {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        PublicNonce {
            D: config.fake_with_rng(rng),
            E: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for NonceResponse {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        NonceResponse {
            dkg_id: Faker.fake_with_rng(rng),
            sign_id: Faker.fake_with_rng(rng),
            sign_iter_id: Faker.fake_with_rng(rng),
            signer_id: Faker.fake_with_rng(rng),
            key_ids: Faker.fake_with_rng(rng),
            nonces: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
            message: Faker.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for SignatureShareRequest {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        SignatureShareRequest {
            dkg_id: Faker.fake_with_rng(rng),
            sign_id: Faker.fake_with_rng(rng),
            sign_iter_id: Faker.fake_with_rng(rng),
            nonce_responses: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
            signature_type: config.fake_with_rng(rng),
            message: Faker.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for SignatureShare {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        SignatureShare {
            id: Faker.fake_with_rng(rng),
            z_i: config.fake_with_rng(rng),
            key_ids: Faker.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for SignatureShareResponse {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        SignatureShareResponse {
            dkg_id: Faker.fake_with_rng(rng),
            sign_id: Faker.fake_with_rng(rng),
            sign_iter_id: Faker.fake_with_rng(rng),
            signer_id: Faker.fake_with_rng(rng),
            signature_shares: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
        }
    }
}

impl Dummy<Unit> for Nonce {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        Nonce {
            d: config.fake_with_rng(rng),
            e: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for (u32, PartyState) {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        (
            Faker.fake_with_rng(rng),
            PartyState {
                polynomial: config.fake_with_rng(rng),
                private_keys: fake::vec![(); 0..20]
                    .into_iter()
                    .map(|_| config.fake_with_rng(rng))
                    .collect(),
                nonce: config.fake_with_rng(rng),
            },
        )
    }
}

impl Dummy<Unit> for SignerState {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        SignerState {
            id: Faker.fake_with_rng(rng),
            key_ids: Faker.fake_with_rng(rng),
            num_keys: Faker.fake_with_rng(rng),
            num_parties: Faker.fake_with_rng(rng),
            threshold: Faker.fake_with_rng(rng),
            group_key: config.fake_with_rng(rng),
            parties: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
        }
    }
}

impl Dummy<Unit> for wsts::schnorr::ID {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        wsts::schnorr::ID {
            id: config.fake_with_rng(rng),
            kG: config.fake_with_rng(rng),
            kca: config.fake_with_rng(rng),
        }
    }
}

impl Dummy<Unit> for PolyCommitment {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        PolyCommitment {
            id: config.fake_with_rng(rng),
            poly: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
        }
    }
}

impl Dummy<Unit> for (u32, PolyCommitment) {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        (Faker.fake_with_rng(rng), config.fake_with_rng(rng))
    }
}

impl Dummy<Unit> for DkgPublicShares {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        DkgPublicShares {
            dkg_id: Faker.fake_with_rng(rng),
            signer_id: Faker.fake_with_rng(rng),
            comms: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
        }
    }
}

impl Dummy<Unit> for BTreeMap<u32, DkgPublicShares> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        fake::vec![(); 0..20]
            .into_iter()
            .map(|_| (Faker.fake_with_rng(rng), config.fake_with_rng(rng)))
            .collect()
    }
}
