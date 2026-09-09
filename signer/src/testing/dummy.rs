//! Utilities for generating dummy values on external types

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Range;

use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TapSighash;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::Hash as _;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::{nakamoto, stacks};
use clarity::util::secp256k1::Secp256k1PublicKey;
use fake::Dummy;
use fake::Fake as _;
use fake::Faker;
use libp2p::Multiaddr;
use libp2p::PeerId;
use p256k1::point::Point;
use p256k1::scalar::Scalar;
use polynomial::Polynomial;
use rand::Rng;
use rand::seq::IteratorRandom as _;
use secp256k1::ecdsa::RecoverableSignature;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use stacks_common::types::chainstate::StacksAddress;
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

use crate::MAX_BITCOIN_BLOCK_VSIZE;
use crate::bitcoin::rpc::BitcoinBlockInfo;
use crate::bitcoin::rpc::BitcoinTxInfo;
use crate::bitcoin::rpc::BitcoinTxVin;
use crate::bitcoin::rpc::BitcoinTxVinPrevout;
use crate::bitcoin::rpc::OutputScriptPubKey;
use crate::bitcoin::utxo::Fees;
use crate::bitcoin::utxo::SignerBtcState;
use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::validation::TxRequestIds;
use crate::codec::Encode as _;
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
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::CompletedDepositEvent;
use crate::storage::model::DkgSharesStatus;
use crate::storage::model::EncryptedDkgShares;
use crate::storage::model::KeyRotationEvent;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::SigHash;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksBlockHeight;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;
use crate::storage::model::TaprootScriptHash;
use crate::storage::model::WithdrawalAcceptEvent;
use crate::storage::model::WithdrawalRejectEvent;

use super::network::MultiaddrExt as _;

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

impl Dummy<Faker> for BitcoinTxInfo {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
        let output_amount = (500_000..1_000_000_000_u64).choose(rng).unwrap();

        let tx_in = txin(config, rng);

        let tx_out = bitcoin::TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: config.fake_with_rng::<ScriptPubKey, _>(rng).into(),
        };

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out],
        };

        tx.fake_with_rng(rng)
    }
}

impl Dummy<bitcoin::Transaction> for BitcoinTxInfo {
    fn dummy_with_rng<R: Rng + ?Sized>(tx: &bitcoin::Transaction, rng: &mut R) -> Self {
        let fee_rate = (1..=50u64).choose(rng).unwrap();

        let vsize = tx.vsize() as u64;
        let vin = tx.input.iter().map(|tx_in| tx_in.fake_with_rng(rng));

        BitcoinTxInfo {
            fee: Some(Amount::from_sat(fee_rate * vsize)),
            vin: vin.collect(),
            tx: tx.clone(),
        }
    }
}

impl Dummy<bitcoin::TxIn> for BitcoinTxVin {
    fn dummy_with_rng<R: Rng + ?Sized>(tx_in: &bitcoin::TxIn, rng: &mut R) -> Self {
        // Check whether this is a transaction input into a coinbase
        // transaction.
        let non_coinbase = !tx_in.previous_output.is_null();
        let script_pubkey: ScriptPubKey = Faker.fake_with_rng(rng);
        let output_amount = script_pubkey.minimal_non_dust().to_sat()..Amount::ONE_BTC.to_sat();
        BitcoinTxVin {
            txid: Some(tx_in.previous_output.txid),
            vout: Some(tx_in.previous_output.vout),
            prevout: non_coinbase.then(|| BitcoinTxVinPrevout {
                value: output_amount.choose(rng).map(Amount::from_sat).unwrap(),
                script_pubkey: OutputScriptPubKey { script: script_pubkey.into() },
            }),
        }
    }
}

impl Dummy<Faker> for BitcoinBlockInfo {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &Faker, rng: &mut R) -> Self {
        let height: BitcoinBlockHeight = Faker.fake_with_rng(rng);
        BitcoinBlockInfo::random_with_height(height, rng)
    }
}

impl BitcoinBlockInfo {
    /// Create a random bitcoin block with the given height
    pub fn random_with_height<R: Rng + ?Sized>(height: BitcoinBlockHeight, rng: &mut R) -> Self {
        // The Default implementation for a bitcoin::TxIn looks similar to
        // the one input of a coinbase transaction.
        let block_height = *height;
        let coinbase_tx_in = bitcoin::TxIn {
            script_sig: bitcoin::script::Builder::new()
                .push_int(block_height.min(i64::MAX as u64) as i64)
                .into_script(),
            ..Default::default()
        };
        let tx_out = bitcoin::TxOut {
            value: Amount::ONE_BTC * 50,
            script_pubkey: Faker.fake_with_rng::<ScriptPubKey, _>(rng).into(),
        };

        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![coinbase_tx_in],
            output: vec![tx_out],
        };

        let time = Faker.fake_with_rng(rng);
        BitcoinBlockInfo {
            block_hash: Faker.fake_with_rng::<BitcoinBlockHash, _>(rng).into(),
            height: block_height.into(),
            time,
            median_time: time.checked_sub(6 * 600),
            previous_block_hash: Faker.fake_with_rng::<BitcoinBlockHash, _>(rng).into(),
            transactions: vec![coinbase.fake_with_rng(rng)],
        }
    }
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
    status: DkgSharesStatus,
) -> model::EncryptedDkgShares {
    let party_state = wsts::traits::PartyState {
        polynomial: None,
        private_keys: vec![],
    };

    let signer_state = wsts::traits::SignerState {
        id: 0,
        key_ids: vec![1],
        num_keys: 1,
        num_parties: 1,
        threshold: 1,
        group_key: group_key.into(),
        party_state,
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
        dkg_shares_status: status,
        started_at_bitcoin_block_hash: Faker.fake_with_rng(rng),
        started_at_bitcoin_block_height: Faker.fake_with_rng::<u32, _>(rng).into(),
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
            sweep_block_height: rng.next_u32().into(),
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
            sweep_block_height: rng.next_u32().into(),
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

impl fake::Dummy<SignerSetConfig> for KeyRotationEvent {
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

        KeyRotationEvent {
            txid: fake::Faker.fake_with_rng(rng),
            block_hash: fake::Faker.fake_with_rng(rng),
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
            dkg_shares_status: DkgSharesStatus::Verified,
            started_at_bitcoin_block_hash: Faker.fake_with_rng(rng),
            started_at_bitcoin_block_height: Faker.fake_with_rng::<u32, _>(rng).into(),
        }
    }
}

impl fake::Dummy<&[PublicKey]> for SignerBtcState {
    fn dummy_with_rng<R: Rng + ?Sized>(signer_set_public_keys: &&[PublicKey], rng: &mut R) -> Self {
        let aggregate_key = PublicKey::combine_keys(*signer_set_public_keys).unwrap();
        let aggregate_key_x_only: XOnlyPublicKey = aggregate_key.into();

        Self {
            fee_rate: Faker.fake_with_rng(rng),
            last_fees: Faker.fake_with_rng(rng),
            magic_bytes: [1, 2],
            public_key: aggregate_key_x_only,
            utxo: SignerUtxo {
                amount: Faker.fake_with_rng(rng),
                outpoint: OutPoint {
                    txid: txid(&Faker, rng),
                    vout: Faker.fake_with_rng(rng),
                },
                public_key: aggregate_key_x_only,
            },
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

impl fake::Dummy<fake::Faker> for TaprootScriptHash {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let bytes: [u8; 32] = config.fake_with_rng(rng);
        TaprootScriptHash::from(bytes)
    }
}

impl fake::Dummy<fake::Faker> for SigHash {
    fn dummy_with_rng<R: Rng + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        TapSighash::from_byte_array(config.fake_with_rng(rng)).into()
    }
}

impl fake::Dummy<fake::Faker> for BitcoinBlockHeight {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_config: &fake::Faker, rng: &mut R) -> Self {
        rng.gen_range(0..i64::MAX as u64).into()
    }
}

impl fake::Dummy<fake::Faker> for StacksBlockHeight {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_config: &fake::Faker, rng: &mut R) -> Self {
        rng.gen_range(0..i64::MAX as u64).into()
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
            id: config.fake_with_rng(rng),
            outpoint: OutPoint {
                txid: txid(config, rng),
                vout: rng.next_u32(),
            },
            tx_fee: config.fake_with_rng(rng),
            signer_bitmap: 0,
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
            id: config.fake_with_rng(rng),
            signer_bitmap: 0,
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
            request_id: config.fake_with_rng::<u32, _>(rng) as u64,
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
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(_: &fake::Faker, rng: &mut R) -> Self {
        let total: u64 = (0..=Amount::MAX_MONEY.to_sat()).fake_with_rng(rng);
        let vsize: u64 = (1..MAX_BITCOIN_BLOCK_VSIZE).fake_with_rng(rng);
        Fees::new_unchecked(total, vsize)
    }
}

impl fake::Dummy<fake::Faker> for BitcoinPreSignRequest {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        BitcoinPreSignRequest {
            request_package: fake::vec![TxRequestIds; 0..20],
            fee_rate: config.fake_with_rng(rng),
            last_fees: Some(config.fake_with_rng::<Fees, _>(rng).into()),
        }
    }
}

impl fake::Dummy<fake::Faker> for BitcoinPreSignAck {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(_config: &fake::Faker, _rng: &mut R) -> Self {
        BitcoinPreSignAck {}
    }
}

impl fake::Dummy<fake::Faker> for model::Timestamp {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(_: &fake::Faker, rng: &mut R) -> Self {
        // The PostgreSQL epoch is 2000-01-01 00:00:00 UTC
        const PG_UNIX_EPOCH: i64 = 946_684_800;
        // Let's try to be somewhat realistic: 2050-01-01 00:00:00 UTC
        const TIMESTAMP_MAX: i64 = 2_524_608_000;
        // Generate a random timestamp between the PostgreSQL epoch and TIMESTAMP_MAX (2050-01-01 00:00:00 UTC)
        // to avoid PG overflow.
        let unix_timestamp: i64 = rng.gen_range(PG_UNIX_EPOCH..TIMESTAMP_MAX);
        time::OffsetDateTime::from_unix_timestamp(unix_timestamp)
            .expect("failed to create OffsetDateTime")
            .into()
    }
}

impl fake::Dummy<fake::Faker> for model::P2PPeer {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let public_key: PublicKey = config.fake_with_rng(rng);
        let multiaddr = Multiaddr::random_memory(rng);
        let peer_id: PeerId = public_key.into();

        model::P2PPeer {
            peer_id: peer_id.into(),
            public_key,
            address: multiaddr.into(),
            last_dialed_at: Faker.fake_with_rng(rng),
        }
    }
}

/// A struct to help with creating dummy values for testing
pub struct Unit;

impl Dummy<Unit> for secp256k1::Keypair {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
        secp256k1::Keypair::new(secp256k1::SECP256K1, rng)
    }
}

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

impl Dummy<Unit> for Vec<(u32, HashMap<u32, Vec<u8>>)> {
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

impl Dummy<Unit> for HashMap<u32, BadPrivateShare> {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        fake::vec![u32; 0..20]
            .into_iter()
            .map(|v| (v, config.fake_with_rng(rng)))
            .collect()
    }
}

impl Dummy<Unit> for HashSet<u32> {
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
            2 => SignatureType::Taproot,
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
            },
        )
    }
}

impl Dummy<Unit> for PartyState {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(config: &Unit, rng: &mut R) -> Self {
        PartyState {
            polynomial: config.fake_with_rng(rng),
            private_keys: fake::vec![(); 0..20]
                .into_iter()
                .map(|_| config.fake_with_rng(rng))
                .collect(),
        }
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
            party_state: config.fake_with_rng(rng),
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
        let id = config.fake_with_rng(rng);
        let poly = fake::vec![(); 1..20]
            .into_iter()
            .map(|_| config.fake_with_rng(rng))
            .collect();
        // SAFETY: We know the poly is non-empty because we generated at
        // least one point, so this will never fail
        PolyCommitment::new(id, poly).unwrap()
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
