//! Utilities for generating dummy values on external types

use bitcoin::hashes::Hash;
use blockstack_lib::chainstate::{nakamoto, stacks};
use fake::faker::time::en::DateTimeAfter;
use fake::Fake;
use rand::Rng;

use crate::storage::model;

use crate::codec::Encode as _;

/// Dummy block
pub fn block<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> bitcoin::Block {
    let max_number_of_transactions = 20;

    let number_of_transactions = (rng.next_u32() % max_number_of_transactions) as usize;

    let mut txdata: Vec<bitcoin::Transaction> = std::iter::repeat_with(|| tx(config, rng))
        .take(number_of_transactions)
        .collect();

    txdata.insert(0, coinbase_tx(config, rng));

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
pub fn signature<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> p256k1::ecdsa::Signature {
    // Represent both the signed message and the signing key.
    let multipurpose_bytes: [u8; 32] = config.fake_with_rng(rng);
    let secret_key = p256k1::scalar::Scalar::from(multipurpose_bytes);

    p256k1::ecdsa::Signature::new(&multipurpose_bytes, &secret_key).unwrap()
}

/// Encrypted dummy DKG shares
pub fn encrypted_dkg_shares<R: rand::RngCore + rand::CryptoRng>(
    _config: &fake::Faker,
    rng: &mut R,
    signer_private_key: &[u8; 32],
    group_key: p256k1::point::Point,
) -> model::EncryptedDkgShares {
    let aggregate_key = group_key.x().to_bytes().to_vec();
    let tweaked_aggregate_key = wsts::compute::tweaked_public_key(&group_key, None)
        .x()
        .to_bytes()
        .to_vec();
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
        group_key,
        parties: vec![(0, party_state)],
    };

    let encoded = signer_state
        .encode_to_vec()
        .expect("encoding to vec failed");

    let encrypted_shares =
        wsts::util::encrypt(signer_private_key, &encoded, rng).expect("failed to encrypt");

    let created_at = DateTimeAfter(time::OffsetDateTime::UNIX_EPOCH).fake_with_rng(rng);

    model::EncryptedDkgShares {
        aggregate_key,
        tweaked_aggregate_key,
        encrypted_shares,
        created_at,
    }
}

/// Coinbase transaction with random block height
fn coinbase_tx<R: rand::RngCore + ?Sized>(
    config: &fake::Faker,
    rng: &mut R,
) -> bitcoin::Transaction {
    // Numbers below 17 are encoded differently which messes with the block height decoding
    let min_block_height = 17;
    let max_block_height = 10000;
    let block_height = rng.gen_range(min_block_height..max_block_height);
    let coinbase_script = bitcoin::script::Builder::new()
        .push_int(block_height)
        .into_script();

    let mut coinbase_tx = tx(config, rng);
    let mut coinbase_input = txin(config, rng);
    coinbase_input.script_sig = coinbase_script;
    coinbase_tx.input = vec![coinbase_input];

    coinbase_tx
}
