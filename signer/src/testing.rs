//! Module with testing utility functions.

pub mod dummy;
pub mod message;
pub mod network;
pub mod storage;
pub mod transaction_signer;
pub mod wallet;

use crate::utxo::UnsignedTransaction;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::opcodes;
use bitcoin::PubkeyHash;
use bitcoin::ScriptBuf;
use bitcoin::TapSighashType;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use secp256k1::SECP256K1;

/// A helper function for correctly setting witness data
pub fn set_witness_data(unsigned: &mut UnsignedTransaction, keypair: secp256k1::Keypair) {
    let sighash_type = TapSighashType::Default;
    let sighashes = unsigned.construct_digests().unwrap();

    let signer_msg = secp256k1::Message::from(sighashes.signers);
    let tweaked = keypair.tap_tweak(SECP256K1, None);
    let signature = SECP256K1.sign_schnorr(&signer_msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    let signer_witness = Witness::p2tr_key_spend(&signature);

    let deposit_witness = sighashes.deposits.into_iter().map(|(deposit, sighash)| {
        let deposit_msg = secp256k1::Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&deposit_msg, &keypair);
        let signature = bitcoin::taproot::Signature { signature, sighash_type };
        deposit.construct_witness_data(signature)
    });

    let witness_data: Vec<Witness> = std::iter::once(signer_witness)
        .chain(deposit_witness)
        .collect();

    unsigned
        .tx
        .input
        .iter_mut()
        .zip(witness_data)
        .for_each(|(tx_in, witness)| {
            tx_in.witness = witness;
        });
}

/// Create a dummy deposit script assuming the signer's public key is the
/// input.
pub fn peg_in_deposit_script(signers_public_key: &XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::builder()
        // Just some dummy data representing the stacks address the user
        // wants the sBTC deposited to. According to https://docs.stacks.co/stacks-101/accounts,
        // stacks addresses are c32check encoded RIPEMD-160 hashes of the
        // SHA256 of the public key. This means they are 25 bytes long
        .push_slice([0u8; 25])
        .push_opcode(opcodes::all::OP_DROP)
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(PubkeyHash::hash(&signers_public_key.serialize()))
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}
