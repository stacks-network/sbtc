//! General utilities for the storage.

use std::collections::HashSet;

use crate::bitcoin::utxo::SignerUtxo;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;

/// Given the sbtc txs in a block, returns the `aggregate_key` utxo (if there's exactly one)
pub fn get_utxo(
    aggregate_key: &PublicKey,
    sbtc_txs: Vec<bitcoin::Transaction>,
) -> Result<Option<SignerUtxo>, Error> {
    let script_pubkey = aggregate_key.signers_script_pubkey();

    let spent: HashSet<bitcoin::OutPoint> = sbtc_txs
        .iter()
        .flat_map(|tx| tx.input.iter().map(|txin| txin.previous_output))
        .collect();

    let utxos = sbtc_txs
        .iter()
        .flat_map(|tx| {
            if let Some(tx_out) = tx.output.first() {
                let outpoint = bitcoin::OutPoint::new(tx.compute_txid(), 0);
                if tx_out.script_pubkey == *script_pubkey && !spent.contains(&outpoint) {
                    return Some(SignerUtxo {
                        outpoint,
                        amount: tx_out.value.to_sat(),
                        // Txs are filtered based on the `aggregate_key` script pubkey
                        public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
                    });
                }
            }

            None
        })
        .collect::<Vec<_>>();

    match utxos[..] {
        [] => Ok(None),
        [utxo] => Ok(Some(utxo)),
        _ => Err(Error::TooManySignerUtxos),
    }
}
