//! Helper functions for the bitcoin module
//!
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::consensus::encode::serialize_hex;

use emily_client::models::CreateDepositRequestBody;
use futures::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use crate::bitcoin::utxo;
use crate::bitcoin::zmq::BitcoinCoreMessageStream;
use crate::error::Error;

/// Return a transaction that is kinda like the signers' transaction,
/// but it does not service any requests, and it does not have any
/// signatures.
pub fn base_signer_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // This is the signers' previous UTXO
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            },
        ],
        output: vec![
            // This represents the signers' new UTXO.
            TxOut {
                value: Amount::ONE_BTC,
                script_pubkey: ScriptBuf::new(),
            },
            // This represents the OP_RETURN sBTC UTXO for a
            // transaction with no withdrawals.
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0; 21]),
            },
        ],
    }
}

impl utxo::DepositRequest {
    /// Transform this deposit request into the body that Emily expects.
    pub fn as_emily_request(&self, tx: &Transaction) -> CreateDepositRequestBody {
        CreateDepositRequestBody {
            bitcoin_tx_output_index: self.outpoint.vout,
            bitcoin_txid: self.outpoint.txid.to_string(),
            deposit_script: self.deposit_script.to_hex_string(),
            reclaim_script: self.reclaim_script.to_hex_string(),
            transaction_hex: serialize_hex(tx),
        }
    }
}

/// Create a new BlockHash stream for messages from bitcoin core over the
/// ZMQ interface.
///
/// The returned object implements Stream + Send + Sync, which is sometimes
/// needed in our integration tests.
///
/// # Notes
///
/// This function panics if it cannot establish a connection the bitcoin
/// core in 10 seconds.
pub async fn new_zmq_block_hash_stream(endpoint: &str) -> ReceiverStream<Result<BlockHash, Error>> {
    let zmq_stream = BitcoinCoreMessageStream::new_from_endpoint(endpoint)
        .await
        .unwrap();

    let (sender, receiver) = tokio::sync::mpsc::channel(100);
    tokio::spawn(async move {
        let mut stream = zmq_stream.to_block_hash_stream();
        while let Some(block) = stream.next().await {
            sender.send(block).await.unwrap();
        }
    });

    ReceiverStream::new(receiver)
}
