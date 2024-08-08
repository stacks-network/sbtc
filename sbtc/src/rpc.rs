//! Contains client wrappers for bitcoin core and electrum.

use bitcoin::consensus;
use bitcoin::consensus::Decodable as _;
use bitcoin::BlockHash;
use bitcoin::Denomination;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoincore_rpc::json::EstimateMode;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::RpcApi as _;
use serde::Deserialize;

use crate::error::Error;

/// A slimmed down type representing a response from bitcoin-core's
/// getrawtransaction RPC.
///
/// The docs for the getrawtransaction RPC call can be found here:
/// https://bitcoincore.org/en/doc/27.0.0/rpc/rawtransactions/getrawtransaction/.
#[derive(Debug, Clone, Deserialize)]
pub struct GetTxResponse {
    /// The raw bitcoin transaction.
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    #[serde(rename = "hex")]
    pub tx: Transaction,
    /// The block hash of the Bitcoin block that includes this transaction.
    #[serde(rename = "blockhash")]
    pub block_hash: Option<BlockHash>,
    /// The number of confirmations deep from that chain tip of the bitcoin
    /// block that includes this transaction.
    pub confirmations: Option<u32>,
    /// The Unix epoch time when the block was mined. It reflects the
    /// timestamp as recorded by the miner of the block.
    #[serde(rename = "blocktime")]
    pub block_time: Option<u64>,
    /// Whether the specified block (in the getrawtransaction RPC) is in
    /// the active chain or not. It is only present when the "blockhash"
    /// argument is present in the RPC.
    pub in_active_chain: Option<bool>,
}

/// A struct representing the recommended fee, in sats per vbyte, from a
/// particular source.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeeEstimate {
    /// Satoshis per vbyte
    pub sats_per_vbyte: f64,
}

/// Trait for interacting with bitcoin-core
pub trait BitcoinClient {
    /// The error type returned for RPC calls.
    type Error: std::error::Error + 'static;
    /// Return the transaction if the transaction is in the mempool or in
    /// any block.
    fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Self::Error>;
}

/// A client for interacting with bitcoin-core
pub struct BitcoinCoreClient {
    /// The underlying bitcoin-core client
    inner: bitcoincore_rpc::Client,
}

impl BitcoinCoreClient {
    /// Return a bitcoin-core RPC client. Will error if the URL is an invalid URL.
    ///
    /// # Notes
    ///
    /// This function does not attempt to establish a connection to bitcoin-core.
    pub fn new(url: &str, username: String, password: String) -> Result<Self, Error> {
        let auth = Auth::UserPass(username, password);
        let client = bitcoincore_rpc::Client::new(url, auth)
            .map_err(|err| Error::BitcoinCoreRpcClient(err, url.to_string()))?;

        Ok(Self { inner: client })
    }
    /// Fetch and decode raw transaction from bitcoin-core using the
    /// getrawtransaction RPC.
    ///
    /// # Notes
    ///
    /// By default, this call only returns a transaction if it is in the
    /// mempool. If -txindex is enabled on bitcoin-core and no blockhash
    /// argument is passed, it will return the transaction if it is in the
    /// mempool or any block.
    pub fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        let response = self
            .inner
            .get_raw_transaction_info(txid, None)
            .map_err(|err| Error::GetTransactionBitcoinCore(err, *txid))?;
        let tx = Transaction::consensus_decode(&mut response.hex.as_slice())
            .map_err(|err| Error::DecodeTx(err, *txid))?;

        debug_assert_eq!(txid, &response.txid);

        Ok(GetTxResponse {
            tx,
            block_hash: response.blockhash,
            confirmations: response.confirmations,
            block_time: response.blocktime.map(|time| time as u64),
            in_active_chain: response.in_active_chain,
        })
    }

    /// Estimates the approximate fee in sats per vbyte needed for a
    /// transaction to be confirmed within `num_blocks`.
    ///
    /// # Notes
    ///
    /// Modified from the bitcoin-core docs[1]:
    ///
    /// Bitcoin-core has two different modes for fee rate estimation,
    /// "conservative" and "economical". We use the "conservative" estimate
    /// because it is more likely to be sufficient for the desired target,
    /// but is not as responsive to short term drops in the prevailing fee
    /// market when compared to the "economical" fee rate. Also, the docs
    /// mention the response is in BTC/kB, but from the comments in
    /// bitcoin-core[2] this is really BTC/kvB (kvB is kilo-vbyte).
    ///
    /// [^1]: https://developer.bitcoin.org/reference/rpc/estimatesmartfee.html
    /// [^2]: https://github.com/bitcoin/bitcoin/blob/d367a4e36f7357c4ebd018e8e1c9c5071db2e1c2/src/rpc/fees.cpp#L90-L91
    pub fn estimate_fee_rate(&self, num_blocks: u16) -> Result<FeeEstimate, Error> {
        let estimate_mode = Some(EstimateMode::Conservative);
        let resp = self
            .inner
            .estimate_smart_fee(num_blocks, estimate_mode)
            .map_err(|err| Error::EstimateSmartFee(err, num_blocks))?;

        // In local testing resp.fee_rate is `None` whenever there haven't
        // been enough transactions to make an estimate. Also, the fee rate
        // is in BTC/kvB, so we need to convert that to sats/vb.
        let sats_per_vbyte = match resp.fee_rate {
            Some(fee_rate) => fee_rate.to_float_in(Denomination::Satoshi) / 1000.,
            None => return Err(Error::EstimateSmartFeeResponse(resp.errors, num_blocks)),
        };

        Ok(FeeEstimate { sats_per_vbyte })
    }
}

impl BitcoinClient for BitcoinCoreClient {
    type Error = Error;
    fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        self.get_tx(txid)
    }
}
