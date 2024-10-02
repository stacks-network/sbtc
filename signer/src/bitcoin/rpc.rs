//! Contains client wrappers for bitcoin core and electrum.

use std::sync::Arc;

use bitcoin::Amount;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Denomination;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoin::Wtxid;
use bitcoincore_rpc::json::EstimateMode;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::GetRawTransactionResultVin;
use bitcoincore_rpc_json::GetRawTransactionResultVout as BitcoinTxInfoVout;
use bitcoincore_rpc_json::GetRawTransactionResultVoutScriptPubKey as BitcoinTxInfoScriptPubKey;
use serde::Deserialize;
use url::Url;

use crate::bitcoin::BitcoinInteract;
use crate::error::Error;

/// A slimmed down type representing a response from bitcoin-core's
/// getrawtransaction RPC.
///
/// The docs for the getrawtransaction RPC call can be found here:
/// <https://bitcoincore.org/en/doc/25.0.0/rpc/rawtransactions/getrawtransaction/>.
#[derive(Debug, Clone, Deserialize)]
pub struct GetTxResponse {
    /// The raw bitcoin transaction.
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
    #[serde(rename = "hex")]
    pub tx: Transaction,
    /// The block hash of the Bitcoin block that includes this transaction.
    #[serde(rename = "blockhash")]
    pub block_hash: Option<BlockHash>,
    /// The number of confirmations deep from that chain tip of the bitcoin
    /// block that includes this transaction.
    ///
    /// TODO(384): In the case of a reorg, it's not entirely clear what
    /// happens here. We need to make sure that the "reasonable thing"
    /// happens.
    pub confirmations: Option<u32>,
    /// The Unix epoch time when the block was mined. It reflects the
    /// timestamp as recorded by the miner of the block.
    #[serde(rename = "blocktime")]
    pub block_time: Option<u64>,
}

/// A struct containing the response from bitcoin-core for a
/// `getrawtransaction` RPC where verbose is set to 2 where the block hash
/// is supplied as an RPC argument.
///
/// # Notes
///
/// * This struct is a slightly modified version of the
///   [`GetRawTransactionResult`](bitcoincore_rpc_json::GetRawTransactionResult)
///   type, which is what the bitcoincore-rpc crate returns for the
///   `getrawtransaction` RPC with verbosity set to 1. That type is missing
///   some information that we may want.
/// * The `block_hash`, `block_time`, `confirmations`, `fee`, and
///   `is_active_chain` fields are always populated from bitcoin-core for a
///   `getrawtransaction` RPC with verbosity 2 when the `block_hash` is
///   supplied. That is why they are not `Option`s here.
/// * This struct omits some fields returned from bitcoin-core, most
///   notably the `vin.prevout.script_pub_key.desc` field.
/// * Since we require bitcoin-core v25 or later these docs were taken from
///   <https://bitcoincore.org/en/doc/25.0.0/rpc/rawtransactions/getrawtransaction/>
///   and not from the more generic bitcoin.org docs
///   <https://developer.bitcoin.org/reference/rpc/getrawtransaction.html>
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize, serde::Serialize)]
pub struct BitcoinTxInfo {
    /// Whether the specified block (in the getrawtransaction RPC) is in
    /// the active chain or not. It is only present when the "blockhash"
    /// argument is present in the RPC.
    pub in_active_chain: bool,
    /// The transaction fee paid to the bitcoin miners.
    ///
    /// This field is returned whenever the "block undo data" is present
    /// for a block. The block undo data is always present for validated
    /// blocks, and block validation is always done for blocks on the
    /// currently active chain [1-4]. So if this field is missing then this
    /// block has not been validated and so is not on the active
    /// blockchain.
    ///
    /// [1]: <https://bitcoincore.reviews/23319#l-133>
    /// [2]: <https://bitcoincore.reviews/23319#l-141>
    /// [3]: <https://bitcoincore.reviews/23319#l-147>
    /// [4]: <https://bitcoincore.reviews/23319#l-153>
    #[serde(default, with = "bitcoin::amount::serde::as_btc")]
    pub fee: Amount,
    /// The raw bitcoin transaction.
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
    #[serde(rename = "hex")]
    pub tx: Transaction,
    /// The transaction id (the same value provided in the RPC).
    pub txid: Txid,
    /// The transaction hash (differs from txid for witness transactions).
    pub hash: Wtxid,
    /// The serialized transaction size.
    pub size: u64,
    /// The virtual transaction size (differs from size for witness
    /// transactions).
    pub vsize: u64,
    /// The inputs into the transaction.
    pub vin: Vec<BitcoinTxInfoVin>,
    /// A description of the transactions outputs. This object is missing
    /// the `desc` field in the `scriptPubKey` object. That field is the
    /// "Inferred descriptor for the output".
    pub vout: Vec<BitcoinTxInfoVout>,
    /// The block hash of the Bitcoin block that includes this transaction.
    #[serde(rename = "blockhash")]
    pub block_hash: BlockHash,
    /// The number of confirmations deep from that chain tip of the bitcoin
    /// block that includes this transaction.
    pub confirmations: u32,
    /// The Unix epoch time when the block was mined. It reflects the
    /// timestamp as recorded by the miner of the block.
    #[serde(rename = "blocktime")]
    pub block_time: u64,
}

/// A description of an input into a transaction.
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize, serde::Serialize)]
pub struct BitcoinTxInfoVin {
    /// Most of the details to the input into the transaction
    #[serde(flatten)]
    pub details: GetRawTransactionResultVin,
    /// The previous output.
    ///
    /// This field is omitted if block undo data is not available, so it is
    /// missing whenever the `fee` field is missing in the
    /// [`BitcoinTxInfo`].
    pub prevout: BitcoinTxInfoVinPrevout,
}

/// The previous output, omitted if block undo data is not available.
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize, serde::Serialize)]
pub struct BitcoinTxInfoVinPrevout {
    /// Whether this is a Coinbase or not.
    pub generated: bool,
    /// The height of the prevout.
    pub height: u64,
    /// The value of the prevout in BTC.
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub value: Amount,
    /// The scriptPubKey of the prevout.
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BitcoinTxInfoScriptPubKey,
}

/// A struct representing the recommended fee, in sats per vbyte, from a
/// particular source.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeeEstimate {
    /// Satoshis per vbyte
    pub sats_per_vbyte: f64,
}

/// A client for interacting with bitcoin-core
#[derive(Debug, Clone)]
pub struct BitcoinCoreClient {
    /// The underlying bitcoin-core client
    inner: Arc<bitcoincore_rpc::Client>,
}

/// Implement TryFrom for Url to allow for easy conversion from a URL to a
/// BitcoinCoreClient.
impl TryFrom<&Url> for BitcoinCoreClient {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        let username = url.username().to_string();
        let password = url.password().unwrap_or_default().to_string();
        let host = url
            .host_str()
            .ok_or(Error::InvalidUrl(url::ParseError::EmptyHost))?;
        let port = url.port().ok_or(Error::PortRequired)?;

        let endpoint = format!("{}://{host}:{port}", url.scheme());

        Self::new(&endpoint, username, password)
    }
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
            .map(Arc::new)
            .map_err(|err| Error::BitcoinCoreRpcClient(err, url.to_string()))?;

        Ok(Self { inner: client })
    }

    /// Return a reference to the inner bitcoin-core RPC client.
    pub fn inner_client(&self) -> &bitcoincore_rpc::Client {
        &self.inner
    }

    /// Fetch the block identified by the given block hash.
    pub fn get_block(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        match self.inner.get_block(block_hash) {
            Ok(block) => Ok(Some(block)),
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -5, .. }))) => Ok(None),
            Err(error) => Err(Error::BitcoinCoreGetBlock(error, *block_hash)),
        }
    }

    /// Fetch and decode raw transaction from bitcoin-core using the
    /// getrawtransaction RPC with a verbosity of 1. None is returned if
    /// the node cannot find the transaction in a bitcoin block or the
    /// mempool.
    ///
    /// # Notes
    ///
    /// By default, this call only returns a transaction if it is in the
    /// mempool. If -txindex is enabled on bitcoin-core and no blockhash
    /// argument is passed, it will return the transaction if it is in the
    /// mempool or any block. We require -txindex to be enabled (same with
    /// stacks-core[^1]) so this should work with transactions in either
    /// the mempool and a bitcoin block.
    ///
    /// [^1]: <https://docs.stacks.co/guides-and-tutorials/run-a-miner/mine-mainnet-stacks-tokens>
    pub fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error> {
        let args = [
            serde_json::to_value(txid).map_err(Error::JsonSerialize)?,
            // This is the verbosity level. The acceptable values are 0, 1,
            // and 2, and we want the 1 for some additional information
            // over just the raw transaction.
            serde_json::Value::Number(serde_json::value::Number::from(1u32)),
            serde_json::Value::Null,
        ];

        match self.inner.call::<GetTxResponse>("getrawtransaction", &args) {
            Ok(tx_info) => Ok(Some(tx_info)),
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -5, .. }))) => Ok(None),
            Err(err) => Err(Error::BitcoinCoreGetTransaction(err, *txid)),
        }
    }

    /// Fetch and decode raw transaction from bitcoin-core using the
    /// `getrawtransaction` RPC with a verbosity of 2.
    ///
    /// # Notes
    ///
    /// We require bitcoin-core v25 or later. For bitcoin-core v24 and
    /// earlier, this function will return an error.
    pub fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error> {
        let args = [
            serde_json::to_value(txid).map_err(Error::JsonSerialize)?,
            // This is the verbosity level. The acceptable values are 0, 1,
            // and 2, and we want the 2 because it will include all the
            // required fields of the type.
            serde_json::Value::Number(serde_json::value::Number::from(2u32)),
            serde_json::to_value(block_hash).map_err(Error::JsonSerialize)?,
        ];

        match self.inner.call::<BitcoinTxInfo>("getrawtransaction", &args) {
            Ok(tx_info) => Ok(Some(tx_info)),
            // If the `block_hash` is not found then the message is "Block
            // hash not found", while if the transaction is not found in an
            // actual block then the message is "No such transaction found
            // in the provided block. Use `gettransaction` for wallet
            // transactions." In both cases the code is the same.
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -5, .. }))) => Ok(None),
            Err(err) => Err(Error::BitcoinCoreGetTransaction(err, *txid)),
        }
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

impl BitcoinInteract for BitcoinCoreClient {
    async fn broadcast_transaction(&self, _: &Transaction) -> Result<(), Error> {
        unimplemented!()
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        self.get_block(block_hash)
    }

    async fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error> {
        self.get_tx(txid)
    }

    async fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error> {
        self.get_tx_info(txid, block_hash)
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        todo!()
    }

    async fn get_last_fee(&self, _: OutPoint) -> Result<Option<super::utxo::Fees>, Error> {
        todo!()
    }
}
