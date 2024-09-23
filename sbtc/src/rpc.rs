//! Contains client wrappers for bitcoin core and electrum.

use std::future::Future;

use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::Denomination;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoin::Weight;
use bitcoin::Wtxid;
use bitcoincore_rpc::json::EstimateMode;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::GetRawTransactionResultVin;
use bitcoincore_rpc_json::GetRawTransactionResultVout as BitcoinTxInfoVout;
use bitcoincore_rpc_json::GetRawTransactionResultVoutScriptPubKey as BitcoinTxInfoScriptPubKey;
use serde::Deserialize;
use url::Url;

use crate::error::Error;

/// A slimmed down type representing a response from bitcoin-core's
/// getrawtransaction RPC.
///
/// The docs for the getrawtransaction RPC call can be found here:
/// https://bitcoincore.org/en/doc/25.0.0/rpc/rawtransactions/getrawtransaction/.
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
    /// currently active chain [1]. So if this field is missing then this
    /// block has not been validated and so is not on the active
    /// blockchain.
    /// 
    /// [1]: https://bitcoincore.reviews/23319#l-133,
    ///     https://bitcoincore.reviews/23319#l-141,
    ///     https://bitcoincore.reviews/23319#l-147,
    ///     https://bitcoincore.reviews/23319#l-153
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

impl BitcoinTxInfo {
    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the input associated with the given `outpoint`.
    ///
    /// # Notes
    ///
    /// Each input and output is assessed a fee that is proportional to
    /// their weight amount all of the requests serviced by this
    /// transaction.
    ///
    /// This function assumes that this transaction is an sBTC transaction,
    /// which implies that the first input and the first two outputs are
    /// always the signers'. So `None` is returned if there is no input,
    /// after the first input, with the given `outpoint`.
    pub fn assess_input_fee(&self, outpoint: OutPoint) -> Option<Amount> {
        let request_weight_vbytes = self.request_weight().to_vbytes_ceil();
        // We skip the first input because that is always the signers'
        // input UTXO.
        let input_weight_vbytes = self
            .tx
            .input
            .iter()
            .find(|tx_in| tx_in.previous_output == outpoint)?
            .segwit_weight()
            .to_vbytes_ceil();

        let fee_sats = (input_weight_vbytes * self.fee.to_sat()).div_ceil(request_weight_vbytes);
        Some(Amount::from_sat(fee_sats))
    }

    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the output at the given output index `vout`.
    ///
    /// # Notes
    ///
    /// Each input and output is assessed a fee that is proportional to
    /// their weight amount all of the requests serviced by this
    /// transaction.
    ///
    /// This function assumes that this transaction is an sBTC transaction,
    /// which implies that the first input and the first two outputs are
    /// always the signers'. So `None` is returned if the given `vout` is 0
    /// or 1 or if there is no output in the transaction at `vout`.
    pub fn assess_output_fee(&self, vout: usize) -> Option<Amount> {
        // We skip the first input because that is always the signers'
        // input UTXO.
        if vout < 2 {
            return None;
        }
        let request_weight_vbytes = self.request_weight().to_vbytes_ceil();
        let input_weight_vbytes = self.tx.output.get(vout)?.weight().to_vbytes_ceil();

        let fee_sats = (input_weight_vbytes * self.fee.to_sat()).div_ceil(request_weight_vbytes);
        Some(Amount::from_sat(fee_sats))
    }

    /// Computes the total weight of the inputs and the outputs, excluding
    /// the ones related to the signers.
    fn request_weight(&self) -> Weight {
        // We skip the first input and output because those are always the
        // signers' UTXO input and output. We skip the second output
        // because that is always the OP_RETURN output for sBTC data.
        self.tx
            .input
            .iter()
            .skip(1)
            .map(|x| x.segwit_weight())
            .chain(self.tx.output.iter().skip(2).map(|x| x.weight()))
            .sum()
    }
}

/// A description of an input into a transaction.
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize, serde::Serialize)]
pub struct BitcoinTxInfoVin {
    /// Most of the details to the input into the transaction
    #[serde(flatten)]
    pub details: GetRawTransactionResultVin,
    /// The previous output, omitted if block undo data is not available.
    pub prevout: Option<BitcoinTxInfoVinPrevout>,
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

/// Trait for interacting with bitcoin-core
pub trait BitcoinClient {
    /// The error type returned for RPC calls.
    type Error: std::error::Error + Sync + Send + 'static;

    /// Return the transaction if the transaction is in the mempool or in
    /// any block.
    fn get_tx(&self, txid: &Txid) -> impl Future<Output = Result<GetTxResponse, Self::Error>>;
}

/// A client for interacting with bitcoin-core
pub struct BitcoinCoreClient {
    /// The underlying bitcoin-core client
    inner: bitcoincore_rpc::Client,
}

/// Implement TryFrom for Url to allow for easy conversion from a URL to a
/// BitcoinCoreClient.
impl TryFrom<Url> for BitcoinCoreClient {
    type Error = Error;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let username = url.username().to_string();
        let password = url.password().unwrap_or_default().to_string();
        let host = url
            .host_str()
            .ok_or(Error::InvalidUrl(url::ParseError::EmptyHost))?;
        let port = url.port().ok_or(Error::PortRequired)?;

        let endpoint = format!("http://{}:{}", host, port);

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
            .map_err(|err| Error::BitcoinCoreRpcClient(err, url.to_string()))?;

        Ok(Self { inner: client })
    }

    /// Return a reference to the inner bitcoin-core RPC client.
    pub fn inner_client(&self) -> &bitcoincore_rpc::Client {
        &self.inner
    }

    /// Fetch and decode raw transaction from bitcoin-core using the
    /// getrawtransaction RPC with a verbosity of 1.
    ///
    /// # Notes
    ///
    /// By default, this call only returns a transaction if it is in the
    /// mempool. If -txindex is enabled on bitcoin-core and no blockhash
    /// argument is passed, it will return the transaction if it is in the
    /// mempool or any block.
    pub fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        let args = [
            serde_json::to_value(txid).map_err(Error::JsonSerialize)?,
            // This is the verbosity level. The acceptable values are 0, 1,
            // and 2, and we want the 1 for some additional information
            // over just the raw transaction.
            serde_json::Value::Number(serde_json::value::Number::from(1u32)),
            serde_json::Value::Null,
        ];

        self.inner
            .call("getrawtransaction", &args)
            .map_err(|err| Error::GetTransactionBitcoinCore(err, *txid))
    }

    /// Fetch and decode raw transaction from bitcoin-core using the
    /// `getrawtransaction` RPC with a verbosity of 2.
    ///
    /// # Notes
    ///
    /// We require bitcoin-core v25 or later. For bitcoin-core v24 and
    /// earlier, this function will return an error.
    pub fn get_tx_info(&self, txid: &Txid, block_hash: &BlockHash) -> Result<BitcoinTxInfo, Error> {
        let args = [
            serde_json::to_value(txid).map_err(Error::JsonSerialize)?,
            // This is the verbosity level. The acceptable values are 0, 1,
            // and 2, and we want the 2 because it will include all of the
            // required fields of the type.
            serde_json::Value::Number(serde_json::value::Number::from(2u32)),
            serde_json::to_value(block_hash).map_err(Error::JsonSerialize)?,
        ];

        self.inner
            .call("getrawtransaction", &args)
            .map_err(|err| Error::GetTransactionBitcoinCore(err, *txid))
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
    async fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        self.get_tx(txid)
    }
}
