//! Contains client wrappers for bitcoin core and electrum.

use std::num::NonZeroU8;

use bitcoin::consensus;
use bitcoin::consensus::Decodable as _;
use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::RpcApi;
use electrum_client::ElectrumApi as _;
use electrum_client::Param;
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
    /// The transaction ID.
    pub txid: Txid,
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

/// Trait for interacting with bitcoin-core
pub trait BitcoinRpcClient {
    /// Return the transaction if the transaction is in the mempool or in
    /// any block.
    fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error>;
}

/// A client for interacting with bitcoin-core
pub struct BtcClient {
    /// The underlying bitcoin-core client
    inner: bitcoincore_rpc::Client,
}

impl BtcClient {
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
            txid: response.txid,
            block_hash: response.blockhash,
            confirmations: response.confirmations,
            block_time: response.blocktime.map(|time| time as u64),
            in_active_chain: response.in_active_chain,
        })
    }
}

impl BitcoinRpcClient for BtcClient {
    fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        self.get_tx(txid)
    }
}

/// A client for interacting with Electrum server
pub struct ElectrumClient {
    /// The underlying electrum client
    inner: electrum_client::Client,
}

impl ElectrumClient {
    /// Establish a connection to the electrum server and return a client.
    ///
    /// # Notes
    ///
    /// * Attempts to establish a connection with the server using the
    ///   given URL.
    /// * The URL must be prefixed with either tcp:// or ssl://.
    /// * The electrum-client authors use an u8 for the timeout instead
    ///   Duration, so we mirror that here. A timeout of zero will error so
    ///   disallow it. A timeout of None means no timeout.
    pub fn new(url: &str, timeout: Option<NonZeroU8>) -> Result<Self, Error> {
        // The config builder will panic if the timeout is set to zero, so
        // we set it to None, which means no timeout. Kind of surprising
        // but this is what is usually meant by a timeout of zero anyway.
        let config = electrum_client::Config::builder()
            .timeout(timeout.map(NonZeroU8::get))
            .retry(2)
            .validate_domain(true)
            .build();
        // This actually attempts to establish a connection with the server
        // and returns and Error otherwise.
        let client = electrum_client::Client::from_config(url, config)
            .map_err(|err| Error::ElectrumClientBuild(err, url.to_string()))?;

        Ok(Self { inner: client })
    }
    /// Fetch and decode raw transaction from the electrum server.
    ///
    /// # Notes
    ///
    /// This function uses the `blockchain.transaction.get` Electrum
    /// protocol method for the response. That method uses bitcoin-core's
    /// getrawtransaction RPC under the hood, but supplies the correct
    /// block hash fetched from Electrum server's index. The benefit of
    /// using electrum for this is that you do not need to set -txindex = 1
    /// in bitcoin-core, and electrum is (presumably) much more efficient.
    pub fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        let params = [Param::String(txid.to_string()), Param::Bool(true)];
        let value = self
            .inner
            .raw_call("blockchain.transaction.get", params)
            .map_err(|err| Error::GetTransactionElectrum(err, *txid))?;

        serde_json::from_value::<GetTxResponse>(value)
            .inspect(|response| debug_assert_eq!(txid, &response.txid))
            .map_err(|err| Error::DeserializeGetTransaction(err, *txid))
    }
}

impl BitcoinRpcClient for ElectrumClient {
    fn get_tx(&self, txid: &Txid) -> Result<GetTxResponse, Error> {
        self.get_tx(txid)
    }
}
