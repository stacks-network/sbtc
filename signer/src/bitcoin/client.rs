//! Bitcoin Core RPC client implementations
//!
//! Here's some info about the Bitcoin Core RPC client errors:
//!
//! - Example when the node is not running/unreachable:
//!   JsonRpc(Transport(SocketError(Os { code: 111, kind: ConnectionRefused, message: "Connection refused" })))
//!
//! - Example when authentication fails:
//!   JsonRpc(Transport(HttpErrorCode(401)))
//!
//! - Example when trying to estimate fees but the node doesn't have enough data:
//!   EstimateSmartFeeResponse(Some(["Insufficient data or no feerate found"]), 1)
//!
//! - Example when trying to get a block that doesn't exist:
//!   JsonRpc(Rpc(RpcError { code: -5, message: "Block not found", data: None }))

use bitcoin::BlockHash;
use bitcoin::Txid;
use bitcoincore_rpc::RpcApi as _;
use url::Url;

use crate::bitcoin::utxo;
use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::BitcoinInteract;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::util::ApiFallbackClient;

use super::rpc::BitcoinCoreClient;
use super::rpc::BitcoinTxInfo;
use super::rpc::GetTxResponse;

/// Implement the [`TryFrom`] trait for a slice of [`Url`]s to allow for a
/// [`ApiFallbackClient`] to be implicitly created from a list of URLs.
impl TryFrom<&[Url]> for ApiFallbackClient<BitcoinCoreClient> {
    type Error = Error;
    fn try_from(urls: &[Url]) -> Result<Self, Self::Error> {
        let clients = urls
            .iter()
            .map(BitcoinCoreClient::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(clients).map_err(Into::into)
    }
}

impl BitcoinInteract for ApiFallbackClient<BitcoinCoreClient> {
    async fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        self.exec(|client, _| async { client.get_block(block_hash) })
            .await
    }

    fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error> {
        self.get_client().get_tx(txid)
    }

    fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error> {
        self.get_client().get_tx_info(txid, block_hash)
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        todo!() // TODO(542)
    }

    async fn get_signer_utxo(
        &self,
        _aggregate_key: &PublicKey,
    ) -> Result<Option<SignerUtxo>, Error> {
        todo!() // TODO(538)
    }

    async fn get_last_fee(&self, _utxo: bitcoin::OutPoint) -> Result<Option<utxo::Fees>, Error> {
        todo!() // TODO(541)
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.exec(|client, _| async {
            client
                .inner_client()
                .send_raw_transaction(tx)
                .map_err(Error::BitcoinCoreRpc)
                .map(|_| ())
        })
        .await
    }
}
