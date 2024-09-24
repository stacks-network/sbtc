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

use bitcoincore_rpc::{jsonrpc::error::RpcError, RpcApi};
use sbtc::rpc::{BitcoinClient, BitcoinCoreClient};
use url::Url;

use crate::{error::Error, util::ApiFallbackClient};

use super::{utxo, BitcoinInteract};

/// Implement the [`TryFrom`] trait for a slice of [`Url`]s to allow for a
/// [`ApiFallbackClient`] to be implicitly created from a list of URLs.
impl TryFrom<&[Url]> for ApiFallbackClient<BitcoinCoreClient> {
    type Error = Error;
    fn try_from(urls: &[Url]) -> Result<Self, Self::Error> {
        let clients = urls
            .iter()
            .map(|url| BitcoinCoreClient::try_from(url.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(clients).map_err(Into::into)
    }
}

impl BitcoinClient for ApiFallbackClient<BitcoinCoreClient> {
    type Error = Error;

    async fn get_tx(&self, _txid: &bitcoin::Txid) -> Result<sbtc::rpc::GetTxResponse, Self::Error> {
        self.exec(|client| async { client.get_tx(_txid).map_err(Error::SbtcLib) })
            .await
    }
}

impl BitcoinInteract for ApiFallbackClient<BitcoinCoreClient> {
    async fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        self.exec(|client| async {
            match client.inner_client().get_block(block_hash) {
                Ok(block) => Ok(Some(block)),
                Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(
                    RpcError { code: -5, .. },
                ))) => Ok(None),
                Err(error) => Err(Error::BitcoinCoreRpc(error)),
            }
        })
        .await
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        todo!() // TODO(542)
    }

    async fn get_last_fee(&self, _utxo: bitcoin::OutPoint) -> Result<Option<utxo::Fees>, Error> {
        todo!() // TODO(541)
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.exec(|client| async {
            client
                .inner_client()
                .send_raw_transaction(tx)
                .map_err(Error::BitcoinCoreRpc)
                .map(|_| ())
        })
        .await
    }
}
