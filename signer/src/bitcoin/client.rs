//! Bitcoin Core RPC client implementations

use bitcoincore_rpc::RpcApi;
use sbtc::rpc::{BitcoinClient, BitcoinCoreClient};
use url::Url;

use crate::{error::Error, keys::PublicKey, util::ApiFallbackClient};

use super::{
    utxo::{self, SignerUtxo},
    BitcoinInteract,
};

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
                // TODO: Double check what the error is from bitcoin-core when no block is found
                Err(bitcoincore_rpc::Error::JsonRpc(_)) => Ok(None),
                Err(error) => Err(Error::BitcoinCoreRpc(error)),
            }
        })
        .await
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        self.exec(|client| async {
            client
                .estimate_fee_rate(1)
                .map(|rate| rate.sats_per_vbyte)
                .map_err(Error::SbtcLib)
        })
        .await
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
