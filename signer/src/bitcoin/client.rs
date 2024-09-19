//! Bitcoin Core RPC client implementations

use bitcoincore_rpc::RpcApi;
use sbtc::rpc::BitcoinCoreClient;
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
            .map(|url| BitcoinCoreClient::try_from(url.clone()).unwrap())
            .collect::<Vec<_>>();

        Ok(Self::new(clients))
    }
}

impl BitcoinInteract for BitcoinCoreClient {
    async fn get_block(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        todo!()
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        self.estimate_fee_rate(1)
            .map(|rate| rate.sats_per_vbyte)
            .map_err(Error::SbtcLib)
    }

    async fn get_signer_utxo(
        &self,
        _aggregate_key: &PublicKey,
    ) -> Result<Option<SignerUtxo>, Error> {
        todo!()
    }

    async fn get_last_fee(&self, _utxo: bitcoin::OutPoint) -> Result<Option<utxo::Fees>, Error> {
        todo!()
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.inner_client()
            .send_raw_transaction(tx)
            .map_err(|e| Error::BitcoinCoreClient(e.to_string()))
            .map(|_| ())
    }
}
