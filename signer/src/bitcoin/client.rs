//! Bitcoin Core RPC client implementations

use bitcoincore_rpc::RpcApi;
use sbtc::rpc::BitcoinCoreClient;
use url::Url;

use crate::{error::Error, keys::PublicKey, util::TryFromUrl};

use super::{utxo::{self, SignerUtxo}, BitcoinInteract};

impl TryFromUrl for BitcoinCoreClient {
    fn try_from_url(uri: &Url) -> Result<Self, Error> {
        let username = uri.username().to_string();
        let password = uri.password().unwrap_or_default().to_string();
        let host = uri.host_str().unwrap();
        let port = uri.port().unwrap_or(8332);

        let endpoint = format!("http://{}:{}", host, port);

        BitcoinCoreClient::new(&endpoint, username, password)
            .map_err(|e| Error::BitcoinCoreClient(e.to_string()))
    }
}

impl BitcoinInteract for BitcoinCoreClient {

    async fn get_block(&self, _block_hash: &bitcoin::BlockHash) -> Result<Option<bitcoin::Block>, Error> {
        todo!()
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        self.estimate_fee_rate(1)
            .map(|rate| rate.sats_per_vbyte)
            .map_err(|e| Error::BitcoinCoreClient(e.to_string()))
    }

    async fn get_signer_utxo(&self, _aggregate_key: &PublicKey) -> Result<Option<SignerUtxo>, Error>{
        todo!()
    }

    async fn get_last_fee(&self, _utxo: bitcoin::OutPoint) -> Result<Option<utxo::Fees>, Error> {
        todo!()
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.inner_client().send_raw_transaction(tx)
            .map_err(|e| Error::BitcoinCoreClient(e.to_string()))
            .map(|_| ())
    }
}