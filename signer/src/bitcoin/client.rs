//! Bitcoin Core RPC client implementations

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
    type Error = Error;

    async fn get_block(&self, _block_hash: &bitcoin::BlockHash) -> Result<Option<bitcoin::Block>, Self::Error> {
        todo!()
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Self::Error> {
        todo!()
    }

    async fn get_signer_utxo(&self, _aggregate_key: &PublicKey) -> Result<Option<SignerUtxo>, Self::Error>{
        todo!()
    }

    async fn get_last_fee(&self, _utxo: bitcoin::OutPoint) -> Result<Option<utxo::Fees>, Self::Error> {
        todo!()
    }

    async fn broadcast_transaction(&self, _tx: &bitcoin::Transaction) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{bitcoin::BitcoinInteract as _, config::Settings, context::{Context as _, DefaultSignerContext}, storage::in_memory::Store};

    #[tokio::test]
    async fn estimate_fee_rate() {
        let ctx = DefaultSignerContext::init(
            Settings::new_from_default_config().unwrap(), 
            Store::new_shared()
        ).unwrap();

        let client = ctx.get_bitcoin_client();

        client.exec(|client| 
            client.estimate_fee_rate()
        ).await;

    }
}