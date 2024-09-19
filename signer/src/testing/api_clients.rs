//! Testing helpers for api clients

use std::cell::LazyCell;

use sbtc::rpc::BitcoinClient;

use crate::{bitcoin::BitcoinInteract, error::Error, util::ApiFallbackClient};

/// A no-op API client that implements the BitcoinClient trait. It will panic
/// if you attempt to use it, but can be useful for fillers in testing.
pub const NOOP_API_CLIENT: LazyCell<ApiFallbackClient<NoopApiClient>> =
    LazyCell::new(|| ApiFallbackClient::new(vec![NoopApiClient]));

/// A no-op API client that doesn't do anything. It will panic if you
/// attempt to use it, but can be useful for fillers in testing.
#[derive(Clone)]
pub struct NoopApiClient;

impl BitcoinClient for NoopApiClient {
    type Error = Error;

    fn get_tx(&self, _txid: &bitcoin::Txid) -> Result<sbtc::rpc::GetTxResponse, Self::Error> {
        unimplemented!()
    }
}

impl BitcoinInteract for NoopApiClient {
    async fn get_block(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        unimplemented!()
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        unimplemented!()
    }

    async fn get_signer_utxo(
        &self,
        _aggregate_key: &crate::keys::PublicKey,
    ) -> Result<Option<crate::bitcoin::utxo::SignerUtxo>, Error> {
        unimplemented!()
    }

    async fn get_last_fee(
        &self,
        _utxo: bitcoin::OutPoint,
    ) -> Result<Option<crate::bitcoin::utxo::Fees>, Error> {
        unimplemented!()
    }

    async fn broadcast_transaction(&self, _tx: &bitcoin::Transaction) -> Result<(), Error> {
        unimplemented!()
    }
}
