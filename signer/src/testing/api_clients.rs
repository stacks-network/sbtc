//! Testing helpers for api clients

use url::Url;

use crate::bitcoin::rpc::BitcoinTxInfo;
use crate::bitcoin::rpc::GetTxResponse;
use crate::bitcoin::BitcoinInteract;
use crate::bitcoin::MockBitcoinInteract;
use crate::blocklist_client::BlocklistChecker;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::stacks::api::StacksInteract;

/// A no-op API client that doesn't do anything. It will panic if you
/// attempt to use it, but can be useful for fillers in testing.
#[derive(Clone)]
pub struct NoopApiClient;

impl TryFrom<&[Url]> for NoopApiClient {
    type Error = Error;
    fn try_from(_value: &[Url]) -> Result<Self, Self::Error> {
        Ok(NoopApiClient)
    }
}

/// Noop implementation of the BitcoinInteract trait.
impl BitcoinInteract for NoopApiClient {
    async fn get_tx(&self, _: &bitcoin::Txid) -> Result<Option<GetTxResponse>, Error> {
        unimplemented!()
    }

    async fn get_tx_info(
        &self,
        _: &bitcoin::Txid,
        _: &bitcoin::BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error> {
        unimplemented!()
    }

    async fn get_block(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        unimplemented!()
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
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

/// Noop implementation of the StacksInteract trait.
impl StacksInteract for NoopApiClient {
    async fn get_current_signer_set(
        &self,
        _contract_principal: &clarity::types::chainstate::StacksAddress,
    ) -> Result<Vec<crate::keys::PublicKey>, Error> {
        unimplemented!()
    }

    async fn get_account(
        &self,
        _address: &clarity::types::chainstate::StacksAddress,
    ) -> Result<crate::stacks::api::AccountInfo, Error> {
        unimplemented!()
    }

    async fn submit_tx(
        &self,
        _tx: &blockstack_lib::chainstate::stacks::StacksTransaction,
    ) -> Result<crate::stacks::api::SubmitTxResponse, Error> {
        unimplemented!()
    }

    async fn get_block(
        &self,
        _block_id: clarity::types::chainstate::StacksBlockId,
    ) -> Result<blockstack_lib::chainstate::nakamoto::NakamotoBlock, Error> {
        unimplemented!()
    }

    async fn get_tenure(
        &self,
        _block_id: clarity::types::chainstate::StacksBlockId,
    ) -> Result<Vec<blockstack_lib::chainstate::nakamoto::NakamotoBlock>, Error> {
        unimplemented!()
    }

    async fn get_tenure_info(
        &self,
    ) -> Result<blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo, Error> {
        unimplemented!()
    }

    async fn estimate_fees<T>(
        &self,
        _payload: &T,
        _priority: crate::stacks::api::FeePriority,
    ) -> Result<u64, Error>
    where
        T: crate::stacks::contracts::AsTxPayload + Send + Sync,
    {
        unimplemented!()
    }

    fn nakamoto_start_height(&self) -> u64 {
        unimplemented!()
    }
}

/// Noop implementation of the EmilyInteract trait.
impl EmilyInteract for NoopApiClient {
    async fn get_deposits(&self) -> Result<Vec<sbtc::deposits::CreateDepositRequest>, Error> {
        todo!()
    }
}

/// Noop implementation of the BlocklistChecker trait.
impl BlocklistChecker for NoopApiClient {
    async fn can_accept(
        &self,
        _address: &str,
    ) -> Result<bool, blocklist_api::apis::Error<blocklist_api::apis::address_api::CheckAddressError>>
    {
        todo!()
    }
}

impl TryFrom<&[Url]> for MockBitcoinInteract {
    type Error = Error;

    fn try_from(_: &[Url]) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}
