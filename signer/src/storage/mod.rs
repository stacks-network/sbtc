//! # Signer storage
//!
//! This module contains the `Read` and `Write` traits representing
//! the interface between the signer and their internal database.
//!
//! The canonical implementation of these traits is the [`postgres::PgStore`]
//! allowing the signer to use a Postgres database to store data.

pub mod in_memory;
pub mod model;
pub mod postgres;
pub mod sqlx;
use std::sync::Arc;

use async_trait::async_trait;
use blockstack_lib::types::chainstate::StacksBlockId;

use crate::error::Error;
use crate::keys::PublicKey;
use crate::stacks::events::CompletedDepositEvent;
use crate::stacks::events::WithdrawalAcceptEvent;
use crate::stacks::events::WithdrawalCreateEvent;
use crate::stacks::events::WithdrawalRejectEvent;

/// Represents a connection to a database that can read and write data.
pub trait DbReadWrite: DbRead + DbWrite + Sync + Send {
    /// Convert the connection to a read-only connection.
    fn as_read(self: Arc<Self>) -> Arc<dyn DbRead>;
    /// Convert the connection to a write-only connection.
    fn as_write(self: Arc<Self>) -> Arc<dyn DbWrite>;
}

impl<T: DbRead + DbWrite + Sync + Send + Sized + 'static> DbReadWrite for T {
    fn as_read(self: Arc<Self>) -> Arc<dyn DbRead> {
        self as Arc<dyn DbRead>
    }
    fn as_write(self: Arc<Self>) -> Arc<dyn DbWrite> {
        self as Arc<dyn DbWrite>
    }
}

/// Represents the ability to read data from the signer storage.
#[async_trait]
pub trait DbRead: Sync + Send {
    /// Get the bitcoin block with the given block hash.
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error>;

    /// Get the stacks block with the given block hash.
    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error>;

    /// Get the bitcoin canonical chain tip.
    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error>;

    /// Get the stacks chain tip, defined as the highest stacks block
    /// confirmed by the bitcoin chain tip.
    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error>;

    /// Get pending deposit requests
    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::DepositRequest>, Error>;

    /// Get pending deposit requests that have been accepted by at least `threshold` signers and has no responses
    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error>;

    /// Get the deposit requests that the signer has accepted to sign
    async fn get_accepted_deposit_requests(
        &self,
        signer: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error>;

    /// Get signer decisions for a deposit request
    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error>;

    /// Get signer decisions for a withdraw request
    async fn get_withdraw_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawSigner>, Error>;

    /// Get pending withdraw requests
    async fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawRequest>, Error>;

    /// Get pending withdraw requests that have been accepted by at least `threshold` signers and has no responses
    async fn get_pending_accepted_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::WithdrawRequest>, Error>;

    /// Get bitcoin blocks that include a particular transaction
    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error>;

    /// Returns whether the given block ID is stored.
    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Error>;

    /// Return the applicable DKG shares for the
    /// given aggregate key
    async fn get_encrypted_dkg_shares(
        &self,
        aggregate_key: &PublicKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>;

    /// Return the latest rotate-keys transaction confirmed by the given `chain-tip`.
    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::RotateKeysTransaction>, Error>;

    /// Get the last 365 days worth of the signers' `scriptPubkey`s.
    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error>;
    /// Get all completed deposit events.
    async fn get_completed_deposit_event(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<Option<model::CompletedDepositEvent>, Error>;
}

/// Represents the ability to write data to the signer storage.
#[async_trait]
pub trait DbWrite: Sync + Send {
    /// Write a bitcoin block.
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error>;

    /// Write a stacks block.
    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error>;

    /// Write a deposit request.
    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error>;

    /// Write many deposit requests.
    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error>;

    /// Write a withdrawal request.
    async fn write_withdraw_request(
        &self,
        withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Error>;

    /// Write a signer decision for a deposit request.
    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error>;

    /// Write a signer decision for a withdrawal request.
    async fn write_withdraw_signer_decision(
        &self,
        decision: &model::WithdrawSigner,
    ) -> Result<(), Error>;

    /// Write a raw transaction.
    async fn write_transaction(&self, transaction: &model::Transaction) -> Result<(), Error>;

    /// Write a connection between a bitcoin block and a transaction
    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> Result<(), Error>;

    /// Write the bitcoin transactions to the data store.
    async fn write_bitcoin_transactions(&self, txs: Vec<model::Transaction>) -> Result<(), Error>;

    /// Write a connection between a stacks block and a transaction
    async fn write_stacks_transaction(
        &self,
        stacks_transaction: &model::StacksTransaction,
    ) -> Result<(), Error>;

    /// Write the stacks transactions to the data store.
    async fn write_stacks_transactions(&self, txs: Vec<model::Transaction>) -> Result<(), Error>;

    /// Write the stacks block ids and their parent block ids.
    async fn write_stacks_block_headers(
        &self,
        headers: Vec<model::StacksBlock>,
    ) -> Result<(), Error>;

    /// Write encrypted DKG shares
    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error>;

    /// Write rotate-keys transaction
    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::RotateKeysTransaction,
    ) -> Result<(), Error>;

    /// Write the withdrawal-reject event to the database.
    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error>;

    /// Write the withdrawal-accept event to the database.
    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error>;

    /// Write the withdrawal-create event to the database.
    async fn write_withdrawal_create_event(
        &self,
        event: &WithdrawalCreateEvent,
    ) -> Result<(), Error>;

    /// Write the completed deposit event to the database.
    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error>;
}
