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

use std::future::Future;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::types::chainstate::StacksBlockId;

/// Represents the ability to read data from the signer storage.
pub trait DbRead {
    /// Read error.
    type Error: std::error::Error;

    /// Get the bitcoin block with the given block hash.
    fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> impl Future<Output = Result<Option<model::BitcoinBlock>, Self::Error>> + Send;

    /// Get the stacks block with the given block hash.
    fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> impl Future<Output = Result<Option<model::StacksBlock>, Self::Error>> + Send;

    /// Get the bitcoin canonical chain tip
    fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> impl Future<Output = Result<Option<model::BitcoinBlockHash>, Self::Error>> + Send;

    /// Get pending deposit requests
    fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
    ) -> impl Future<Output = Result<Vec<model::DepositRequest>, Self::Error>> + Send;

    /// Get signer decisions for a deposit request
    fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: i32,
    ) -> impl Future<Output = Result<Vec<model::DepositSigner>, Self::Error>> + Send;

    /// Get signer decisions for a withdraw request
    fn get_withdraw_signers(
        &self,
        request_id: i32,
        block_hash: &model::StacksBlockHash,
    ) -> impl Future<Output = Result<Vec<model::WithdrawSigner>, Self::Error>> + Send;

    /// Get pending withdraw requests
    fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        stacks_context_window: usize,
    ) -> impl Future<Output = Result<Vec<model::WithdrawRequest>, Self::Error>> + Send;

    /// Get bitcoin blocks that include a particular transaction
    fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> impl Future<Output = Result<Vec<model::BitcoinBlockHash>, Self::Error>> + Send;

    /// Returns whether the given block ID is stored.
    fn stacks_block_exists(
        &self,
        block_id: StacksBlockId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

/// Represents the ability to write data to the signer storage.
pub trait DbWrite {
    /// Write error.
    type Error: std::error::Error;

    /// Write a bitcoin block.
    fn write_bitcoin_block(
        &self,
        block: &model::BitcoinBlock,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a stacks block.
    fn write_stacks_block(
        &self,
        block: &model::StacksBlock,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a deposit request.
    fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a withdrawal request.
    fn write_withdraw_request(
        &self,
        withdraw_request: &model::WithdrawRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a signer decision for a deposit request.
    fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a signer decision for a withdrawal request.
    fn write_withdraw_signer_decision(
        &self,
        decision: &model::WithdrawSigner,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a raw transaction.
    fn write_transaction(
        &self,
        transaction: &model::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a connection between a bitcoin block and a transaction
    fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a connection between a stacks block and a transaction
    fn write_stacks_transaction(
        &self,
        stacks_transaction: &model::StacksTransaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write the stacks blocks.
    /// TODO(212): This function should use model::StacksBlock instead of an external type
    fn write_stacks_blocks(
        &self,
        blocks: &[NakamotoBlock],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
