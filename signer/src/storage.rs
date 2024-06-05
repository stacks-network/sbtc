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

/// Represents the ability to read data from the signer storage.
pub trait DbRead {
    /// Read error.
    type Error: std::error::Error;

    /// Get the bitcoin block with the given block hash.
    fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> impl Future<Output = Result<Option<model::BitcoinBlock>, Self::Error>> + Send;

    /// Get the bitcoin canonical chain tip
    fn get_bitcoin_canonical_chain_tip(
        self,
    ) -> impl Future<Output = Result<Option<model::BitcoinBlockHash>, Self::Error>> + Send;

    /// Get pending deposit requests
    fn get_pending_deposit_requests(
        self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> impl Future<Output = Result<Vec<model::DepositRequest>, Self::Error>> + Send;

    /// Get signer decisions for a deposit request
    fn get_deposit_signers(
        self,
        txid: &model::BitcoinTxId,
        output_index: usize,
    ) -> impl Future<Output = Result<Vec<model::DepositSigner>, Self::Error>> + Send;

    /// Get pending withdraw requests
    fn get_pending_withdraw_requests(
        self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> impl Future<Output = Result<Vec<model::WithdrawRequest>, Self::Error>> + Send;

    /// Get bitcoin blocks that include a particular transaction
    fn get_bitcoin_blocks_with_transaction(
        self,
        txid: &model::BitcoinTxId,
    ) -> impl Future<Output = Result<Vec<model::BitcoinBlockHash>, Self::Error>> + Send;
}

/// Represents the ability to write data to the signer storage.
pub trait DbWrite {
    /// Write error.
    type Error: std::error::Error;

    /// Write a bitcoin block.
    fn write_bitcoin_block(
        self,
        block: &model::BitcoinBlock,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a deposit request.
    fn write_deposit_request(
        self,
        deposit_request: &model::DepositRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a withdraw request.
    fn write_withdraw_request(
        self,
        withdraw_request: &model::WithdrawRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a signer decision for a deposit request.
    fn write_deposit_signer_decision(
        self,
        decision: &model::DepositSigner,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a signer decision for a withdraw request.
    fn write_withdraw_signer_decision(
        self,
        decision: &model::WithdrawSigner,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a raw transaction.
    fn write_transaction(
        self,
        transaction: &model::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Write a connection between a bitcoin block and a transaction
    fn write_bitcoin_transaction(
        self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<'a, T> DbRead for &'a mut T
where
    &'a T: DbRead,
    T: Send,
{
    type Error = <&'a T as DbRead>::Error;

    async fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        (&*self).get_bitcoin_block(block_hash).await
    }

    async fn get_bitcoin_canonical_chain_tip(
        self,
    ) -> Result<Option<model::BitcoinBlockHash>, Self::Error> {
        (&*self).get_bitcoin_canonical_chain_tip().await
    }

    async fn get_pending_deposit_requests(
        self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        (&*self)
            .get_pending_deposit_requests(chain_tip, context_window)
            .await
    }

    async fn get_deposit_signers(
        self,
        txid: &model::BitcoinTxId,
        output_index: usize,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        (&*self).get_deposit_signers(txid, output_index).await
    }

    async fn get_pending_withdraw_requests(
        self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        (&*self)
            .get_pending_withdraw_requests(chain_tip, context_window)
            .await
    }

    async fn get_bitcoin_blocks_with_transaction(
        self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Self::Error> {
        (&*self).get_bitcoin_blocks_with_transaction(txid).await
    }
}

impl<'a, T> DbWrite for &'a mut T
where
    &'a T: DbWrite,
    T: Send,
{
    type Error = <&'a T as DbWrite>::Error;

    async fn write_bitcoin_block(self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        (&*self).write_bitcoin_block(block).await
    }

    async fn write_deposit_request(
        self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Self::Error> {
        (&*self).write_deposit_request(deposit_request).await
    }

    async fn write_withdraw_request(
        self,
        withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        (&*self).write_withdraw_request(withdraw_request).await
    }

    async fn write_deposit_signer_decision(
        self,
        decision: &model::DepositSigner,
    ) -> Result<(), Self::Error> {
        (&*self).write_deposit_signer_decision(decision).await
    }

    async fn write_withdraw_signer_decision(
        self,
        decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        (&*self).write_withdraw_signer_decision(decision).await
    }

    async fn write_transaction(self, transaction: &model::Transaction) -> Result<(), Self::Error> {
        (&*self).write_transaction(transaction).await
    }

    async fn write_bitcoin_transaction(
        self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> Result<(), Self::Error> {
        (&*self)
            .write_bitcoin_transaction(bitcoin_transaction)
            .await
    }
}
