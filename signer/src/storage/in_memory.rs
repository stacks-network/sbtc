//! In-memory store implementation - useful for tests

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::types::chainstate::StacksBlockId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::storage::model;

/// A store wrapped in an Arc<Mutex<...>> for interior mutability
pub type SharedStore = Arc<Mutex<Store>>;

type DepositRequestPk = (model::BitcoinTxId, usize);

/// In-memory store
#[derive(Debug, Default)]
pub struct Store {
    /// Bitcoin blocks
    pub bitcoin_blocks: HashMap<model::BitcoinBlockHash, model::BitcoinBlock>,

    /// Deposit requests
    pub deposit_requests: HashMap<DepositRequestPk, model::DepositRequest>,

    /// Deposit signers
    pub deposit_signers: HashMap<DepositRequestPk, Vec<model::DepositSigner>>,

    /// The blocks which contain deposit requests
    pub deposit_request_blocks: HashMap<model::BitcoinBlockHash, Vec<DepositRequestPk>>,

    /// Bitcoin blocks to transactions
    pub bitcoin_block_to_transactions: HashMap<model::BitcoinBlockHash, Vec<model::BitcoinTxId>>,

    /// Bitcoin transactions to blocks
    pub bitcoin_transactions_to_blocks: HashMap<model::BitcoinTxId, Vec<model::BitcoinBlockHash>>,

    /// Stacks blocks under nakamoto
    pub stacks_blocks: HashMap<StacksBlockId, NakamotoBlock>,
}

impl Store {
    /// Create an empty store
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store wrapped in an Arc<Mutex<...>>
    pub fn new_shared() -> SharedStore {
        Arc::new(Mutex::new(Self::new()))
    }
}

impl super::DbRead for SharedStore {
    type Error = std::convert::Infallible;

    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        Ok(self.lock().await.bitcoin_blocks.get(block_hash).cloned())
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Self::Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_blocks
            .values()
            .max_by_key(|block| (block.block_height, block.block_hash.clone()))
            .map(|block| block.block_hash.clone()))
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let maps = self.lock().await;

        Ok((0..context_window)
            // Find all tracked transaction IDs in the context window
            .scan(chain_tip, |block_hash, _| {
                let transaction_ids = maps
                    .bitcoin_block_to_transactions
                    .get(*block_hash)
                    .cloned()
                    .unwrap_or_else(Vec::new);

                let block = maps.bitcoin_blocks.get(*block_hash)?;
                *block_hash = &block.parent_hash;

                Some(transaction_ids)
            })
            .flatten()
            // Return all deposit requests associated with any of these transaction IDs
            .flat_map(|txid| {
                maps.deposit_requests
                    .values()
                    .filter(move |req| req.txid == txid)
                    .cloned()
            })
            .collect())
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: usize,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        Ok(self
            .lock()
            .await
            .deposit_signers
            .get(&(txid.clone(), output_index))
            .cloned()
            .unwrap_or_else(Vec::new))
    }

    async fn get_pending_withdraw_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: usize,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        Ok(Vec::new()) // TODO(245): Implement
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Self::Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_transactions_to_blocks
            .get(txid)
            .cloned()
            .unwrap_or_else(Vec::new))
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Self::Error> {
        Ok(self.lock().await.stacks_blocks.contains_key(&block_id))
    }
}

impl super::DbWrite for SharedStore {
    type Error = std::convert::Infallible;

    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        self.lock()
            .await
            .bitcoin_blocks
            .insert(block.block_hash.clone(), block.clone());

        Ok(())
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Self::Error> {
        self.lock().await.deposit_requests.insert(
            (deposit_request.txid.clone(), deposit_request.output_index),
            deposit_request.clone(),
        );

        Ok(())
    }

    async fn write_withdraw_request(
        &self,
        _withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(245): Implement
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .deposit_signers
            .entry((decision.txid.clone(), decision.output_index))
            .or_default()
            .push(decision.clone());

        Ok(())
    }

    async fn write_withdraw_signer_decision(
        &self,
        _decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(245): Implement
    }

    async fn write_transaction(
        &self,
        _transaction: &model::Transaction,
    ) -> Result<(), Self::Error> {
        // Currently not needed in-memory since it's not required by any queries
        Ok(())
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> Result<(), Self::Error> {
        let mut maps = self.lock().await;

        maps.bitcoin_block_to_transactions
            .entry(bitcoin_transaction.block_hash.clone())
            .or_default()
            .push(bitcoin_transaction.txid.clone());

        maps.bitcoin_transactions_to_blocks
            .entry(bitcoin_transaction.txid.clone())
            .or_default()
            .push(bitcoin_transaction.block_hash.clone());

        Ok(())
    }

    async fn write_stacks_blocks(&self, blocks: &[NakamotoBlock]) -> Result<(), Self::Error> {
        let mut maps = self.lock().await;
        blocks.iter().for_each(|block| {
            maps.stacks_blocks.insert(block.block_id(), block.clone());
        });

        Ok(())
    }
}
