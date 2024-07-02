//! In-memory store implementation - useful for tests

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::StreamExt;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::storage::model;

/// A store wrapped in an Arc<Mutex<...>> for interior mutability
pub type SharedStore = Arc<Mutex<Store>>;

type DepositRequestPk = (model::BitcoinTxId, i32);
type WithdrawRequestPk = (i32, model::StacksBlockHash);

/// In-memory store
#[derive(Debug, Default)]
pub struct Store {
    /// Bitcoin blocks
    pub bitcoin_blocks: HashMap<model::BitcoinBlockHash, model::BitcoinBlock>,

    /// Stacks blocks
    pub stacks_blocks: HashMap<model::StacksBlockHash, model::StacksBlock>,

    /// Deposit requests
    pub deposit_requests: HashMap<DepositRequestPk, model::DepositRequest>,

    /// Deposit requests
    pub withdraw_requests: HashMap<WithdrawRequestPk, model::WithdrawRequest>,

    /// Deposit signers
    pub deposit_signers: HashMap<DepositRequestPk, Vec<model::DepositSigner>>,

    /// Withdraw signers
    pub withdraw_signers: HashMap<WithdrawRequestPk, Vec<model::WithdrawSigner>>,

    /// Bitcoin blocks to transactions
    pub bitcoin_block_to_transactions: HashMap<model::BitcoinBlockHash, Vec<model::BitcoinTxId>>,

    /// Bitcoin transactions to blocks
    pub bitcoin_transactions_to_blocks: HashMap<model::BitcoinTxId, Vec<model::BitcoinBlockHash>>,

    /// Stacks blocks to transactions
    pub stacks_block_to_transactions: HashMap<model::StacksBlockHash, Vec<model::StacksTxId>>,

    /// Stacks transactions to blocks
    pub stacks_transactions_to_blocks: HashMap<model::StacksTxId, Vec<model::StacksBlockHash>>,

    /// Stacks blocks to withdraw requests
    pub stacks_block_to_withdraw_requests: HashMap<model::StacksBlockHash, Vec<WithdrawRequestPk>>,

    /// Stacks blocks under nakamoto
    pub stacks_nakamoto_blocks: HashMap<StacksBlockId, NakamotoBlock>,
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

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Self::Error> {
        Ok(self.lock().await.stacks_blocks.get(block_hash).cloned())
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
        context_window: i32,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let store = self.lock().await;

        Ok((0..context_window)
            // Find all tracked transaction IDs in the context window
            .scan(chain_tip, |block_hash, _| {
                let transaction_ids = store
                    .bitcoin_block_to_transactions
                    .get(*block_hash)
                    .cloned()
                    .unwrap_or_else(Vec::new);

                let block = store.bitcoin_blocks.get(*block_hash)?;
                *block_hash = &block.parent_hash;

                Some(transaction_ids)
            })
            .flatten()
            // Return all deposit requests associated with any of these transaction IDs
            .flat_map(|txid| {
                store
                    .deposit_requests
                    .values()
                    .filter(move |req| req.txid == txid)
                    .cloned()
            })
            .collect())
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: i32,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        Ok(self
            .lock()
            .await
            .deposit_signers
            .get(&(txid.clone(), output_index))
            .cloned()
            .unwrap_or_default())
    }

    async fn get_withdraw_signers(
        &self,
        request_id: i32,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawSigner>, Self::Error> {
        Ok(self
            .lock()
            .await
            .withdraw_signers
            .get(&(request_id, block_hash.clone()))
            .cloned()
            .unwrap_or_default())
    }

    async fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: usize,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let Some(bitcoin_chain_tip) = self.get_bitcoin_block(chain_tip).await? else {
            return Ok(Vec::new());
        };

        let context_window_end_block = futures::stream::try_unfold(
            bitcoin_chain_tip.block_hash.clone(),
            |block_hash| async move {
                self.get_bitcoin_block(&block_hash)
                    .await
                    .map(|opt| opt.map(|block| (block.clone(), block.parent_hash)))
            },
        )
        .skip(context_window + 1)
        .boxed()
        .try_next()
        .await?
        .unwrap_or_else(|| bitcoin_chain_tip.clone());

        let stacks_blocks: Vec<_> = futures::stream::iter(bitcoin_chain_tip.confirms)
            .then(
                |stacks_block_hash| async move { self.get_stacks_block(&stacks_block_hash).await },
            )
            .try_collect()
            .await?;

        let Some(highest_stacks_block) = stacks_blocks
            .into_iter()
            .flatten()
            .max_by_key(|block| (block.block_height, block.block_hash.clone()))
        else {
            return Ok(Vec::new());
        };

        let store = self.lock().await;

        Ok(
            std::iter::successors(Some(&highest_stacks_block), |stacks_block| {
                store.stacks_blocks.get(&stacks_block.parent_hash)
            })
            .take_while(|stacks_block| {
                !context_window_end_block
                    .confirms
                    .contains(&stacks_block.block_hash)
            })
            .flat_map(|stacks_block| {
                store
                    .stacks_block_to_withdraw_requests
                    .get(&stacks_block.block_hash)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|pk| {
                        store
                            .withdraw_requests
                            .get(&pk)
                            .expect("missing withdraw request")
                            .clone()
                    })
            })
            .collect(),
        )
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
        Ok(self
            .lock()
            .await
            .stacks_nakamoto_blocks
            .contains_key(&block_id))
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

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Self::Error> {
        self.lock()
            .await
            .stacks_blocks
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
        withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        let mut store = self.lock().await;

        let pk = (
            withdraw_request.request_id,
            withdraw_request.block_hash.clone(),
        );

        store
            .stacks_block_to_withdraw_requests
            .entry(pk.1.clone())
            .or_default()
            .push(pk.clone());

        store.withdraw_requests.insert(pk, withdraw_request.clone());

        Ok(())
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
        decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .withdraw_signers
            .entry((decision.request_id, decision.block_hash.clone()))
            .or_default()
            .push(decision.clone());

        Ok(())
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
        let mut store = self.lock().await;

        store
            .bitcoin_block_to_transactions
            .entry(bitcoin_transaction.block_hash.clone())
            .or_default()
            .push(bitcoin_transaction.txid.clone());

        store
            .bitcoin_transactions_to_blocks
            .entry(bitcoin_transaction.txid.clone())
            .or_default()
            .push(bitcoin_transaction.block_hash.clone());

        Ok(())
    }

    async fn write_stacks_transaction(
        &self,
        stacks_transaction: &model::StacksTransaction,
    ) -> Result<(), Self::Error> {
        let mut store = self.lock().await;

        store
            .stacks_block_to_transactions
            .entry(stacks_transaction.block_hash.clone())
            .or_default()
            .push(stacks_transaction.txid.clone());

        store
            .stacks_transactions_to_blocks
            .entry(stacks_transaction.txid.clone())
            .or_default()
            .push(stacks_transaction.block_hash.clone());

        Ok(())
    }

    async fn write_stacks_blocks(&self, blocks: &[NakamotoBlock]) -> Result<(), Self::Error> {
        let mut store = self.lock().await;
        blocks.iter().for_each(|block| {
            store
                .stacks_nakamoto_blocks
                .insert(block.block_id(), block.clone());
        });

        Ok(())
    }
}
