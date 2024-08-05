//! In-memory store implementation - useful for tests

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

    /// Deposit request to signers
    pub deposit_request_to_signers: HashMap<DepositRequestPk, Vec<model::DepositSigner>>,

    /// Deposit signer to request
    pub signer_to_deposit_request: HashMap<model::PubKey, Vec<DepositRequestPk>>,

    /// Withdraw signers
    pub withdraw_request_to_signers: HashMap<WithdrawRequestPk, Vec<model::WithdrawSigner>>,

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
    pub stacks_nakamoto_blocks: HashMap<model::StacksBlockHash, model::StacksBlock>,

    /// Encrypted DKG shares
    pub encrypted_dkg_shares: HashMap<model::PubKey, model::EncryptedDkgShares>,
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

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
        threshold: i64,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let pending_deposit_requests = self
            .get_pending_deposit_requests(chain_tip, context_window)
            .await?;
        let store = self.lock().await;

        let threshold = threshold.try_into().expect("type conversion failure");

        Ok(pending_deposit_requests
            .into_iter()
            .filter(|deposit_request| {
                store
                    .deposit_request_to_signers
                    .get(&(deposit_request.txid.clone(), deposit_request.output_index))
                    .map(|signers| {
                        signers.iter().filter(|signer| signer.is_accepted).count() >= threshold
                    })
                    .unwrap_or_default()
            })
            .collect())
    }

    async fn get_accepted_deposit_requests(
        &self,
        signer: &model::PubKey,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let store = self.lock().await;

        let accepted_deposit_pks = store
            .signer_to_deposit_request
            .get(signer)
            .cloned()
            .unwrap_or_default();

        Ok(accepted_deposit_pks
            .into_iter()
            .map(|req| {
                store
                    .deposit_requests
                    .get(&req)
                    .cloned()
                    .expect("missing deposit request")
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
            .deposit_request_to_signers
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
            .withdraw_request_to_signers
            .get(&(request_id, block_hash.clone()))
            .cloned()
            .unwrap_or_default())
    }

    async fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
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
        .skip((context_window).try_into().unwrap_or_default())
        .boxed()
        .try_next()
        .await?;

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
                    .as_ref()
                    .is_some_and(|block| block.confirms.contains(&stacks_block.block_hash))
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

    async fn get_pending_accepted_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
        threshold: i64,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let pending_withdraw_requests = self
            .get_pending_withdraw_requests(chain_tip, context_window)
            .await?;
        let store = self.lock().await;

        let threshold = threshold.try_into().expect("type conversion failure");

        Ok(pending_withdraw_requests
            .into_iter()
            .filter(|withdraw_request| {
                store
                    .withdraw_request_to_signers
                    .get(&(
                        withdraw_request.request_id,
                        withdraw_request.block_hash.clone(),
                    ))
                    .map(|signers| {
                        signers.iter().filter(|signer| signer.is_accepted).count() >= threshold
                    })
                    .unwrap_or_default()
            })
            .collect())
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
            .contains_key(block_id.to_bytes().as_slice()))
    }

    async fn get_encrypted_dkg_shares(
        &self,
        aggregate_key: &model::PubKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Self::Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .get(aggregate_key)
            .cloned())
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

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Self::Error> {
        let mut store = self.lock().await;
        for req in deposit_requests.into_iter() {
            store
                .deposit_requests
                .insert((req.txid.clone(), req.output_index), req);
        }
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
        let mut store = self.lock().await;

        let deposit_request_pk = (decision.txid.clone(), decision.output_index);

        store
            .deposit_request_to_signers
            .entry(deposit_request_pk.clone())
            .or_default()
            .push(decision.clone());

        store
            .signer_to_deposit_request
            .entry(decision.signer_pub_key.clone())
            .or_default()
            .push(deposit_request_pk);

        Ok(())
    }

    async fn write_withdraw_signer_decision(
        &self,
        decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .withdraw_request_to_signers
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

    async fn write_stacks_transactions(
        &self,
        stacks_transactions: Vec<model::Transaction>,
    ) -> Result<(), Self::Error> {
        for tx in stacks_transactions {
            let stacks_transaction = model::StacksTransaction {
                txid: tx.txid,
                block_hash: tx.block_hash,
            };
            self.write_stacks_transaction(&stacks_transaction).await?;
        }

        Ok(())
    }

    async fn write_stacks_block_headers(
        &self,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Self::Error> {
        let mut store = self.lock().await;
        blocks.iter().for_each(|block| {
            store
                .stacks_nakamoto_blocks
                .insert(block.block_hash.clone(), block.clone());
        });

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .encrypted_dkg_shares
            .insert(shares.aggregate_key.clone(), shares.clone());

        Ok(())
    }
}
