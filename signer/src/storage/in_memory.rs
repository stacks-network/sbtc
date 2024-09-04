//! In-memory store implementation - useful for tests

use bitcoin::OutPoint;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::StreamExt;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::keys::PublicKey;
use crate::stacks::events::CompletedDepositEvent;
use crate::stacks::events::WithdrawalAcceptEvent;
use crate::stacks::events::WithdrawalCreateEvent;
use crate::stacks::events::WithdrawalRejectEvent;
use crate::storage::model;

/// A store wrapped in an Arc<Mutex<...>> for interior mutability
pub type SharedStore = Arc<Mutex<Store>>;

type DepositRequestPk = (model::BitcoinTxId, u32);
type WithdrawRequestPk = (u64, model::StacksBlockHash);

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
    pub signer_to_deposit_request: HashMap<PublicKey, Vec<DepositRequestPk>>,

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
    pub encrypted_dkg_shares: HashMap<PublicKey, model::EncryptedDkgShares>,

    /// Rotate keys transactions
    pub rotate_keys_transactions: HashMap<model::StacksTxId, model::RotateKeysTransaction>,

    /// A mapping between request_ids and withdrawal-create events. Note
    /// that in prod we can have a single request_id be associated with
    /// more than one withdrawal-create event because of reorgs.
    pub withdrawal_create_events: HashMap<u64, WithdrawalCreateEvent>,

    /// A mapping between request_ids and withdrawal-accept events. Note
    /// that in prod we can have a single request_id be associated with
    /// more than one withdrawal-accept event because of reorgs.
    pub withdrawal_accept_events: HashMap<u64, WithdrawalAcceptEvent>,

    /// A mapping between request_ids and withdrawal-reject events. Note
    /// that in prod we can have a single request_id be associated with
    /// more than one withdrawal-reject event because of reorgs.
    pub withdrawal_reject_events: HashMap<u64, WithdrawalRejectEvent>,

    /// A mapping between request_ids and completed-deposit events. Note
    /// that in prod we can have a single outpoint be associated with
    /// more than one completed-deposit event because of reorgs.
    pub completed_deposit_events: HashMap<OutPoint, CompletedDepositEvent>,
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

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Self::Error> {
        let store = self.lock().await;
        let Some(bitcoin_chain_tip) = store.bitcoin_blocks.get(bitcoin_chain_tip) else {
            return Ok(None);
        };

        Ok(bitcoin_chain_tip
            .confirms
            .iter()
            .filter_map(|stacks_block_hash| store.stacks_blocks.get(stacks_block_hash))
            .max_by_key(|block| (block.block_height, &block.block_hash))
            .cloned())
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
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
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let pending_deposit_requests = self
            .get_pending_deposit_requests(chain_tip, context_window)
            .await?;
        let store = self.lock().await;

        let threshold = threshold as usize;

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
        signer: &PublicKey,
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
        output_index: u32,
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
        request_id: u64,
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
        context_window: u16,
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
        .skip(context_window as usize)
        .boxed()
        .try_next()
        .await?;

        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };

        let store = self.lock().await;

        Ok(
            std::iter::successors(Some(&stacks_chain_tip), |stacks_block| {
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
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let pending_withdraw_requests = self
            .get_pending_withdraw_requests(chain_tip, context_window)
            .await?;
        let store = self.lock().await;

        let threshold = threshold as usize;

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
        aggregate_key: &PublicKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Self::Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .get(aggregate_key)
            .cloned())
    }

    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::RotateKeysTransaction>, Self::Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(None);
        };

        let store = self.lock().await;

        Ok(
            std::iter::successors(Some(&stacks_chain_tip), |stacks_block| {
                store.stacks_blocks.get(&stacks_block.parent_hash)
            })
            .find_map(|block| {
                store
                    .stacks_block_to_transactions
                    .get(&block.block_hash)
                    .into_iter()
                    .flatten()
                    .find_map(|txid| store.rotate_keys_transactions.get(txid))
            })
            .cloned(),
        )
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Self::Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .map(|share| share.script_pubkey.clone())
            .collect())
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

    async fn write_bitcoin_transactions(
        &self,
        txs: Vec<model::Transaction>,
    ) -> Result<(), Self::Error> {
        for tx in txs {
            let bitcoin_transaction = model::BitcoinTransaction {
                txid: tx.txid,
                block_hash: tx.block_hash,
            };
            self.write_bitcoin_transaction(&bitcoin_transaction).await?;
        }

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
            .entry(decision.signer_pub_key)
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
            .insert(shares.aggregate_key, shares.clone());

        Ok(())
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::RotateKeysTransaction,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .rotate_keys_transactions
            .insert(key_rotation.txid.clone(), key_rotation.clone());

        Ok(())
    }

    async fn write_withdrawal_create_event(
        &self,
        event: &WithdrawalCreateEvent,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .withdrawal_create_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .withdrawal_accept_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .withdrawal_reject_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Self::Error> {
        self.lock()
            .await
            .completed_deposit_events
            .insert(event.outpoint, event.clone());

        Ok(())
    }
}
