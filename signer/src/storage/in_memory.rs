//! In-memory store implementation - useful for tests

use bitcoin::consensus::Decodable as _;
use bitcoin::OutPoint;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::StreamExt as _;
use futures::TryStreamExt as _;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bitcoin::utxo::SignerUtxo;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::stacks::events::CompletedDepositEvent;
use crate::stacks::events::WithdrawalAcceptEvent;
use crate::stacks::events::WithdrawalCreateEvent;
use crate::stacks::events::WithdrawalRejectEvent;
use crate::storage::model;

use super::util::get_utxo;

/// A store wrapped in an Arc<Mutex<...>> for interior mutability
pub type SharedStore = Arc<Mutex<Store>>;

type DepositRequestPk = (model::BitcoinTxId, u32);
type WithdrawalRequestPk = (u64, model::StacksBlockHash);

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
    pub withdrawal_requests: HashMap<WithdrawalRequestPk, model::WithdrawalRequest>,

    /// Deposit request to signers
    pub deposit_request_to_signers: HashMap<DepositRequestPk, Vec<model::DepositSigner>>,

    /// Deposit signer to request
    pub signer_to_deposit_request: HashMap<PublicKey, Vec<DepositRequestPk>>,

    /// Withdraw signers
    pub withdrawal_request_to_signers: HashMap<WithdrawalRequestPk, Vec<model::WithdrawalSigner>>,

    /// Raw transaction data
    pub raw_transactions: HashMap<[u8; 32], model::Transaction>,

    /// Bitcoin blocks to transactions
    pub bitcoin_block_to_transactions: HashMap<model::BitcoinBlockHash, Vec<model::BitcoinTxId>>,

    /// Bitcoin transactions to blocks
    pub bitcoin_transactions_to_blocks: HashMap<model::BitcoinTxId, Vec<model::BitcoinBlockHash>>,

    /// Bitcoin transactions to blocks
    pub bitcoin_transactions:
        HashMap<(model::BitcoinTxId, model::BitcoinBlockHash), model::BitcoinTx>,

    /// Stacks blocks to transactions
    pub stacks_block_to_transactions: HashMap<model::StacksBlockHash, Vec<model::StacksTxId>>,

    /// Stacks transactions to blocks
    pub stacks_transactions_to_blocks: HashMap<model::StacksTxId, Vec<model::StacksBlockHash>>,

    /// Stacks blocks to withdraw requests
    pub stacks_block_to_withdrawal_requests:
        HashMap<model::StacksBlockHash, Vec<WithdrawalRequestPk>>,

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
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        Ok(self.lock().await.bitcoin_blocks.get(block_hash).cloned())
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        Ok(self.lock().await.stacks_blocks.get(block_hash).cloned())
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_blocks
            .values()
            .max_by_key(|block| (block.block_height, block.block_hash))
            .map(|block| block.block_hash))
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
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
    ) -> Result<Vec<model::DepositRequest>, Error> {
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
    ) -> Result<Vec<model::DepositRequest>, Error> {
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
                    .get(&(deposit_request.txid, deposit_request.output_index))
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
    ) -> Result<Vec<model::DepositRequest>, Error> {
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
    ) -> Result<Vec<model::DepositSigner>, Error> {
        Ok(self
            .lock()
            .await
            .deposit_request_to_signers
            .get(&(*txid, output_index))
            .cloned()
            .unwrap_or_default())
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        Ok(self
            .lock()
            .await
            .withdrawal_request_to_signers
            .get(&(request_id, *block_hash))
            .cloned()
            .unwrap_or_default())
    }

    async fn get_pending_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let Some(bitcoin_chain_tip) = self.get_bitcoin_block(chain_tip).await? else {
            return Ok(Vec::new());
        };

        let context_window_end_block =
            futures::stream::try_unfold(bitcoin_chain_tip.block_hash, |block_hash| async move {
                self.get_bitcoin_block(&block_hash)
                    .await
                    .map(|opt| opt.map(|block| (block.clone(), block.parent_hash)))
            })
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
                    .stacks_block_to_withdrawal_requests
                    .get(&stacks_block.block_hash)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|pk| {
                        store
                            .withdrawal_requests
                            .get(&pk)
                            .expect("missing withdraw request")
                            .clone()
                    })
            })
            .collect(),
        )
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let pending_withdraw_requests = self
            .get_pending_withdrawal_requests(chain_tip, context_window)
            .await?;
        let store = self.lock().await;

        let threshold = threshold as usize;

        Ok(pending_withdraw_requests
            .into_iter()
            .filter(|withdraw_request| {
                store
                    .withdrawal_request_to_signers
                    .get(&(withdraw_request.request_id, withdraw_request.block_hash))
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
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_transactions_to_blocks
            .get(txid)
            .cloned()
            .unwrap_or_else(Vec::new))
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Error> {
        Ok(self
            .lock()
            .await
            .stacks_nakamoto_blocks
            .contains_key(&block_id.into()))
    }

    async fn get_encrypted_dkg_shares(
        &self,
        aggregate_key: &PublicKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
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
    ) -> Result<Option<model::RotateKeysTransaction>, Error> {
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

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .map(|share| share.script_pubkey.to_bytes())
            .collect())
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        context_window: u16,
    ) -> Result<Option<SignerUtxo>, Error> {
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let store = self.lock().await;
        let bitcoin_blocks = &store.bitcoin_blocks;
        let first = bitcoin_blocks.get(chain_tip);

        // Traverse the canonical chain backwards and find the first block containing relevant sbtc tx(s)
        let sbtc_txs = std::iter::successors(first, |block| bitcoin_blocks.get(&block.parent_hash))
            .take(context_window as usize)
            .filter_map(|block| {
                let txs = store.bitcoin_block_to_transactions.get(&block.block_hash)?;

                let mut sbtc_txs = txs
                    .iter()
                    .filter_map(|tx| store.raw_transactions.get(&tx.into_bytes()))
                    .filter(|sbtc_tx| sbtc_tx.tx_type == model::TransactionType::SbtcTransaction)
                    .filter_map(|tx| {
                        bitcoin::Transaction::consensus_decode(&mut tx.tx.as_slice()).ok()
                    })
                    .filter(|tx| {
                        tx.output
                            .first()
                            .is_some_and(|out| out.script_pubkey == script_pubkey)
                    })
                    .peekable();

                if sbtc_txs.peek().is_some() {
                    Some(sbtc_txs.collect::<Vec<_>>())
                } else {
                    None
                }
            })
            .next();

        // `sbtc_txs` contains all the txs in the highest canonical block where the first
        // output is spendable by script_pubkey
        let Some(sbtc_txs) = sbtc_txs else {
            return Ok(None);
        };

        get_utxo(aggregate_key, sbtc_txs)
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        // Let's fetch the votes for the outpoint
        let signers = self.get_deposit_signers(txid, output_index).await?;
        let mut signer_votes: HashMap<PublicKey, bool> = signers
            .iter()
            .map(|vote| (vote.signer_pub_key, vote.is_accepted))
            .collect();

        // Now we might not have votes from every signer, so lets get the
        // full signer set.
        let store = self.lock().await;
        let ans = store
            .rotate_keys_transactions
            .iter()
            .find(|(_, tx)| &tx.aggregate_key == aggregate_key);

        // Let's merge the signer set with the actual votes.
        if let Some((_, rotate_keys_tx)) = ans {
            let votes: Vec<model::SignerVote> = rotate_keys_tx
                .signer_set
                .iter()
                .map(|public_key| model::SignerVote {
                    signer_public_key: *public_key,
                    is_accepted: signer_votes.remove(public_key),
                })
                .collect();
            Ok(model::SignerVotes::from(votes))
        } else {
            Ok(model::SignerVotes::from(Vec::new()))
        }
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        // Let's fetch the votes for the outpoint
        let signers = self
            .get_withdrawal_signers(id.request_id, &id.block_hash)
            .await?;
        let signer_votes: HashMap<PublicKey, bool> = signers
            .iter()
            .map(|vote| (vote.signer_pub_key, vote.is_accepted))
            .collect();

        // Now we might not have votes from every signer, so lets get the
        // full signer set.
        let store = self.lock().await;
        let ans = store
            .rotate_keys_transactions
            .iter()
            .find(|(_, tx)| &tx.aggregate_key == aggregate_key);

        // Let's merge the signer set with the actual votes.
        if let Some((_, rotate_keys_tx)) = ans {
            let votes: Vec<model::SignerVote> = rotate_keys_tx
                .signer_set
                .iter()
                .map(|public_key| model::SignerVote {
                    signer_public_key: *public_key,
                    is_accepted: signer_votes.get(public_key).copied(),
                })
                .collect();
            Ok(model::SignerVotes::from(votes))
        } else {
            Ok(model::SignerVotes::from(Vec::new()))
        }
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        let store = self.lock().await;
        let bitcoin_blocks = &store.bitcoin_blocks;
        let first = bitcoin_blocks.get(&chain_tip.block_hash);

        let num_matches =
            std::iter::successors(first, |block| bitcoin_blocks.get(&block.parent_hash))
                .map(model::BitcoinBlockRef::from)
                .skip_while(|block| block != block_ref)
                .count();

        Ok(num_matches > 0)
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .any(|share| &share.script_pubkey == script))
    }

    async fn get_bitcoin_tx(
        &self,
        txid: &model::BitcoinTxId,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinTx>, Error> {
        let store = self.lock().await;
        let maybe_tx = store
            .bitcoin_transactions
            .get(&(*txid, *block_hash))
            .cloned();

        Ok(maybe_tx)
    }
}

impl super::DbWrite for SharedStore {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        self.lock()
            .await
            .bitcoin_blocks
            .insert(block.block_hash, block.clone());

        Ok(())
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::Transaction>) -> Result<(), Error> {
        for tx in txs {
            let bitcoin_transaction = model::BitcoinTxRef {
                txid: tx.txid.into(),
                block_hash: tx.block_hash.into(),
            };
            self.write_bitcoin_transaction(&bitcoin_transaction).await?;
        }

        Ok(())
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        self.lock()
            .await
            .stacks_blocks
            .insert(block.block_hash, block.clone());

        Ok(())
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        self.lock().await.deposit_requests.insert(
            (deposit_request.txid, deposit_request.output_index),
            deposit_request.clone(),
        );

        Ok(())
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        for req in deposit_requests.into_iter() {
            store
                .deposit_requests
                .insert((req.txid, req.output_index), req);
        }
        Ok(())
    }

    async fn write_withdrawal_request(
        &self,
        withdraw_request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;

        let pk = (withdraw_request.request_id, withdraw_request.block_hash);

        store
            .stacks_block_to_withdrawal_requests
            .entry(pk.1)
            .or_default()
            .push(pk);

        store
            .withdrawal_requests
            .insert(pk, withdraw_request.clone());

        Ok(())
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;

        let deposit_request_pk = (decision.txid, decision.output_index);

        store
            .deposit_request_to_signers
            .entry(deposit_request_pk)
            .or_default()
            .push(decision.clone());

        store
            .signer_to_deposit_request
            .entry(decision.signer_pub_key)
            .or_default()
            .push(deposit_request_pk);

        Ok(())
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .withdrawal_request_to_signers
            .entry((decision.request_id, decision.block_hash))
            .or_default()
            .push(decision.clone());

        Ok(())
    }

    async fn write_transaction(&self, transaction: &model::Transaction) -> Result<(), Error> {
        self.lock()
            .await
            .raw_transactions
            .insert(transaction.txid, transaction.clone());

        Ok(())
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTxRef,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;

        store
            .bitcoin_block_to_transactions
            .entry(bitcoin_transaction.block_hash)
            .or_default()
            .push(bitcoin_transaction.txid);

        store
            .bitcoin_transactions_to_blocks
            .entry(bitcoin_transaction.txid)
            .or_default()
            .push(bitcoin_transaction.block_hash);

        Ok(())
    }

    async fn write_stacks_transaction(
        &self,
        stacks_transaction: &model::StacksTransaction,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;

        store
            .stacks_block_to_transactions
            .entry(stacks_transaction.block_hash)
            .or_default()
            .push(stacks_transaction.txid);

        store
            .stacks_transactions_to_blocks
            .entry(stacks_transaction.txid)
            .or_default()
            .push(stacks_transaction.block_hash);

        Ok(())
    }

    async fn write_stacks_transactions(
        &self,
        stacks_transactions: Vec<model::Transaction>,
    ) -> Result<(), Error> {
        for tx in stacks_transactions {
            let stacks_transaction = model::StacksTransaction {
                txid: tx.txid.into(),
                block_hash: tx.block_hash.into(),
            };
            self.write_stacks_transaction(&stacks_transaction).await?;
        }

        Ok(())
    }

    async fn write_stacks_block_headers(
        &self,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        blocks.iter().for_each(|block| {
            store
                .stacks_nakamoto_blocks
                .insert(block.block_hash, block.clone());
        });

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .encrypted_dkg_shares
            .insert(shares.aggregate_key, shares.clone());

        Ok(())
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::RotateKeysTransaction,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .rotate_keys_transactions
            .insert(key_rotation.txid, key_rotation.clone());

        Ok(())
    }

    async fn write_withdrawal_create_event(
        &self,
        event: &WithdrawalCreateEvent,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .withdrawal_create_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .withdrawal_accept_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .withdrawal_reject_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        self.lock()
            .await
            .completed_deposit_events
            .insert(event.outpoint, event.clone());

        Ok(())
    }
}
