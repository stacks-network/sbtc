//! In-memory store implementation - useful for tests

use bitcoin::consensus::Decodable as _;
use bitcoin::OutPoint;
use blockstack_lib::types::chainstate::StacksBlockId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::validation::DepositRequestReport;
use crate::bitcoin::validation::WithdrawalRequestReport;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::keys::SignerScriptPubKey as _;
use crate::storage::model;
use crate::storage::model::CompletedDepositEvent;
use crate::storage::model::WithdrawalAcceptEvent;
use crate::storage::model::WithdrawalRejectEvent;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;

use super::model::DkgSharesStatus;
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

    /// A mapping between (request_ids, block_hash) and withdrawal-create events.
    /// Note that a single request_id may be associated with
    /// more than one withdrawal-create event because of reorgs.
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

    /// Bitcoin anchor to stacks blocks
    pub bitcoin_anchor_to_stacks_blocks:
        HashMap<model::BitcoinBlockHash, Vec<model::StacksBlockHash>>,

    /// Encrypted DKG shares
    pub encrypted_dkg_shares: BTreeMap<PublicKeyXOnly, (OffsetDateTime, model::EncryptedDkgShares)>,

    /// Rotate keys transactions
    pub rotate_keys_transactions: HashMap<model::StacksTxId, model::RotateKeysTransaction>,

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

    /// Bitcoin transaction outputs
    pub bitcoin_outputs: HashMap<model::BitcoinTxId, model::TxOutput>,

    /// Bitcoin transaction inputs
    pub bitcoin_prevouts: HashMap<model::BitcoinTxId, model::TxPrevout>,

    /// Bitcoin signhashes
    pub bitcoin_sighashes: HashMap<model::SigHash, model::BitcoinTxSigHash>,

    /// Bitcoin withdrawal outputs
    pub bitcoin_withdrawal_outputs:
        HashMap<(u64, model::StacksBlockHash), model::BitcoinWithdrawalOutput>,
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

    async fn get_utxo_from_donation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        context_window: u16,
    ) -> Result<Option<SignerUtxo>, Error> {
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let bitcoin_blocks = &self.bitcoin_blocks;
        let first = bitcoin_blocks.get(chain_tip);

        // Traverse the canonical chain backwards and find the first block containing relevant tx(s)
        let sbtc_txs = std::iter::successors(first, |block| bitcoin_blocks.get(&block.parent_hash))
            .take(context_window as usize)
            .filter_map(|block| {
                let txs = self.bitcoin_block_to_transactions.get(&block.block_hash)?;

                let mut sbtc_txs = txs
                    .iter()
                    .filter_map(|tx| self.raw_transactions.get(&tx.into_bytes()))
                    .filter(|sbtc_tx| sbtc_tx.tx_type == model::TransactionType::Donation)
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

    /// Get all deposit requests that are on the blockchain identified by
    /// the chain tip within the context window.
    pub fn get_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Vec<model::DepositRequest> {
        (0..context_window)
            // Find all tracked transaction IDs in the context window
            .scan(chain_tip, |block_hash, _| {
                let transaction_ids = self
                    .bitcoin_block_to_transactions
                    .get(*block_hash)
                    .cloned()
                    .unwrap_or_else(Vec::new);

                let block = self.bitcoin_blocks.get(*block_hash)?;
                *block_hash = &block.parent_hash;

                Some(transaction_ids)
            })
            .flatten()
            // Return all deposit requests associated with any of these transaction IDs
            .flat_map(|txid| {
                self.deposit_requests
                    .values()
                    .filter(move |req| req.txid == txid)
                    .cloned()
            })
            .collect()
    }

    fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Option<model::StacksBlock> {
        let bitcoin_chain_tip = self.bitcoin_blocks.get(bitcoin_chain_tip)?;

        std::iter::successors(Some(bitcoin_chain_tip), |block| {
            self.bitcoin_blocks.get(&block.parent_hash)
        })
        .filter_map(|block| self.bitcoin_anchor_to_stacks_blocks.get(&block.block_hash))
        .flatten()
        .filter_map(|stacks_block_hash| self.stacks_blocks.get(stacks_block_hash))
        .max_by_key(|block| (block.block_height, block.block_hash.to_bytes()))
        .cloned()
    }

    fn get_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Vec<model::WithdrawalRequest> {
        let first_block = self.bitcoin_blocks.get(chain_tip);

        let context_window_end_block = std::iter::successors(first_block, |block| {
            Some(self.bitcoin_blocks.get(&block.parent_hash).unwrap_or(block))
        })
        .nth(context_window as usize);

        let Some(context_window_end_block) = context_window_end_block else {
            return Vec::new();
        };

        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip) else {
            return Vec::new();
        };

        std::iter::successors(Some(&stacks_chain_tip), |stacks_block| {
            self.stacks_blocks.get(&stacks_block.parent_hash)
        })
        .take_while(|stacks_block| {
            self.bitcoin_blocks
                .get(&stacks_block.bitcoin_anchor)
                .is_some_and(|anchor| anchor.block_height >= context_window_end_block.block_height)
        })
        .flat_map(|stacks_block| {
            self.stacks_block_to_withdrawal_requests
                .get(&stacks_block.block_hash)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|pk| {
                    self.withdrawal_requests
                        .get(&pk)
                        .expect("missing withdraw request")
                        .clone()
                })
        })
        .collect()
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

    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_blocks
            .values()
            .max_by_key(|block| (block.block_height, block.block_hash))
            .map(model::BitcoinBlockRef::from))
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        Ok(self.lock().await.get_stacks_chain_tip(bitcoin_chain_tip))
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        let store = self.lock().await;

        let deposits_requests = store.get_deposit_requests(chain_tip, context_window);
        let voted: HashSet<(model::BitcoinTxId, u32)> = store
            .signer_to_deposit_request
            .get(signer_public_key)
            .cloned()
            .unwrap_or(Vec::new())
            .into_iter()
            .collect();

        let result = deposits_requests
            .into_iter()
            .filter(|x| !voted.contains(&(x.txid, x.output_index)))
            .collect();

        Ok(result)
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        let store = self.lock().await;
        let deposit_requests = store.get_deposit_requests(chain_tip, context_window);

        let threshold = threshold as usize;

        // Add one to the acceptable unlock height because the chain tip is at height one less
        // than the height of the next block, which is the block for which we are assessing
        // the threshold.
        let minimum_acceptable_unlock_height =
            store.bitcoin_blocks.get(chain_tip).unwrap().block_height as u32
                + DEPOSIT_LOCKTIME_BLOCK_BUFFER as u32
                + 1;

        // Get all canonical blocks in the context window.
        let canonical_bitcoin_blocks = std::iter::successors(Some(chain_tip), |block_hash| {
            store
                .bitcoin_blocks
                .get(block_hash)
                .map(|block| &block.parent_hash)
        })
        .take(context_window as usize)
        .collect::<HashSet<_>>();

        Ok(deposit_requests
            .into_iter()
            .filter(|deposit_request| {
                store
                    .bitcoin_transactions_to_blocks
                    .get(&deposit_request.txid)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .filter(|block_hash| canonical_bitcoin_blocks.contains(block_hash))
                    .filter_map(|block_hash| store.bitcoin_blocks.get(block_hash))
                    .map(|block_included: &model::BitcoinBlock| {
                        let unlock_height =
                            block_included.block_height as u32 + deposit_request.lock_time;
                        unlock_height >= minimum_acceptable_unlock_height
                    })
                    .next()
                    .unwrap_or(false)
            })
            .filter(|deposit_request| {
                store
                    .deposit_request_to_signers
                    .get(&(deposit_request.txid, deposit_request.output_index))
                    .map(|signers| {
                        signers
                            .iter()
                            .filter(|signer| signer.can_accept && signer.can_sign)
                            .count()
                            >= threshold
                    })
                    .unwrap_or_default()
            })
            .collect())
    }

    async fn get_deposit_request_report(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _txid: &model::BitcoinTxId,
        _output_index: u32,
        _signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        // You can find an implementation in git commit
        // 717381ebcae4f399c80b9fd8f4506836ff4974ec that handles most of
        // the logic but doesn't handle swept deposits.
        unimplemented!()
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

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        let store = self.lock().await;
        let deposit_request = store.deposit_requests.get(&(*txid, output_index)).cloned();
        let Some(deposit_request) = deposit_request else {
            return Ok(None);
        };

        let can_sign = store
            .encrypted_dkg_shares
            .values()
            .filter(|(_, shares)| shares.signer_set_public_keys.contains(signer_public_key))
            .map(|(_, shares)| PublicKeyXOnly::from(shares.aggregate_key))
            .any(|x_only_key| x_only_key == deposit_request.signers_public_key);

        Ok(Some(can_sign))
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        let store = self.lock().await;
        Ok(store.deposit_requests.contains_key(&(*txid, output_index)))
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
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let store = self.lock().await;
        let withdrawal_requests = store.get_withdrawal_requests(chain_tip, context_window);

        // These are the withdrawal requests that this signer has voted on.
        let voted: HashSet<(u64, model::StacksBlockHash)> = store
            .withdrawal_request_to_signers
            .iter()
            .filter_map(|(pk, decisions)| {
                decisions
                    .iter()
                    .find(|decision| &decision.signer_pub_key == signer_public_key)
                    .map(|_| *pk)
            })
            .collect();

        let result = withdrawal_requests
            .into_iter()
            .filter(|x| !voted.contains(&(x.request_id, x.block_hash)))
            .collect();

        Ok(result)
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        _bitcoin_chain_tip: &model::BitcoinBlockHash,
        _stacks_chain_tip: &model::StacksBlockHash,
        _min_bitcoin_height: u64,
        _threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        unimplemented!();
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        _chain_tip: &model::BitcoinBlockRef,
        _context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        unimplemented!()
    }

    async fn get_withdrawal_request_report(
        &self,
        _bitcoin_chain_tip: &model::BitcoinBlockHash,
        _stacks_chain_tip: &model::StacksBlockHash,
        _id: &model::QualifiedRequestId,
        _signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalRequestReport>, Error> {
        unimplemented!()
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
            .stacks_blocks
            .contains_key(&block_id.into()))
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .get(&aggregate_key.into())
            .map(|(_, shares)| shares.clone()))
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .max_by_key(|(time, _)| time)
            .map(|(_, shares)| shares.clone()))
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .filter(|(_, shares)| shares.dkg_shares_status == DkgSharesStatus::Verified)
            .max_by_key(|(time, _)| time)
            .map(|(_, shares)| shares.clone()))
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .filter(|(_, shares)| shares.dkg_shares_status != DkgSharesStatus::Failed)
            .count() as u32)
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

    async fn key_rotation_exists(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _signer_set: &BTreeSet<PublicKey>,
        _aggregate_key: &PublicKey,
        _signatures_required: u16,
    ) -> Result<bool, Error> {
        unimplemented!()
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .map(|(_, share)| share.script_pubkey.to_bytes())
            .collect())
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error> {
        let Some(dkg_shares) = self.get_latest_encrypted_dkg_shares().await? else {
            return Ok(None);
        };
        let aggregate_key = dkg_shares.aggregate_key;
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let store = self.lock().await;
        let bitcoin_blocks = &store.bitcoin_blocks;
        let first = bitcoin_blocks.get(chain_tip);

        let context_window = 1000;
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
            // if no sbtc tx exists, consider donations
            return store
                .get_utxo_from_donation(chain_tip, &aggregate_key, context_window)
                .await;
        };

        get_utxo(&aggregate_key, sbtc_txs)
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
            .map(|vote| (vote.signer_pub_key, vote.can_accept))
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

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        Ok(self.lock().await.bitcoin_blocks.contains_key(block_hash))
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
            .any(|(_, share)| &share.script_pubkey == script))
    }

    async fn is_withdrawal_inflight(
        &self,
        _: &model::QualifiedRequestId,
        _: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        unimplemented!()
    }

    async fn is_withdrawal_active(
        &self,
        _: &model::QualifiedRequestId,
        _: &model::BitcoinBlockRef,
        _: u64,
    ) -> Result<bool, Error> {
        unimplemented!()
    }

    async fn compute_withdrawn_total(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error> {
        let db = self.lock().await;
        // Get the blockchain
        let bitcoin_blocks = std::iter::successors(Some(chain_tip), |block_hash| {
            db.bitcoin_blocks
                .get(block_hash)
                .map(|block| &block.parent_hash)
        })
        .take(context_window.max(1) as usize)
        .collect::<HashSet<_>>();

        // Get all transactions in the blockchain
        let txs = bitcoin_blocks
            .iter()
            .flat_map(|block_hash| db.bitcoin_block_to_transactions.get(block_hash))
            .flatten()
            .collect::<HashSet<_>>();

        // Get withdrawal IDs related to the above transactions.
        let swept_withdrawals = db
            .bitcoin_withdrawal_outputs
            .values()
            .filter(|x| txs.contains(&x.bitcoin_txid))
            .map(|x| (x.request_id, x.stacks_block_hash))
            .collect::<HashSet<_>>();

        // Compute the total amount from all of these swept withdrawal
        // requests.
        let total_withdrawn = swept_withdrawals
            .iter()
            .filter_map(|id| db.withdrawal_requests.get(id))
            .map(|req| req.amount)
            .sum();

        Ok(total_withdrawn)
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

    async fn get_swept_deposit_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        unimplemented!("can only be tested using integration tests for now.");
    }

    async fn get_swept_withdrawal_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        unimplemented!("can only be tested using integration tests for now.");
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        Ok(self
            .lock()
            .await
            .deposit_requests
            .get(&(*txid, output_index))
            .cloned())
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly)>, Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_sighashes
            .get(sighash)
            .map(|s| (s.will_sign, s.aggregate_key)))
    }

    // The postgres implementation uses a timestamp to figure out when a
    // decision was inserted into the database. The in memory database
    // does not have such a timestamp, so we use the Stacks block's
    // bitcoin anchor block as a proxy for when the decision was made.
    // Discussion about this can be found here:
    // https://github.com/stacks-network/sbtc/pull/1243#discussion_r1922483913
    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        let store = self.lock().await;

        let first_block = store.bitcoin_blocks.get(chain_tip);

        let context_window_end_block = std::iter::successors(first_block, |block| {
            Some(
                store
                    .bitcoin_blocks
                    .get(&block.parent_hash)
                    .unwrap_or(block),
            )
        })
        .nth(context_window as usize);

        let Some(context_window_end_block) = context_window_end_block else {
            return Ok(Vec::new());
        };

        let Some(stacks_chain_tip) = store.get_stacks_chain_tip(chain_tip) else {
            return Ok(Vec::new());
        };

        let stacks_blocks_in_context: HashSet<_> =
            std::iter::successors(Some(&stacks_chain_tip), |stacks_block| {
                store.stacks_blocks.get(&stacks_block.parent_hash)
            })
            .take_while(|stacks_block| {
                store
                    .bitcoin_blocks
                    .get(&stacks_block.bitcoin_anchor)
                    .is_some_and(|anchor| {
                        anchor.block_height >= context_window_end_block.block_height
                    })
            })
            .map(|stacks_block| stacks_block.block_hash)
            .collect();

        let withdrawal_signers: Vec<_> = store
            .withdrawal_request_to_signers
            .iter()
            .map(|(_, signers)| signers)
            .flatten()
            .filter(|signer| {
                stacks_blocks_in_context.contains(&signer.block_hash)
                    && signer.signer_pub_key == *signer_public_key
            })
            .cloned()
            .collect();

        Ok(withdrawal_signers)
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        let store = self.lock().await;
        let deposit_requests = store.get_deposit_requests(chain_tip, context_window);
        let voted: HashSet<(model::BitcoinTxId, u32)> = store
            .signer_to_deposit_request
            .get(signer_public_key)
            .cloned()
            .unwrap_or(Vec::new())
            .into_iter()
            .collect();

        let result = deposit_requests
            .into_iter()
            .filter_map(|request| {
                if !voted.contains(&(request.txid, request.output_index)) {
                    return None;
                }
                store
                    .deposit_request_to_signers
                    .get(&(request.txid, request.output_index))
                    .and_then(|signers| {
                        signers
                            .iter()
                            .find(|signer| signer.signer_pub_key == *signer_public_key)
                            .cloned()
                    })
            })
            .collect();

        Ok(result)
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
            self.write_transaction(&tx).await?;
            let bitcoin_transaction = model::BitcoinTxRef {
                txid: tx.txid.into(),
                block_hash: tx.block_hash.into(),
            };
            self.write_bitcoin_transaction(&bitcoin_transaction).await?;
        }

        Ok(())
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.stacks_blocks.insert(block.block_hash, block.clone());
        store
            .bitcoin_anchor_to_stacks_blocks
            .entry(block.bitcoin_anchor)
            .or_default()
            .push(block.block_hash);
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
            self.write_transaction(&tx).await?;
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
            store.stacks_blocks.insert(block.block_hash, block.clone());
            store
                .bitcoin_anchor_to_stacks_blocks
                .entry(block.bitcoin_anchor)
                .or_default()
                .push(block.block_hash);
        });

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        self.lock().await.encrypted_dkg_shares.insert(
            shares.aggregate_key.into(),
            (time::OffsetDateTime::now_utc(), shares.clone()),
        );

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

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        self.lock()
            .await
            .bitcoin_outputs
            .insert(output.txid, output.clone());

        Ok(())
    }

    async fn write_withdrawal_tx_output(
        &self,
        _output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        self.lock()
            .await
            .bitcoin_prevouts
            .insert(prevout.txid, prevout.clone());

        Ok(())
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawal_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        withdrawal_outputs.iter().for_each(|output| {
            store.bitcoin_withdrawal_outputs.insert(
                (output.request_id, output.stacks_block_hash),
                output.clone(),
            );
        });
        Ok(())
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        sighashes.iter().for_each(|sighash| {
            store
                .bitcoin_sighashes
                .insert(sighash.sighash, sighash.clone());
        });
        Ok(())
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        let mut store = self.lock().await;
        if let Some((_, shares)) = store.encrypted_dkg_shares.get_mut(&aggregate_key.into()) {
            if shares.dkg_shares_status == DkgSharesStatus::Unverified {
                shares.dkg_shares_status = DkgSharesStatus::Failed;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        let mut store = self.lock().await;
        if let Some((_, shares)) = store.encrypted_dkg_shares.get_mut(&aggregate_key.into()) {
            if shares.dkg_shares_status == DkgSharesStatus::Unverified {
                shares.dkg_shares_status = DkgSharesStatus::Verified;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
