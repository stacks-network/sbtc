use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{
    DEPOSIT_LOCKTIME_BLOCK_BUFFER,
    bitcoin::{
        utxo::SignerUtxo,
        validation::{DepositRequestReport, WithdrawalRequestReport},
    },
    error::Error,
    keys::{PublicKey, PublicKeyXOnly, SignerScriptPubKey as _},
    storage::{
        DbRead,
        model::{self, BitcoinBlockHeight, DkgSharesStatus, StacksBlockHash},
        util::get_utxo,
    },
};

use super::{SharedStore, store::InMemoryTransaction};

impl DbRead for SharedStore {
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
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        let store = self.lock().await;
        let deposit_requests = store.get_deposit_requests(&chain_tip.block_hash, context_window);

        let threshold = threshold as usize;

        // Add one to the acceptable unlock height because the chain tip is at height one less
        // than the height of the next block, which is the block for which we are assessing
        // the threshold.
        let minimum_acceptable_unlock_height =
            chain_tip.block_height + DEPOSIT_LOCKTIME_BLOCK_BUFFER as u64 + 1;

        // Get all canonical blocks in the context window.
        let canonical_bitcoin_blocks =
            std::iter::successors(Some(&chain_tip.block_hash), |block_hash| {
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
                            block_included.block_height + deposit_request.lock_time as u64;
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
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        _: &model::StacksBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let store = self.lock().await;
        let withdrawal_requests = store.get_withdrawal_requests(bitcoin_chain_tip, context_window);

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
        _min_bitcoin_height: BitcoinBlockHeight,
        _threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        unimplemented!();
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        _bitcoin_chain_tip: &model::BitcoinBlockRef,
        _stacks_chain_tip: &model::StacksBlockHash,
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

    async fn stacks_block_exists(&self, block_id: &StacksBlockHash) -> Result<bool, Error> {
        Ok(self.lock().await.stacks_blocks.contains_key(block_id))
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

    async fn get_latest_non_failed_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        Ok(self
            .lock()
            .await
            .encrypted_dkg_shares
            .values()
            .filter(|(_, shares)| shares.dkg_shares_status != DkgSharesStatus::Failed)
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
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(None);
        };

        let store = self.lock().await;

        let event = store
            .stacks_blockchain(&stacks_chain_tip)
            .filter_map(|block| {
                store
                    .rotate_keys_transactions
                    .get(&block.block_hash)?
                    .last()
                    .cloned()
            })
            .next();

        Ok(event)
    }

    async fn key_rotation_exists(
        &self,
        _stacks_chain_tip: &model::StacksBlockHash,
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
                    .filter_map(|txid| {
                        let outputs = store.bitcoin_outputs.get(txid)?;

                        outputs
                            .iter()
                            .any(|output| output.output_type == model::TxOutputType::SignersOutput)
                            .then_some(outputs.first()?.txid)
                            .and_then(|txid| store.reconstruct_transaction(&txid))
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
            .values()
            .flatten()
            .find(|tx| &tx.aggregate_key == aggregate_key);

        // Let's merge the signer set with the actual votes.
        if let Some(rotate_keys_tx) = ans {
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
            .values()
            .flatten()
            .find(|tx| &tx.aggregate_key == aggregate_key);

        // Let's merge the signer set with the actual votes.
        if let Some(rotate_keys_tx) = ans {
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
        let store = self.lock().await;
        let is_known_dkg_shares = store
            .encrypted_dkg_shares
            .values()
            .any(|(_, share)| &share.script_pubkey == script);

        let is_known_signer_output = store
            .bitcoin_outputs
            .values()
            .flatten()
            .filter(|output| output.output_type == model::TxOutputType::SignersOutput)
            .any(|output| &output.script_pubkey == script);

        Ok(is_known_dkg_shares || is_known_signer_output)
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

    async fn get_swept_deposit_requests(
        &self,
        _bitcoin_chain_tip: &model::BitcoinBlockHash,
        _stacks_chain_tip: &model::StacksBlockHash,
        _context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        unimplemented!("can only be tested using integration tests for now.");
    }

    async fn get_swept_withdrawal_requests(
        &self,
        _bitcoin_chain_tip: &model::BitcoinBlockHash,
        _stacks_chain_tip: &model::StacksBlockHash,
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
    ) -> Result<Option<(bool, PublicKeyXOnly, model::TxPrevoutType)>, Error> {
        Ok(self
            .lock()
            .await
            .bitcoin_sighashes
            .get(sighash)
            .map(|s| (s.will_sign, s.aggregate_key, s.prevout_type)))
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
            .values()
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

    async fn get_p2p_peers(&self) -> Result<Vec<model::P2PPeer>, Error> {
        let store = self.lock().await;
        let peers = store.p2p_peers.values().cloned().collect();
        Ok(peers)
    }
}

impl DbRead for InMemoryTransaction {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        self.store.get_bitcoin_block(block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.store.get_stacks_block(block_hash).await
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        self.store.get_bitcoin_canonical_chain_tip().await
    }

    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        self.store.get_bitcoin_canonical_chain_tip_ref().await
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.store.get_stacks_chain_tip(bitcoin_chain_tip).await
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.store
            .get_pending_deposit_requests(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
        signatures_required: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.store
            .get_pending_accepted_deposit_requests(chain_tip, context_window, signatures_required)
            .await
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        self.store.deposit_request_exists(txid, output_index).await
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        self.store
            .get_deposit_request_report(chain_tip, txid, output_index, signer_public_key)
            .await
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.store.get_deposit_signers(txid, output_index).await
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.store
            .get_deposit_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.store
            .get_withdrawal_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        self.store
            .can_sign_deposit_tx(txid, output_index, signer_public_key)
            .await
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.store
            .get_withdrawal_signers(request_id, block_hash)
            .await
    }

    async fn get_pending_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.store
            .get_pending_withdrawal_requests(
                bitcoin_chain_tip,
                stacks_chain_tip,
                context_window,
                signer_public_key,
            )
            .await
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        min_bitcoin_height: BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.store
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip,
                stacks_chain_tip,
                min_bitcoin_height,
                signature_threshold,
            )
            .await
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        stacks_chain_tip: &model::StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.store
            .get_pending_rejected_withdrawal_requests(
                bitcoin_chain_tip,
                stacks_chain_tip,
                context_window,
            )
            .await
    }

    async fn get_withdrawal_request_report(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalRequestReport>, Error> {
        self.store
            .get_withdrawal_request_report(
                bitcoin_chain_tip,
                stacks_chain_tip,
                id,
                signer_public_key,
            )
            .await
    }

    async fn compute_withdrawn_total(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error> {
        self.store
            .compute_withdrawn_total(bitcoin_chain_tip, context_window)
            .await
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        self.store.get_bitcoin_blocks_with_transaction(txid).await
    }

    async fn stacks_block_exists(&self, block_id: &StacksBlockHash) -> Result<bool, Error> {
        self.store.stacks_block_exists(block_id).await
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.store.get_encrypted_dkg_shares(aggregate_key).await
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.store.get_latest_encrypted_dkg_shares().await
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.store.get_latest_verified_dkg_shares().await
    }

    async fn get_latest_non_failed_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.store.get_latest_non_failed_dkg_shares().await
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        self.store.get_encrypted_dkg_shares_count().await
    }

    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        self.store.get_last_key_rotation(chain_tip).await
    }

    async fn key_rotation_exists(
        &self,
        stacks_chain_tip: &model::StacksBlockHash,
        signer_set: &BTreeSet<PublicKey>,
        aggregate_key: &PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error> {
        self.store
            .key_rotation_exists(
                stacks_chain_tip,
                signer_set,
                aggregate_key,
                signatures_required,
            )
            .await
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        self.store.get_signers_script_pubkeys().await
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error> {
        self.store.get_signer_utxo(chain_tip).await
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.store
            .get_deposit_request_signer_votes(txid, output_index, aggregate_key)
            .await
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.store
            .get_withdrawal_request_signer_votes(id, aggregate_key)
            .await
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.store.is_known_bitcoin_block_hash(block_hash).await
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        self.store
            .in_canonical_bitcoin_blockchain(chain_tip, block_ref)
            .await
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        self.store.is_signer_script_pub_key(script).await
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.store
            .is_withdrawal_inflight(id, bitcoin_chain_tip)
            .await
    }

    async fn is_withdrawal_active(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error> {
        self.store
            .is_withdrawal_active(id, bitcoin_chain_tip, min_confirmations)
            .await
    }

    async fn get_swept_deposit_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        self.store
            .get_swept_deposit_requests(bitcoin_chain_tip, stacks_chain_tip, context_window)
            .await
    }

    async fn get_swept_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        self.store
            .get_swept_withdrawal_requests(bitcoin_chain_tip, stacks_chain_tip, context_window)
            .await
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        self.store.get_deposit_request(txid, output_index).await
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly, model::TxPrevoutType)>, Error> {
        self.store.will_sign_bitcoin_tx_sighash(sighash).await
    }

    async fn get_p2p_peers(&self) -> Result<Vec<model::P2PPeer>, Error> {
        self.store.get_p2p_peers().await
    }
}
