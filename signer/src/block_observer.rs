//! # Block observer
//!
//! This module contains the block observer implementation for the sBTC signer.
//! The block observer is responsible for populating the signer database with
//! information from the Bitcoin and Stacks blockchains, and notifying
//! the signer event loop whenever the state has been updated.
//!
//! The following information is extracted by the block observer:
//! - Bitcoin blocks
//! - Stacks blocks
//! - Deposit requests
//! - sBTC transactions
//! - Withdraw requests
//! - Deposit accept transactions
//! - Withdraw accept transactions
//! - Withdraw reject transactions
//! - Update signer set transactions
//! - Set aggregate key transactions

use std::collections::HashMap;

use crate::error;
use crate::stacks::api::StacksInteract;
use crate::storage;

use bitcoin::hashes::Hash;
use blockstack_lib::chainstate::nakamoto;
use blockstack_lib::chainstate::stacks;
use futures::stream::StreamExt;
use storage::model;
use storage::DbRead;
use storage::DbWrite;

type DepositRequestMap = HashMap<bitcoin::Txid, Vec<DepositRequest>>;

/// Block observer
#[derive(Debug)]
pub struct BlockObserver<BitcoinClient, StacksClient, EmilyClient, BlockHashStream, Storage> {
    /// Bitcoin client
    pub bitcoin_client: BitcoinClient,
    /// Stacks client
    pub stacks_client: StacksClient,
    /// Emily client
    pub emily_client: EmilyClient,
    /// Stream of blocks from the block notifier
    pub bitcoin_blocks: BlockHashStream,
    /// Database connection
    pub storage: Storage,
    /// Used to notify any other system that the database has been updated
    pub subscribers: tokio::sync::watch::Sender<()>,
    /// How far back in time the observer should look
    pub horizon: usize,
}

impl<BC, SC, EC, BHS, S> BlockObserver<BC, SC, EC, BHS, S>
where
    BC: BitcoinInteract,
    SC: StacksInteract,
    EC: EmilyInteract,
    S: DbWrite + DbRead + Send + Sync,
    BHS: futures::stream::Stream<Item = bitcoin::BlockHash> + Unpin,
    error::Error: From<<S as DbRead>::Error>,
    error::Error: From<<S as DbWrite>::Error>,
{
    /// Run the block observer
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), error::Error> {
        let mut known_deposit_requests = HashMap::new();

        while let Some(new_block_hash) = self.bitcoin_blocks.next().await {
            self.load_latest_deposit_requests(&mut known_deposit_requests)
                .await;

            for block in self.next_blocks_to_process(new_block_hash).await? {
                self.process_bitcoin_block(&known_deposit_requests, block)
                    .await?;
            }

            if self.subscribers.send(()).is_err() {
                tracing::info!("block observer has no subscribers");
                break;
            }
        }

        tracing::info!("shutting down block observer");

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn load_latest_deposit_requests(
        &mut self,
        known_deposit_requests: &mut DepositRequestMap,
    ) {
        self.emily_client
            .get_deposits()
            .await
            .into_iter()
            .for_each(|deposit| {
                known_deposit_requests
                    .entry(deposit.txid)
                    .or_default()
                    .push(deposit)
            });
    }

    #[tracing::instrument(skip(self))]
    async fn next_blocks_to_process(
        &mut self,
        mut block_hash: bitcoin::BlockHash,
    ) -> Result<Vec<bitcoin::Block>, error::Error> {
        let mut blocks = Vec::new();

        for _ in 0..self.horizon {
            if self.have_already_processed_block(block_hash).await? {
                break;
            }

            let block = self
                .bitcoin_client
                .get_block(&block_hash)
                .await
                .ok_or(error::Error::MissingBlock)?;

            block_hash = block.header.prev_blockhash;
            blocks.push(block);
        }

        // Make order chronological
        blocks.reverse();
        Ok(blocks)
    }

    #[tracing::instrument(skip(self))]
    async fn have_already_processed_block(
        &mut self,
        block_hash: bitcoin::BlockHash,
    ) -> Result<bool, error::Error> {
        Ok(self
            .storage
            .get_bitcoin_block(&block_hash.to_byte_array().into())
            .await?
            .is_some())
    }

    #[tracing::instrument(skip(self))]
    async fn process_bitcoin_block(
        &mut self,
        known_deposit_requests: &DepositRequestMap,
        block: bitcoin::Block,
    ) -> Result<(), error::Error> {
        let info = self.stacks_client.get_tenure_info().await?;
        let stacks_blocks = crate::stacks::api::fetch_unknown_ancestors(
            &self.stacks_client,
            &self.storage,
            info.tip_block_id,
        )
        .await?;

        self.extract_deposit_requests(&block.txdata);
        self.extract_sbtc_transactions(&block.txdata);

        for stacks_block in stacks_blocks {
            self.extract_withdraw_requests(&stacks_block.txs);
            self.extract_withdraw_accept_transactions(&stacks_block.txs);
            self.extract_withdraw_reject_transactions(&stacks_block.txs);
            self.extract_deposit_accept_transactions(&stacks_block.txs);
            self.extract_update_signer_set_transactions(&stacks_block.txs);
            self.extract_set_aggregate_key_transactions(&stacks_block.txs);

            self.write_stacks_block(&stacks_block).await;
        }

        self.write_bitcoin_block(&block).await?;

        Ok(())
    }

    fn extract_deposit_requests(&self, _transactions: &[bitcoin::Transaction]) {
        // TODO(#203): Implement
    }

    fn extract_sbtc_transactions(&self, _transactions: &[bitcoin::Transaction]) {
        // TODO(#204): Implement
    }

    fn extract_withdraw_requests(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#205): Implement
    }

    fn extract_withdraw_accept_transactions(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#206): Implement
    }

    fn extract_withdraw_reject_transactions(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#207): Implement
    }

    fn extract_deposit_accept_transactions(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#207): Implement
    }

    fn extract_update_signer_set_transactions(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#208): Implement
    }

    fn extract_set_aggregate_key_transactions(&self, _transactions: &[stacks::StacksTransaction]) {
        // TODO(#209): Implement
    }

    async fn write_stacks_block(&mut self, _block: &nakamoto::NakamotoBlock) {
        // TODO(#212): Implement
    }

    async fn write_bitcoin_block(&mut self, block: &bitcoin::Block) -> Result<(), error::Error> {
        let db_block = model::BitcoinBlock {
            block_hash: block.block_hash().to_byte_array().to_vec(),
            block_height: block
                .bip34_block_height()
                .expect("Failed to get block height") as i64,
            parent_hash: block.header.prev_blockhash.to_byte_array().to_vec(),
            confirms: Vec::new(),
            created_at: time::OffsetDateTime::now_utc(),
        };

        self.storage.write_bitcoin_block(&db_block).await?;

        Ok(())
    }
}

// Placehoder traits. To be replaced with the actual traits once implemented.

/// Placeholder trait
pub trait BitcoinInteract {
    /// Get block
    fn get_block(
        &mut self,
        block_hash: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Option<bitcoin::Block>>;
}

/// Placeholder trait
pub trait EmilyInteract {
    /// Get deposits
    fn get_deposits(&mut self) -> impl std::future::Future<Output = Vec<DepositRequest>>;
}

/// Placeholder type
#[derive(Debug, Clone, Hash, PartialEq)]
pub struct DepositRequest {
    /// Txid
    txid: bitcoin::Txid,
}

#[cfg(test)]
mod tests {
    use bitcoin::BlockHash;
    use blockstack_lib::chainstate::burn::ConsensusHash;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
    use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
    use blockstack_lib::types::chainstate::StacksBlockId;
    use rand::seq::IteratorRandom;
    use rand::SeedableRng;

    use crate::storage;
    use crate::testing::dummy;

    use super::*;

    #[tokio::test]
    async fn should_be_able_to_extract_bitcoin_blocks_given_a_block_header_stream() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let storage = storage::in_memory::Store::new_shared();
        let test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        let block_hash_stream = test_harness.spawn_block_hash_stream();
        let (subscribers, subscriber_rx) = tokio::sync::watch::channel(());

        let block_observer = BlockObserver {
            bitcoin_client: test_harness.clone(),
            stacks_client: test_harness.clone(),
            emily_client: (),
            bitcoin_blocks: block_hash_stream,
            storage: storage.clone(),
            subscribers,
            horizon: 1,
        };

        block_observer.run().await.expect("block observer failed");

        for block in test_harness.bitcoin_blocks {
            let persisted = storage
                .get_bitcoin_block(&block.block_hash().to_byte_array().to_vec())
                .await
                .expect("storage error")
                .expect("block wasn't persisted");

            assert_eq!(persisted.block_hash, block.block_hash().to_byte_array())
        }

        std::mem::drop(subscriber_rx);
    }

    #[derive(Debug, Clone)]
    struct TestHarness {
        bitcoin_blocks: Vec<bitcoin::Block>,
        /// This represents the Stacks block chain. The bitcoin::BlockHash
        /// is used to identify tenures. That is, all NakamotoBlocks that
        /// have the same bitcoin::BlockHash occur within the same tenure.
        stacks_blocks: Vec<(StacksBlockId, NakamotoBlock, BlockHash)>,
    }

    impl TestHarness {
        fn generate(
            rng: &mut impl rand::RngCore,
            num_bitcoin_blocks: usize,
            num_stacks_blocks_per_bitcoin_block: std::ops::Range<usize>,
        ) -> Self {
            let mut bitcoin_blocks: Vec<_> =
                std::iter::repeat_with(|| dummy::block(&fake::Faker, rng))
                    .take(num_bitcoin_blocks)
                    .collect();

            for idx in 1..bitcoin_blocks.len() {
                bitcoin_blocks[idx].header.prev_blockhash = bitcoin_blocks[idx - 1].block_hash();
            }

            let first_header = NakamotoBlockHeader::empty();
            let stacks_blocks: Vec<(StacksBlockId, NakamotoBlock, BlockHash)> = bitcoin_blocks
                .iter()
                .scan(first_header, |previous_stx_block_header, btc_block| {
                    let num_blocks = num_stacks_blocks_per_bitcoin_block
                        .clone()
                        .choose(rng)
                        .unwrap_or_default();
                    let initial_state = previous_stx_block_header.clone();
                    let stacks_blocks: Vec<(StacksBlockId, NakamotoBlock, BlockHash)> =
                        std::iter::repeat_with(|| dummy::stacks_block(&fake::Faker, rng))
                            .take(num_blocks)
                            .scan(initial_state, |last_stx_block_header, mut stx_block| {
                                stx_block.header.parent_block_id = last_stx_block_header.block_id();
                                stx_block.header.chain_length =
                                    last_stx_block_header.chain_length + 1;
                                *last_stx_block_header = stx_block.header.clone();
                                Some((stx_block.block_id(), stx_block, btc_block.block_hash()))
                            })
                            .collect();

                    if let Some((_, stx_block, _)) = stacks_blocks.last() {
                        *previous_stx_block_header = stx_block.header.clone()
                    };

                    Some(stacks_blocks)
                })
                .flatten()
                .collect();

            Self { bitcoin_blocks, stacks_blocks }
        }

        fn spawn_block_hash_stream(
            &self,
        ) -> tokio_stream::wrappers::ReceiverStream<bitcoin::BlockHash> {
            let headers: Vec<_> = self
                .bitcoin_blocks
                .iter()
                .map(|block| block.block_hash())
                .collect();

            let (tx, rx) = tokio::sync::mpsc::channel(128);

            tokio::spawn(async move {
                for header in headers {
                    tx.send(header).await.expect("failed to send header");
                }
            });

            rx.into()
        }
    }

    impl BitcoinInteract for TestHarness {
        async fn get_block(&mut self, block_hash: &bitcoin::BlockHash) -> Option<bitcoin::Block> {
            self.bitcoin_blocks
                .iter()
                .find(|block| &block.block_hash() == block_hash)
                .cloned()
        }
    }

    impl StacksInteract for TestHarness {
        async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, error::Error> {
            self.stacks_blocks
                .iter()
                .skip_while(|(id, _, _)| &block_id != id)
                .map(|(_, block, _)| block)
                .next()
                .cloned()
                .ok_or(error::Error::MissingBlock)
        }
        async fn get_tenure(
            &self,
            block_id: StacksBlockId,
        ) -> Result<Vec<NakamotoBlock>, error::Error> {
            let (stx_block_id, stx_block, btc_block_id) = self
                .stacks_blocks
                .iter()
                .skip_while(|(id, _, _)| &block_id != id)
                .next()
                .ok_or(error::Error::MissingBlock)?;

            let blocks: Vec<NakamotoBlock> = self
                .stacks_blocks
                .iter()
                .skip_while(|(_, _, block_id)| block_id != btc_block_id)
                .take_while(|(block_id, _, _)| block_id != stx_block_id)
                .map(|(_, block, _)| block)
                .chain(std::iter::once(stx_block))
                .cloned()
                .collect();

            Ok(blocks)
        }
        async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, error::Error> {
            let (_, _, btc_block_id) = self.stacks_blocks.last().unwrap();

            Ok(RPCGetTenureInfo {
                consensus_hash: ConsensusHash([0; 20]),
                tenure_start_block_id: self
                    .stacks_blocks
                    .iter()
                    .skip_while(|(_, _, block_id)| block_id != btc_block_id)
                    .next()
                    .map(|(stx_block_id, _, _)| *stx_block_id)
                    .unwrap(),
                parent_consensus_hash: ConsensusHash([0; 20]),
                parent_tenure_start_block_id: StacksBlockId::first_mined(),
                tip_block_id: self
                    .stacks_blocks
                    .last()
                    .map(|(block_id, _, _)| *block_id)
                    .unwrap(),
                tip_height: self.stacks_blocks.len() as u64,
                reward_cycle: 0,
            })
        }

        fn nakamoto_start_height(&self) -> u64 {
            self.stacks_blocks
                .first()
                .map(|(_, block, _)| block.header.chain_length)
                .unwrap_or_default()
        }
    }

    impl EmilyInteract for () {
        async fn get_deposits(&mut self) -> Vec<DepositRequest> {
            Vec::new()
        }
    }
}
