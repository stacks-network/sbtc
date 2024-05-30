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
pub struct BlockObserver<BitcoinClient, StacksClient, EmilyClient, BlockHashStream, SignerStorage> {
    /// Bitcoin client
    pub bitcoin_client: BitcoinClient,
    /// Stacks client
    pub stacks_client: StacksClient,
    /// Emily client
    pub emily_client: EmilyClient,
    /// Stream of blocks from the block notifier
    pub bitcoin_blocks: BlockHashStream,
    /// Database connection
    pub storage: SignerStorage,
    /// Used to notify any other system that the database has been updated
    pub subscribers: tokio::sync::watch::Sender<()>,
    /// How far back in time the observer should look
    pub horizon: usize,
}

impl<BC, SC, EC, BHS, SS> BlockObserver<BC, SC, EC, BHS, SS>
where
    BC: BitcoinInteract,
    SC: StacksInteract,
    EC: EmilyInteract,
    BHS: futures::stream::Stream<Item = bitcoin::BlockHash> + Unpin,
    for<'a> &'a mut SS: storage::DbRead + storage::DbWrite,
    for<'a> <&'a mut SS as storage::DbRead>::Error: std::error::Error,
    for<'a> <&'a mut SS as storage::DbWrite>::Error: std::error::Error,
{
    /// Run the block observer
    pub async fn run(mut self) -> Result<(), Error> {
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
    ) -> Result<Vec<bitcoin::Block>, Error> {
        let mut blocks = Vec::new();

        for _ in 0..self.horizon {
            if self.have_already_processed_block(block_hash).await? {
                break;
            }

            let block = self
                .bitcoin_client
                .get_block(&block_hash)
                .await
                .ok_or(Error::MissingBlock)?;

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
    ) -> Result<bool, Error> {
        Ok(self
            .storage
            .get_bitcoin_block(&block_hash.to_byte_array().into())
            .await
            .map_err(|_| Error::StorageError)?
            .is_some())
    }

    #[tracing::instrument(skip(self))]
    async fn process_bitcoin_block(
        &mut self,
        known_deposit_requests: &DepositRequestMap,
        block: bitcoin::Block,
    ) -> Result<(), Error> {
        let stacks_blocks = self
            .stacks_client
            .get_blocks_by_bitcoin_block(&block.block_hash())
            .await;

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

    async fn write_bitcoin_block(&mut self, block: &bitcoin::Block) -> Result<(), Error> {
        let now = time::OffsetDateTime::now_utc();
        let created_at = time::PrimitiveDateTime::new(now.date(), now.time());

        let db_block = model::BitcoinBlock {
            block_hash: block.block_hash().to_byte_array().to_vec(),
            block_height: block
                .bip34_block_height()
                .expect("Failed to get block height") as i64,
            parent_hash: block.header.prev_blockhash.to_byte_array().to_vec(),
            confirms: None,
            created_at,
        };

        self.storage
            .write_bitcoin_block(&db_block)
            .await
            .map_err(|_| Error::StorageError)?;

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
pub trait StacksInteract {
    /// Get stacks blocks confirmed by the given bitcoin block
    fn get_blocks_by_bitcoin_block(
        &mut self,
        bitcoin_block_hash: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Vec<nakamoto::NakamotoBlock>>;
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

/// Error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Missing block
    #[error("missing block")]
    MissingBlock,
    /// Storage error
    #[error("storage error")]
    StorageError,
}

#[cfg(test)]
mod tests {
    use rand::{seq::IteratorRandom, SeedableRng};

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
        stacks_blocks_per_bitcoin_block: HashMap<bitcoin::BlockHash, Vec<nakamoto::NakamotoBlock>>,
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

            let (stacks_blocks_per_bitcoin_block, _) = bitcoin_blocks.iter().fold(
                (HashMap::new(), None),
                |(mut stacks_blocks_per_bitcoin_block, previous_stacks_block_hash), block| {
                    let num_blocks = num_stacks_blocks_per_bitcoin_block
                        .clone()
                        .choose(rng)
                        .unwrap();
                    let mut stacks_blocks: Vec<_> =
                        std::iter::repeat_with(|| dummy::stacks_block(&fake::Faker, rng))
                            .take(num_blocks)
                            .collect();

                    for idx in 1..stacks_blocks.len() {
                        stacks_blocks[idx].header.parent_block_id = stacks_blocks[idx].block_id();
                    }

                    let previous_stacks_block_hash = if !stacks_blocks.is_empty() {
                        if let Some(hash) = previous_stacks_block_hash {
                            stacks_blocks[0].header.parent_block_id = hash;
                        }

                        Some(stacks_blocks.last().unwrap().block_id())
                    } else {
                        previous_stacks_block_hash
                    };

                    stacks_blocks_per_bitcoin_block.insert(block.block_hash(), stacks_blocks);

                    (stacks_blocks_per_bitcoin_block, previous_stacks_block_hash)
                },
            );

            Self {
                bitcoin_blocks,
                stacks_blocks_per_bitcoin_block,
            }
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
        async fn get_blocks_by_bitcoin_block(
            &mut self,
            bitcoin_block_hash: &bitcoin::BlockHash,
        ) -> Vec<nakamoto::NakamotoBlock> {
            self.stacks_blocks_per_bitcoin_block
                .get(bitcoin_block_hash)
                .cloned()
                .unwrap_or_else(Vec::new)
        }
    }

    impl EmilyInteract for () {
        async fn get_deposits(&mut self) -> Vec<DepositRequest> {
            Vec::new()
        }
    }
}
