//! In-memory store implementation - useful for tests

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::storage::model;

/// In-memory store
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Store {
    /// Bitcoin blocks
    pub bitcoin_blocks: HashMap<model::BitcoinBlockHash, model::BitcoinBlock>,
}

impl Store {
    /// Create an empty store
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store wrapped in an Arc<Mutex<...>>
    pub fn new_shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new()))
    }
}

impl super::DbRead for &Store {
    type Error = Error;

    async fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        Ok(self.bitcoin_blocks.get(block_hash).cloned())
    }
}

impl super::DbWrite for &mut Store {
    type Error = Error;

    async fn write_bitcoin_block(self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        self.bitcoin_blocks
            .insert(block.block_hash.clone(), block.clone());

        Ok(())
    }
}

impl super::DbRead for &Arc<Mutex<Store>> {
    type Error = Error;

    async fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        self.lock().await.get_bitcoin_block(block_hash).await
    }
}

impl super::DbWrite for &Arc<Mutex<Store>> {
    type Error = Error;

    async fn write_bitcoin_block(self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        self.lock().await.write_bitcoin_block(block).await
    }
}

/// In-memory store operations are infallible
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {}
