//! Test utilities for the `storage` module

use std::future::Future;
use std::time::Duration;

use crate::storage::model::{
    BitcoinBlock, BitcoinBlockHash, BitcoinBlockRef, StacksBlock, StacksBlockHash,
};
use crate::storage::postgres::PgStore;
use crate::storage::{DbRead, DbWrite};

pub mod model;
pub mod postgres;

/// The postgres connection string to the test database.
pub const DATABASE_URL_BASE: &str = "postgres://postgres:postgres@localhost:5432";

/// It's better to create a new pool for each test since there is some
/// weird bug in sqlx. The issue that can crop up with pool reuse is
/// basically a PoolTimeOut error. This is a known issue:
/// https://github.com/launchbadge/sqlx/issues/2567
fn get_connection_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .test_before_acquire(true)
        .connect_lazy(url)
        .unwrap()
}

/// Create a new test database
///
/// There are quite a few approaches that work (or don't work) for having
/// test isolation for us.
/// 1. Have each test use a transaction (or a set of transactions). This
///    works for many tests, since they only need one connection to the
///    database in order for the test to work as designed. Tests that check
///    that the collection of signers can complete a task don't work well
///    with the sqlx::Transaction object, so this approach doesn't work.
/// 2. Do the above, but have each transaction connect to its own
///    database. This actually works, and it's not clear why.
/// 3. Have each test use a new pool to a new database. This works as well.
pub async fn new_test_database() -> PgStore {
    // We create a new connection to the default database each time this
    // function is called, because we depend on all connections to this
    // database being closed before it begins.
    let postgres_url = format!("{}/postgres", DATABASE_URL_BASE);
    let pool = get_connection_pool(&postgres_url);

    sqlx::query("CREATE SEQUENCE IF NOT EXISTS db_num_seq;")
        .execute(&pool)
        .await
        .unwrap();

    let db_num: i64 = sqlx::query_scalar("SELECT nextval('db_num_seq');")
        .fetch_one(&pool)
        .await
        .unwrap();

    let db_name = format!("signer_test_{}", db_num);

    let create_db = format!("CREATE DATABASE \"{db_name}\" WITH OWNER = 'postgres';");

    sqlx::query(&create_db)
        .execute(&pool)
        .await
        .expect("failed to create test database");

    let test_db_url = format!("{}/{}", DATABASE_URL_BASE, db_name);
    // In order to create a new database from another database, there
    // cannot exist any other connections to that database. So we
    // explicitly close this connection. See the notes section in the docs
    // <https://www.postgresql.org/docs/16/sql-createdatabase.html>
    pool.close().await;

    let store = PgStore::connect(&test_db_url).await.unwrap();
    store
        .apply_migrations()
        .await
        .expect("failed to apply db migrations");
    store
}

/// When we are done with the test, we need to delete any test databases
/// that were created. This is so that we do not run out of space on the CI
/// server.
pub async fn drop_db(store: PgStore) {
    if let Some(db_name) = store.pool().connect_options().get_database() {
        // This is not a test database, we should not close it
        if db_name == "postgres" {
            return;
        }

        let postgres_url = format!("{}/postgres", DATABASE_URL_BASE);
        let pool = get_connection_pool(&postgres_url);

        // FORCE closes all connections to the database if there are any
        // and then drops the database.
        let drop_db = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
        sqlx::query(&drop_db)
            .execute(&pool)
            .await
            .expect("failed to drop test database");
    }
}

/// This is a helper function for waiting for the database to be up-to-date
/// with the chain-tip of the bitcoin blockchain.
///
/// A typical need for this function arises when we need to wait for
/// bitcoin-core to send us all the notifications so that we are up to date
/// with the chain tip. This occurs because the first message that we
/// process from the ZeroMQ socket need not be the last one sent by
/// bitcoin-core.
pub async fn wait_for_chain_tip<D>(db: &D, chain_tip: BitcoinBlockHash)
where
    D: DbRead + Clone,
{
    let mut current_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap();

    let waiting_fut = async {
        let db = db.clone();
        while current_chain_tip != Some(chain_tip) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            current_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap();
        }
    };

    // Wrap in a timeout just in case the block observer crashes and
    // can no longer update the database.
    tokio::time::timeout(Duration::from_secs(10), waiting_fut)
        .await
        .unwrap();
}

/// This is a helper function for waiting for the database to have a row in
/// the dkg_shares, signaling that DKG has finished successfully.
pub async fn wait_for_dkg(db: &PgStore, count: u32) {
    let waiting_fut = async {
        let db = db.clone();
        while db.get_encrypted_dkg_shares_count().await.unwrap() < count {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    tokio::time::timeout(Duration::from_secs(10), waiting_fut)
        .await
        .unwrap();
}

/// Extension trait for [`DbWrite`] that provides additional methods for
/// testing purposes.
pub trait DbWriteTestExt {
    /// Helper function to write multiple bitcoin blocks to the database and
    /// panics if any errors are encountered.
    ///
    /// ## Examples:
    /// ```
    /// # use crate::testing::storage::DbWriteExt;
    /// # use crate::storage::model::BitcoinBlock;
    /// # use crate::storage::model::StacksBlock;
    ///
    /// db.write_bitcoin_blocks(
    ///     [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
    /// )
    /// .await;
    /// ```
    fn write_bitcoin_blocks<'a, I>(&self, blocks: I) -> impl Future<Output = ()> + Send
    where
        I: IntoIterator<Item = &'a BitcoinBlock> + Send + Sync + 'a,
        I::IntoIter: Send + Sync;

    /// Helper function to write multiple stacks blocks to the database and
    /// panics if any errors are encountered.
    ///
    /// ## Examples:
    /// ```
    /// # use crate::testing::storage::DbWriteExt;
    /// # use crate::storage::model::BitcoinBlock;
    /// # use crate::storage::model::StacksBlock;
    ///
    /// db.write_stacks_blocks(
    ///     [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
    /// )
    /// .await;
    /// ```
    fn write_stacks_blocks<'a, I>(&self, blocks: I) -> impl Future<Output = ()> + Send
    where
        I: IntoIterator<Item = &'a StacksBlock> + Send + Sync + 'a,
        I::IntoIter: Send + Sync;

    /// Helper function to write multiple bitcoin and stacks blocks to the
    /// database and panics if any errors are encountered.
    ///
    /// ## Examples:
    /// ```
    /// # use crate::testing::storage::DbWriteExt;
    /// # use crate::storage::model::BitcoinBlock;
    /// # use crate::storage::model::StacksBlock;
    ///
    /// db.write_blocks(
    ///     [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
    ///     [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
    /// )
    /// .await;
    /// ```
    fn write_blocks<'a, IB, IS>(
        &self,
        bitcoin_blocks: IB,
        stacks_blocks: IS,
    ) -> impl Future<Output = ()> + Send
    where
        IB: IntoIterator<Item = &'a BitcoinBlock> + Send + Sync + 'a,
        IB::IntoIter: Send + Sync,
        IS: IntoIterator<Item = &'a StacksBlock> + Send + Sync + 'a,
        IS::IntoIter: Send + Sync;
}

/// Extension trait for [`DbRead`] that provides additional methods for
/// testing purposes.
pub trait DbReadTestExt {
    /// Helper function to get both bitcoin and stacks chain tips from the
    /// database and panics on error.
    ///
    /// ## Examples:
    /// ```
    /// # use crate::testing::storage::DbReadExt;
    ///
    /// let (bitcoin_tip, stacks_tip) = db.get_chain_tips().await;
    /// ```
    fn get_chain_tips(&self) -> impl Future<Output = (BitcoinBlockRef, StacksBlockHash)> + Send;
}

/// Implement the [`DbWriteExt`] trait for all types that implement [`DbWrite`].
impl<T> DbWriteTestExt for T
where
    T: DbWrite + DbRead + Send + Sync + 'static,
{
    async fn write_bitcoin_blocks<'a, I>(&self, blocks: I)
    where
        I: IntoIterator<Item = &'a BitcoinBlock>,
    {
        for block in blocks {
            self.write_bitcoin_block(block)
                .await
                .expect("failed to write bitcoin block");
        }
    }

    async fn write_stacks_blocks<'a, I>(&self, blocks: I)
    where
        I: IntoIterator<Item = &'a StacksBlock>,
    {
        for block in blocks {
            self.write_stacks_block(block)
                .await
                .expect("failed to write stacks block");
        }
    }

    async fn write_blocks<'a, IB, IS>(&self, bitcoin_blocks: IB, stacks_blocks: IS)
    where
        IB: IntoIterator<Item = &'a BitcoinBlock> + Send + Sync + 'a,
        IB::IntoIter: Send + Sync,
        IS: IntoIterator<Item = &'a StacksBlock> + Send + Sync + 'a,
        IS::IntoIter: Send + Sync,
    {
        self.write_bitcoin_blocks(bitcoin_blocks).await;
        self.write_stacks_blocks(stacks_blocks).await;
    }
}

/// Implement the [`DbReadExt`] trait for all types that implement [`DbRead`].
impl<T> DbReadTestExt for T
where
    T: DbRead + Send + Sync + 'static,
{
    async fn get_chain_tips(&self) -> (BitcoinBlockRef, StacksBlockHash) {
        let bitcoin_tip = self
            .get_bitcoin_canonical_chain_tip_ref()
            .await
            .expect("db error: error when retrieving bitcoin chain tip")
            .expect("no bitcoin chain tip found");

        let stacks_tip = self
            .get_stacks_chain_tip(&bitcoin_tip.block_hash)
            .await
            .expect("db error: error when retrieving stacks chain tip")
            .expect("no stacks chain tip found")
            .block_hash;

        (bitcoin_tip, stacks_tip)
    }
}
