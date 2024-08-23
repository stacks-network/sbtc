//! Test utilities for the `storage` module

use std::sync::atomic::AtomicU16;

use crate::storage::postgres::PgStore;

pub mod model;

/// The postgres connection string to the test database.
pub const DATABASE_URL: &str = "postgres://user@localhost:5432/signer";

/// This is needed to make sure that each test has as many isolated
/// databases as it needs.
pub static DATABASE_NUM: AtomicU16 = AtomicU16::new(0);

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
pub async fn new_test_database(db_num: u16) -> PgStore {
    let db_name = format!("test_db_{db_num}");

    // We create a new connection to the default database each time this
    // function is called, because we depend on all connections to this
    // database being closed before it begins.
    let pool = get_connection_pool(DATABASE_URL);

    // We need to manually check if it exists and drop it if it does.
    let db_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT TRUE FROM pg_database WHERE datname = $1)",
    )
    .bind(&db_name)
    .fetch_one(&pool)
    .await
    .unwrap();

    if db_exists {
        // FORCE closes all connections to the database if there are any
        // and then drops the database.
        let drop_db = format!("DROP DATABASE \"{db_name}\" WITH (FORCE)");
        sqlx::query(&drop_db)
            .execute(&pool)
            .await
            .expect("failed to create test database");
    }
    let create_db = format!("CREATE DATABASE \"{db_name}\" TEMPLATE signer");

    sqlx::query(&create_db)
        .execute(&pool)
        .await
        .expect("failed to create test database");

    let test_db_url = DATABASE_URL.replace("signer", &db_name);
    // In order to create a new database from another database, there
    // cannot exist any other connections to that database. So we
    // explicitly close this connection. See the notes section in the docs
    // <https://www.postgresql.org/docs/16/sql-createdatabase.html>
    pool.close().await;

    let pool = get_connection_pool(&test_db_url);
    PgStore::from(pool)
}

/// When we are done with the test, we need to delete any test databases
/// that were created. This is so that we do not run out of space on the CI
/// server.
pub async fn drop_db(store: PgStore) {
    if let Some(db_name) = store.pool().connect_options().get_database() {
        // This is not a test database, we should not close it
        if db_name == "signer" {
            return;
        }
        // Might as well.
        store.pool().close().await;
        let pool = get_connection_pool(DATABASE_URL);

        // FORCE closes all connections to the database if there are any
        // and then drops the database.
        let drop_db = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
        sqlx::query(&drop_db)
            .execute(&pool)
            .await
            .expect("failed to create test database");
    }
}
