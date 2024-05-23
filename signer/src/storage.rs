//! # Signer storage
//!
//! This module contains the `Read` and `Write` traits representing
//! the interface between the signer and their internal database.
//!
//! The canonical implementation of these traits is the [`postgres::PgStore`]
//! allowing the signer to use a Postgres database to store data.

pub mod model;
pub mod postgres;

use std::future::Future;

/// Represents the ability to read data from the signer storage.
pub trait Read {
    /// Read error.
    type Error;

    /// Get the bitcoin block with the given block hash.
    fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> impl Future<Output = Result<model::BitcoinBlock, Self::Error>> + Send;
}

/// Represents the ability to write data to the signer storage.
pub trait Write {
    /// Write error.
    type Error;

    /// Write a bitcoin block.
    fn write_bitcoin_block(
        self,
        block: &model::BitcoinBlock,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
