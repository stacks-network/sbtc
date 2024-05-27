//! # Signer storage
//!
//! This module contains the `Read` and `Write` traits representing
//! the interface between the signer and their internal database.
//!
//! The canonical implementation of these traits is the [`postgres::PgStore`]
//! allowing the signer to use a Postgres database to store data.

pub mod in_memory;
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
    ) -> impl Future<Output = Result<Option<model::BitcoinBlock>, Self::Error>> + Send;
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

impl<'a, T> Read for &'a mut T
where
    &'a T: Read,
    T: Send,
{
    type Error = <&'a T as Read>::Error;

    async fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        (&*self).get_bitcoin_block(block_hash).await
    }
}

impl<'a, T> Write for &'a mut T
where
    &'a T: Write,
    T: Send,
{
    type Error = <&'a T as Write>::Error;

    async fn write_bitcoin_block(self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        (&*self).write_bitcoin_block(block).await
    }
}
