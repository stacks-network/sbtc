//! Test utilities for working with Docker containers.

use std::future::Future;

use bitcoin::BlockHash;
use sbtc_docker_testing::images::BitcoinCore;
use tokio_stream::wrappers::ReceiverStream;

use crate::{bitcoin::rpc::BitcoinCoreClient, error::Error};

use super::btc::new_zmq_block_hash_stream;

/// Test extension trait for `BitcoinCore`.
pub trait BitcoinCoreTestExt {
    /// Returns a new [`BitcoinCoreClient`] pointed at the RPC endpoint of the
    /// [`BitcoinCore`] instance.
    fn client(&self) -> BitcoinCoreClient;
    /// Returns a stream of block hashes from the ZMQ endpoint of the
    /// [`BitcoinCore`] instance.
    fn zmq_block_hash_stream(
        &self,
    ) -> impl Future<Output = ReceiverStream<Result<BlockHash, Error>>>;
}

impl<S> BitcoinCoreTestExt for BitcoinCore<S> {
    fn client(&self) -> BitcoinCoreClient {
        BitcoinCoreClient::new(
            self.rpc_endpoint().as_str(),
            Self::RPC_USERNAME.into(),
            Self::RPC_PASSWORD.into(),
        )
        .expect("failed to construct BitcoinCoreClient")
    }

    async fn zmq_block_hash_stream(&self) -> ReceiverStream<Result<BlockHash, Error>> {
        new_zmq_block_hash_stream(self.zmq_endpoint().as_str()).await
    }
}
