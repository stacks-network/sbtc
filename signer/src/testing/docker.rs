//! Test utilities for working with Docker containers.

use sbtc_docker_testing::images::BitcoinCore;

use crate::bitcoin::rpc::BitcoinCoreClient;

/// Test extension trait for `BitcoinCore`.
pub trait BitcoinCoreTestExt {
    /// Returns a new [`BitcoinCoreClient`] pointed at the RPC endpoint of the
    /// [`BitcoinCore`] instance.
    fn client(&self) -> BitcoinCoreClient;
}

impl BitcoinCoreTestExt for BitcoinCore {
    fn client(&self) -> BitcoinCoreClient {
        BitcoinCoreClient::new(
            self.rpc_endpoint().as_str(),
            BitcoinCore::RPC_USERNAME.into(),
            BitcoinCore::RPC_PASSWORD.into(),
        )
        .expect("failed to construct BitcoinCoreClient")
    }
}
