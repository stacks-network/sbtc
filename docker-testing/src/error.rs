#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TestContainers(#[from] testcontainers::TestcontainersError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    BitcoinCoreRpc(#[from] bitcoincore_rpc::Error),

    #[error("connectivity checks did not succeed within the allotted time")]
    StartupConnectivityTimeout,
}
