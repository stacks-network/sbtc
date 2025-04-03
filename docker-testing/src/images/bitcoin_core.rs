use std::time::Duration;

use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use testcontainers::core::ContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers::GenericImage;
use testcontainers::ImageExt;
use url::Host;
use url::Url;

use crate::error::Error;
use crate::logging;

use super::container_name;
use super::DEFAULT_BITCOIN_CORE_TAG;

pub struct BitcoinCore<S = ()> {
    container: ContainerAsync<GenericImage>,
    host: Host,
    rpc_port: u16,
    zmq_port: u16,
    rpc_endpoint: Url,
    rpc_client: bitcoincore_rpc::Client,
    state: S,
}

impl BitcoinCore<()> {
    pub async fn start() -> Result<BitcoinCore<()>, Error> {
        Self::start_with_state(()).await
    }
}

impl<S> BitcoinCore<S> {
    /// The username for RPC calls in bitcoin-core
    pub const RPC_USERNAME: &str = "devnet";
    /// The password for RPC calls in bitcoin-core
    pub const RPC_PASSWORD: &str = "devnet";
    /// The port for RPC calls in bitcoin-core
    pub const RPC_PORT: u16 = 18443;
    /// The default port for ZMQ notifications in bitcoin-core
    pub const ZMQ_PORT: u16 = 28332;

    pub async fn start_with_state(state: S) -> Result<BitcoinCore<S>, Error> {
        let wait_strategy = WaitFor::message_on_stdout("dnsseed thread exit");
        let cmd: Vec<String> = vec![
            "-chain=regtest".into(),
            "-server".into(),
            "-rpcbind=0.0.0.0".into(),
            format!("-rpcuser={}", Self::RPC_USERNAME),
            format!("-rpcpassword={}", Self::RPC_PASSWORD),
            "-rpcallowip=0.0.0.0/0".into(),
            "-rpcallowip=::/0".into(),
            "-txindex".into(),
            "-zmqpubhashblock=tcp://*:28332".into(),
            "-zmqpubrawblock=tcp://*:28332".into(),
            "-fallbackfee=0.00001".into(),
        ];

        let bitcoind = GenericImage::new("bitcoin/bitcoin", DEFAULT_BITCOIN_CORE_TAG)
            .with_wait_for(wait_strategy)
            .with_entrypoint("/opt/bitcoin-28.1/bin/bitcoind")
            .with_cmd(cmd)
            .with_container_name(container_name("bitcoind"))
            .with_mapped_port(0, ContainerPort::Tcp(Self::RPC_PORT))
            .with_mapped_port(0, ContainerPort::Tcp(Self::ZMQ_PORT))
            .with_log_consumer(logging::SimpleLogConsumer::new())
            .with_startup_timeout(Duration::from_secs(5))
            .start()
            .await?;

        let host = bitcoind.get_host().await?;
        let rpc_port = bitcoind.get_host_port_ipv4(Self::RPC_PORT).await?;
        let zmq_port = bitcoind.get_host_port_ipv4(Self::ZMQ_PORT).await?;
        let rpc_endpoint = Url::parse(&format!("http://{}:{rpc_port}", host))?;

        let host_str = host.to_string();
        let check_rpc = tokio::spawn(async move {
            super::wait_for_tcp_connectivity(&host_str, rpc_port, Duration::from_secs(5)).await;
        });

        let host_str = host.to_string();
        let check_zmq = tokio::spawn(async move {
            super::wait_for_tcp_connectivity(&host_str, zmq_port, Duration::from_secs(5)).await;
        });

        tokio::try_join!(check_rpc, check_zmq).map_err(|_| Error::StartupConnectivityTimeout)?;

        // Create a client which is used for the `as_ref()` implementation,
        // returning a reference to the client.
        let auth = Auth::UserPass(Self::RPC_USERNAME.into(), Self::RPC_PASSWORD.into());
        let rpc_client = Client::new(rpc_endpoint.as_str(), auth).map_err(Error::BitcoinCoreRpc)?;

        Ok(Self {
            container: bitcoind,
            host,
            rpc_port,
            zmq_port,
            rpc_endpoint,
            rpc_client,
            state,
        })
    }

    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn rpc_endpoint(&self) -> &Url {
        &self.rpc_endpoint
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    pub fn rpc_host(&self) -> &url::Host {
        &self.host
    }

    #[allow(unused)]
    /// Create a new client for the bitcoin-core RPC interface
    pub fn rpc_client(&self) -> Result<bitcoincore_rpc::Client, Error> {
        let auth = Auth::UserPass(Self::RPC_USERNAME.into(), Self::RPC_PASSWORD.into());
        Client::new(self.rpc_endpoint.as_str(), auth).map_err(Error::BitcoinCoreRpc)
    }

    pub fn zmq_endpoint(&self) -> Url {
        let url = format!(
            "tcp://{host}:{port}",
            host = self.host,
            port = self.zmq_port
        );
        Url::parse(&url).unwrap()
    }

    pub async fn stop(self) -> Result<(), Error> {
        self.container.stop().await.map_err(Error::TestContainers)
    }

    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S> AsRef<Client> for BitcoinCore<S> {
    fn as_ref(&self) -> &Client {
        &self.rpc_client
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::{bitcoin::Network, RpcApi};

    use super::*;

    #[ignore = "utility test for manually verifying that the bitcoind docker setup works"]
    #[tokio::test]
    async fn test_bitcoind() {
        let bitcoind = BitcoinCore::start()
            .await
            .expect("failed to start bitcoind");

        let client = bitcoind.rpc_client().expect("failed to create rpc client");
        let info = client.get_blockchain_info().expect("failed to query node");
        assert_eq!(info.chain, Network::Regtest);

        dbg!(info);
    }
}
