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

use super::container_name;
use super::DEFAULT_BITCOIN_CORE_TAG;

pub struct BitcoinCore {
    container: ContainerAsync<GenericImage>,
    host: Host,
    rpc_port: u16,
    zmq_port: u16,
    rpc_client: Client,
}

impl BitcoinCore {
    /// The username for RPC calls in bitcoin-core
    pub const RPC_USERNAME: &str = "devnet";
    /// The password for RPC calls in bitcoin-core
    pub const RPC_PASSWORD: &str = "devnet";
    /// The port for RPC calls in bitcoin-core
    pub const RPC_PORT: u16 = 18443;
    /// The default port for ZMQ notifications in bitcoin-core
    pub const ZMQ_PORT: u16 = 28332;

    pub async fn start() -> Result<BitcoinCore, Error> {
        let wait_strategy = WaitFor::message_on_stdout("dnsseed thread exit");
        let cmd: Vec<String> = vec![
            "-c".into(),
            "bitcoind".into(),
            "-chain=regtest".into(),
            "-server".into(),
            "-rpcbind=0.0.0.0".into(),
            format!("-rpcuser={}", Self::RPC_USERNAME),
            format!("-rpcpassword={}", Self::RPC_PASSWORD),
            "-rpcallowip=0.0.0.0/0".into(),
            "-rpcallowip=::/0".into(),
            "-txindex".into(),
            "-zmqpubhashblock='tcp://*:28332'".into(),
            "-zmqpubrawblock='tcp://*:28332'".into(),
            "-fallbackfee=0.00001".into(),
        ];

        let bitcoind = GenericImage::new("bitcoin/bitcoin", DEFAULT_BITCOIN_CORE_TAG)
            .with_wait_for(wait_strategy)
            .with_entrypoint("/bin/bash")
            .with_cmd(cmd)
            .with_container_name(container_name("bitcoind"))
            .with_mapped_port(0, ContainerPort::Tcp(Self::RPC_PORT))
            .with_mapped_port(0, ContainerPort::Tcp(Self::ZMQ_PORT))
            .with_startup_timeout(Duration::from_secs(5))
            .start()
            .await?;

        let host = bitcoind.get_host().await?;
        let rpc_port = bitcoind.get_host_port_ipv4(Self::RPC_PORT).await?;
        let zmq_port = bitcoind.get_host_port_ipv4(Self::ZMQ_PORT).await?;

        let auth = Auth::UserPass(Self::RPC_USERNAME.into(), Self::RPC_PASSWORD.into());
        let rpc_client = Client::new("http://localhost:18443", auth).unwrap();

        Ok(Self {
            container: bitcoind,
            host,
            rpc_port,
            zmq_port,
            rpc_client,
        })
    }

    pub fn rpc_endpoint(&self) -> Url {
        let url = format!(
            "http://{username}:{password}@{host}:{port}",
            username = Self::RPC_USERNAME,
            password = Self::RPC_PASSWORD,
            host = self.host,
            port = self.rpc_port
        );
        Url::parse(&url).unwrap()
    }

    #[allow(unused)]
    pub fn rpc_client(&self) -> &bitcoincore_rpc::Client {
        &self.rpc_client
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
}

impl AsRef<Client> for BitcoinCore {
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

        let client = bitcoind.rpc_client();

        let info = client.get_blockchain_info().unwrap();
        assert_eq!(info.chain, Network::Regtest);

        dbg!(info);
    }
}
