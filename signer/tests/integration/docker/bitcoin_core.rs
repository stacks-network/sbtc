use std::ops::Deref;
use std::time::Duration;

use bitcoincore_rpc::RpcApi;
use sbtc::testing::regtest;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::util::ApiFallbackClient;
use testcontainers::core::ContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers::Image;
use testcontainers::ImageExt;
use tokio_stream::wrappers::ReceiverStream;
use url::Url;

use super::container_name;
use super::DEFAULT_BITCOIN_CORE_TAG;

const STARTUP_TIMEOUT_MILLIS: u64 = 1500;

pub struct BitcoinCore {
    image_tag: &'static str,
    exposed_ports: Vec<ContainerPort>,
}

impl BitcoinCore {
    pub async fn start() -> BitcoinCoreContainer {
        let bitcoind = BitcoinCore {
            image_tag: DEFAULT_BITCOIN_CORE_TAG,
            exposed_ports: vec![ContainerPort::Tcp(18443), ContainerPort::Tcp(28332)],
        }
        .with_container_name(container_name("bitcoind"))
        .with_mapped_port(0, ContainerPort::Tcp(18443))
        .with_mapped_port(0, ContainerPort::Tcp(28332));

        let bitcoind = bitcoind.start().await.expect("failed to start bitcoind");
        let container = BitcoinCoreContainer::new(bitcoind).await;

        container
    }
}

impl Image for BitcoinCore {
    fn name(&self) -> &str {
        "bitcoin/bitcoin"
    }

    fn tag(&self) -> &str {
        self.image_tag
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stdout("dnsseed thread exit")]
    }

    fn entrypoint(&self) -> Option<&str> {
        Some("/bin/bash")
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        vec![
            "-c".to_owned(),
            format!("bitcoind -chain=regtest -server -rpcbind=0.0.0.0 -rpcuser={rpcuser} -rpcpassword={rpcpassword} -rpcallowip=0.0.0.0/0 -rpcallowip=::/0 -txindex -zmqpubhashblock='tcp://*:28332' -zmqpubrawblock='tcp://*:28332' -fallbackfee=0.00001 ",
                rpcuser = regtest::BITCOIN_CORE_RPC_USERNAME,
                rpcpassword = regtest::BITCOIN_CORE_RPC_PASSWORD
            ),
        ]
    }
}

pub struct BitcoinCoreContainer {
    container: ContainerAsync<BitcoinCore>,
    host: String,
    rpc_username: String,
    rpc_password: String,
    rpc_port: u16,
    zmq_port: u16,
    client: BitcoinCoreClient,
}

impl BitcoinCoreContainer {
    async fn new(container: ContainerAsync<BitcoinCore>) -> Self {
        let host = container.get_host().await.unwrap().to_string();
        let rpc_port = container.get_host_port_ipv4(18443).await.unwrap();
        let zmq_port = container.get_host_port_ipv4(28332).await.unwrap();

        let client = BitcoinCoreClient::new(
            format!("http://{host}:{rpc_port}").as_str(),
            regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
            regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
        )
        .expect("failed to create new bitcoin core client");

        Self {
            container,
            host,
            rpc_username: regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
            rpc_password: regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
            rpc_port,
            zmq_port,
            client,
        }
    }

    pub fn rpc_endpoint(&self) -> Url {
        let url = format!(
            "http://{username}:{password}@{host}:{port}",
            username = self.rpc_username,
            password = self.rpc_password,
            host = self.host,
            port = self.rpc_port
        );
        Url::parse(&url).unwrap()
    }

    pub fn zmq_endpoint(&self) -> Url {
        let url = format!(
            "tcp://{host}:{port}",
            host = self.host,
            port = self.zmq_port
        );
        Url::parse(&url).unwrap()
    }

    pub async fn zmq_block_hash_stream(
        &self,
    ) -> ReceiverStream<Result<bitcoin::BlockHash, signer::error::Error>> {
        signer::testing::btc::new_zmq_block_hash_stream(self.zmq_endpoint().as_str()).await
    }

    pub fn client(&self) -> BitcoinCoreClient {
        self.client.clone()
    }

    #[allow(unused)]
    pub fn rpc_client(&self) -> &bitcoincore_rpc::Client {
        self.client.inner_client()
    }

    #[allow(unused)]
    pub fn fallback_client(&self) -> ApiFallbackClient<BitcoinCoreClient> {
        ApiFallbackClient::new(vec![self.client()])
            .expect("failed to create new api fallback client")
    }

    #[allow(unused)]
    pub fn container(&self) -> &ContainerAsync<BitcoinCore> {
        &self.container
    }

    pub fn initialize_blockchain(&self) -> &regtest::Faucet {
        let (_, faucet) = regtest::initialize_blockchain_at(self.rpc_endpoint().as_str());
        faucet
    }
}

impl Deref for BitcoinCoreContainer {
    type Target = BitcoinCoreClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[ignore = "Utility test for manual verification/debugging of the BitcoinCoreContainer"]
#[test_log::test(tokio::test)]
async fn test_bitcoind() {
    let bitcoind = BitcoinCore::start().await;

    let client = bitcoind.client();

    let info = client.inner_client().get_blockchain_info().unwrap();

    dbg!(info);
}
