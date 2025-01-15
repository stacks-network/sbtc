
use bitcoincore_rpc::RpcApi;
use sbtc::testing::regtest;
use signer::bitcoin::rpc::BitcoinCoreClient;
use testcontainers::core::ContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers::Image;
use url::Url;

pub struct BitcoinCore {
    exposed_ports: Vec<ContainerPort>,
}

impl BitcoinCore {
    pub async fn start() -> BitcoinCoreContainer {
        let bitcoind = BitcoinCore {
            exposed_ports: vec![ContainerPort::Tcp(18443), ContainerPort::Tcp(28332)],
        };
        let bitcoind = bitcoind.start().await.expect("failed to start bitcoind");
        BitcoinCoreContainer::new(bitcoind).await
    }
}

impl Image for BitcoinCore {
    fn name(&self) -> &str {
        "bitcoin/bitcoin"
    }
    
    fn tag(&self) -> &str {
        "28"
    }
    
    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stdout("dnsseed thread exit")]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &self.exposed_ports
    }
    
    fn entrypoint(&self) -> Option<&str> {
        Some("/bin/bash")
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        vec![
            "-c".to_owned(),
            format!("bitcoind -chain=regtest -server -rpcbind=0.0.0.0 -rpcuser={rpcuser} -rpcpassword={rpcpassword} -rpcallowip=0.0.0.0/0 -rpcallowip=::/0 -txindex -zmqpubhashblock='tcp://*:28332' -zmqpubrawblock='tcp://*:28332'",
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
}

impl BitcoinCoreContainer {
    async fn new(container: ContainerAsync<BitcoinCore>) -> Self {
        let host = container.get_host().await.unwrap().to_string();
        let rpc_port = container.get_host_port_ipv4(18443).await.unwrap();
        let zmq_port = container.get_host_port_ipv4(28332).await.unwrap();

        Self {
            container,
            host,
            rpc_username: regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
            rpc_password: regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
            rpc_port,
            zmq_port,
        }
    }

    pub fn get_rpc_endpoint(&self) -> Url {
        let url = format!("http://{username}:{password}@{host}:{port}", 
            username = self.rpc_username, 
            password = self.rpc_password, 
            host = self.host, 
            port = self.rpc_port
        );
        Url::parse(&url).unwrap()
    }

    pub fn get_zmq_endpoint(&self) -> Url {
        let url = format!("tcp://{host}:{port}", host = self.host, port = self.zmq_port);
        Url::parse(&url).unwrap()
    }

    pub fn get_client(&self) -> BitcoinCoreClient {
        BitcoinCoreClient::new(
            self.get_rpc_endpoint().as_str(),
            self.rpc_username.clone(),
            self.rpc_password.clone(),
        )
        .unwrap()
    }

    pub fn get_container(&self) -> &ContainerAsync<BitcoinCore> {
        &self.container
    }

    pub fn initialize_blockchain(&self) -> &regtest::Faucet {
        let (_, faucet) = regtest::initialize_blockchain_at(self.get_rpc_endpoint().as_str());
        faucet
    }
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_log::test(tokio::test)]
async fn test_bitcoind() {
    let bitcoind = BitcoinCore::start().await;
    
    let client = bitcoind.get_client();

    let info = client.inner_client().get_blockchain_info().unwrap();
    dbg!(info);
}