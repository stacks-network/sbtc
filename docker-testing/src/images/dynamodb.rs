use std::{net::IpAddr, time::Duration};

use testcontainers::{
    core::ContainerPort, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt,
};
use url::{Host, Url};

use crate::{error::Error, images::container_name};

const CONTAINER_PORT: u16 = 8000;
const CONTAINER_NAME: &str = "dynamodb";

pub struct DynamoDb {
    container: ContainerAsync<GenericImage>,
    bridge_ip: IpAddr,
    host: Host,
    host_port: u16,
}

impl DynamoDb {
    pub async fn start() -> Result<DynamoDb, Error> {
        let container_name = container_name(CONTAINER_NAME);
        let dynamodb = GenericImage::new("amazon/dynamodb-local", "latest")
            .with_mapped_port(0, ContainerPort::Tcp(8000))
            .with_cmd(vec![
                "-jar",
                "DynamoDBLocal.jar",
                "-sharedDb",
                "-dbPath",
                ".",
            ])
            .with_container_name(&container_name)
            .pull_image()
            .await?
            .start()
            .await?;

        let host = dynamodb.get_host().await?;
        let host_port = dynamodb.get_host_port_ipv4(CONTAINER_PORT).await?;
        let bridge_ip = dynamodb.get_bridge_ip_address().await?;

        super::wait_for_tcp_connectivity(&host.to_string(), host_port, Duration::from_secs(5))
            .await;

        Ok(Self {
            container: dynamodb,
            bridge_ip,
            host,
            host_port,
        })
    }

    pub fn container_endpoint(&self) -> Result<Url, Error> {
        let endpoint = format!("http://{}:{CONTAINER_PORT}", self.bridge_ip);
        Url::parse(&endpoint).map_err(Error::UrlParse)
    }

    pub fn host_endpoint(&self) -> Result<Url, Error> {
        let endpoint = format!("http://{}:{}", self.host, self.host_port);
        Url::parse(&endpoint).map_err(Error::UrlParse)
    }

    pub async fn stop(self) -> Result<(), Error> {
        self.container.stop().await.map_err(Error::TestContainers)
    }
}
