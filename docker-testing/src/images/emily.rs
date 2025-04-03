use std::time::Duration;

use testcontainers::{
    core::{wait::ExitWaitStrategy, ContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use url::{Host, Url};

use crate::{error::Error, images::dynamodb::DynamoDb, logging};

use super::container_name;

pub struct Emily {
    dynamodb: DynamoDb,
    emily_server: ContainerAsync<GenericImage>,
    host: Host,
    port: u16,
}

impl Emily {
    pub async fn start() -> Result<Emily, Error> {
        let dynamodb = DynamoDb::start().await?;
        let dynamodb_container_endpoint = dynamodb.container_endpoint()?;

        let aws_setup_wait_strategy = WaitFor::Exit(
            ExitWaitStrategy::default()
                .with_exit_code(0)
                .with_poll_interval(Duration::from_millis(50)),
        );
        GenericImage::new("docker-emily-aws-setup", "latest")
            .with_wait_for(aws_setup_wait_strategy)
            .with_container_name(container_name("emily-aws-setup"))
            .with_env_var("DYNAMODB_ENDPOINT", dynamodb_container_endpoint.as_str())
            .with_env_var("TRUSTED_REORG_API_KEY", "")
            .with_env_var("DEPLOYER_ADDRESS", "")
            .with_log_consumer(logging::SimpleLogConsumer::new())
            .start()
            .await?;

        let emily_server = GenericImage::new("docker-emily-server", "latest")
            .with_mapped_port(0, ContainerPort::Tcp(3031))
            .with_container_name(container_name("emily-server"))
            .with_env_var("DYNAMODB_ENDPOINT", dynamodb_container_endpoint.as_str())
            .with_env_var("AWS_ACCESS_KEY_ID", "xxxxxxxxxxxx")
            .with_env_var("AWS_SECRET_ACCESS_KEY", "xxxxxxxxxxxx")
            .with_env_var("AWS_REGION", "us-west-2")
            .with_env_var("PORT", "3031")
            .with_log_consumer(logging::SimpleLogConsumer::new())
            .start()
            .await?;

        let emily_host = emily_server.get_host().await?;
        let emily_port = emily_server.get_host_port_ipv4(3031).await?;
        super::wait_for_tcp_connectivity(
            &emily_host.to_string(),
            emily_port,
            Duration::from_secs(5),
        )
        .await;

        eprintln!(
            "emily server available at http://{}:{}",
            emily_host, emily_port
        );

        // A short wait just to ensure the http listener is ready
        tokio::time::sleep(Duration::from_millis(250)).await;

        Ok(Self {
            dynamodb,
            emily_server,
            host: emily_host,
            port: emily_port,
        })
    }

    #[allow(unused)]
    async fn stop(self) -> Result<(), Error> {
        self.dynamodb.stop().await?;
        self.emily_server.stop().await?;
        Ok(())
    }

    pub fn endpoint(&self) -> Url {
        Url::parse(&format!(
            "http://testApiKey@{host}:{port}",
            host = self.host,
            port = self.port
        ))
        .expect("failed to parse emily endpoint")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "utility test for manually verifying that the emily docker setup works"]
    #[tokio::test]
    async fn test_emily() {
        let emily = Emily::start().await.expect("failed to start emily server");
        let emily_host = emily.emily_server.get_host().await.unwrap();
        let emily_port = emily.emily_server.get_host_port_ipv4(3031).await.unwrap();

        println!("emily host: {}", emily_host);
        println!("emily port: {}", emily_port);

        emily.emily_server.stop().await.unwrap();
        emily.dynamodb.stop().await.unwrap();
    }
}
