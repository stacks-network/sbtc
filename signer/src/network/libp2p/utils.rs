use std::net::ToSocketAddrs;

use libp2p::Multiaddr;
use url::Url;

use super::errors::SignerSwarmError;
use super::DEFAULT_P2P_PORT;

/// A trait for converting a value into a vector of [`Multiaddr`]s.
pub trait TryIntoMultiAddrs {
    /// Attempts to convert the value into a vector of [`Multiaddr`]s.
    #[allow(dead_code)]
    fn try_into_multiaddrs(&self) -> Result<Vec<Multiaddr>, SignerSwarmError>;
}

impl TryIntoMultiAddrs for Url {
    fn try_into_multiaddrs(&self) -> Result<Vec<Multiaddr>, SignerSwarmError> {
        eprintln!("url: {:?}", self);
        let host = self
            .host_str()
            .ok_or(SignerSwarmError::Builder("host cannot be empty"))?;

        if !["tcp", "quic-v1"].contains(&self.scheme()) {
            return Err(SignerSwarmError::Builder(
                "Only `tcp` and `quic-v1` schemes are supported",
            ));
        }

        let port = if let Some(p) = self.port() {
            p
        } else {
            DEFAULT_P2P_PORT
        };

        let mut multiaddrs: Vec<Multiaddr> = Vec::new();

        if let Ok(addrs) = format!("{host}:{port}").to_socket_addrs() {
            for addr in addrs {
                let multiaddr_str = format!(
                    "/{}/{}/{}/{}",
                    if addr.is_ipv6() { "ip6" } else { "ip4" },
                    addr.ip(),
                    self.scheme(),
                    addr.port()
                );
                eprintln!("multiaddr_str: {:?}", multiaddr_str);
                let multiaddr = multiaddr_str.parse()?;
                eprintln!("parsed multiaddr: {:?}", multiaddr);
                multiaddrs.push(multiaddr);
            }
        }

        Ok(multiaddrs)
    }
}
