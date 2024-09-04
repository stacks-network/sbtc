use std::net::ToSocketAddrs;

use libp2p::multiaddr::Protocol;
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
                // NOTE: The `.with()` calls are ordered, so the order in which
                // they are called matters.
                let mut multiaddr = Multiaddr::empty().with(Protocol::from(addr.ip()));

                if self.scheme() == "quic-v1" {
                    multiaddr = multiaddr.with(Protocol::Udp(port));
                    multiaddr = multiaddr.with(Protocol::QuicV1);
                } else if self.scheme() == "tcp" {
                    multiaddr = multiaddr.with(Protocol::Tcp(port));
                }

                multiaddrs.push(multiaddr);
            }
        }

        Ok(multiaddrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_localhost() {
        let url = Url::parse("tcp://localhost:1234").unwrap();
        // NOTE: This only resolves to the local IPv4 address.
        let multiaddrs = url.try_into_multiaddrs().unwrap();
        assert!(multiaddrs.len() > 0);
        assert!(multiaddrs.contains(&"/ip4/127.0.0.1/tcp/1234".parse().unwrap()));
    }

    /// This test uses example.com, which is a [IANA reserved domain name](https://www.iana.org/help/example-domains).
    /// Hopefully the IP addresses for example.com will not change anytime soon,
    /// but if they do, this test will fail.
    ///
    /// This test requires an internet connection or that you've added the following to your `/etc/hosts` file:
    /// ```plaintext
    /// 127.0.0.1 example.com
    /// 2606:2800:21f:cb07:6820:80da:af6b:8b2c example.com
    /// ```
    #[test]
    fn test_resolve_example_dot_com() {
        let url = Url::parse("tcp://example.com:1234").unwrap();
        let multiaddrs = url.try_into_multiaddrs().unwrap();
        dbg!(multiaddrs.clone());
        assert!(multiaddrs.len() > 0);
        assert!(multiaddrs.contains(&"/ip4/93.184.215.14/tcp/1234".parse().unwrap()));
        assert!(multiaddrs.contains(
            &"/ip6/2606:2800:21f:cb07:6820:80da:af6b:8b2c/tcp/1234"
                .parse()
                .unwrap()
        ));
    }
}
