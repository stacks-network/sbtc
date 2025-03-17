//! Helper logic for working with multiaddresses.

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

/// Extensions for [`Multiaddr`].
pub trait MultiaddrExt {
    /// Returns `true` if the multiaddress uses the TCP transport protocol.
    fn is_tcp(&self) -> bool;
    /// Returns `true` if the multiaddress uses the QUIC transport protocol.
    fn is_quic(&self) -> bool;
    /// Returns `true` if the multiaddress uses the in-memory transport protocol.
    fn is_memory(&self) -> bool;
    /// Returns the transport protocol used by the multiaddress, or `None` if no
    /// supported transport protocol was found.
    fn get_transport_protocol(&self) -> Option<Protocol>;
    /// If the P2P protocol is present, return a new [`Multiaddr`] with the P2P
    /// protocol stripped. Otherwise, return a clone of the original
    /// [`Multiaddr`] (which is shallow as it uses a [`std::sync::Arc<Vec<u8>>`]
    /// internally).
    fn without_p2p_protocol(&self) -> Self;
}

impl MultiaddrExt for Multiaddr {
    fn is_tcp(&self) -> bool {
        let mut parts = self.iter();
        matches!(
            (parts.next(), parts.next()),
            (
                Some(Protocol::Ip4(_))
                    | Some(Protocol::Ip6(_))
                    | Some(Protocol::Dns(_))
                    | Some(Protocol::Dns4(_))
                    | Some(Protocol::Dns6(_))
                    | Some(Protocol::Dnsaddr(_)),
                Some(Protocol::Tcp(_))
            )
        )
    }

    fn is_quic(&self) -> bool {
        let mut parts = self.iter();
        matches!(
            (parts.next(), parts.next(), parts.next()),
            (
                Some(Protocol::Ip4(_))
                    | Some(Protocol::Ip6(_))
                    | Some(Protocol::Dns(_))
                    | Some(Protocol::Dns4(_))
                    | Some(Protocol::Dns6(_))
                    | Some(Protocol::Dnsaddr(_)),
                Some(Protocol::Udp(_)),
                Some(Protocol::Quic) | Some(Protocol::QuicV1)
            )
        )
    }

    fn is_memory(&self) -> bool {
        let mut parts = self.iter();
        matches!(parts.next(), Some(Protocol::Memory(_)))
    }

    fn get_transport_protocol(&self) -> Option<Protocol> {
        let mut parts = self.iter();
        parts.find(|part| {
            matches!(
                part,
                Protocol::Tcp(_) | Protocol::QuicV1 | Protocol::Quic | Protocol::Memory(_)
            )
        })
    }

    fn without_p2p_protocol(&self) -> Self {
        // If the last protocol is not P2P, return a clone of the original
        // (which is shallow as it uses a `std::sync::Arc<Vec<u8>>` internally).
        if !matches!(self.iter().last(), Some(Protocol::P2p(_))) {
            return self.clone();
        }

        let mut addr = Multiaddr::empty();
        for part in self.iter() {
            if matches!(part, Protocol::P2p(_)) {
                break;
            }
            addr.push(part.clone());
        }
        addr
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use libp2p::multiaddr::Protocol;
    use libp2p::{Multiaddr, PeerId};

    use super::*;

    const IP4_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const IP6_LOOPBACK: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

    #[test]
    fn test_is_tcp() {
        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(multiaddr.is_tcp(), "ip4 + tcp");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(multiaddr.is_tcp(), "ip6 + tcp");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Tcp(8080));
        assert!(multiaddr.is_tcp(), "dns + tcp");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Udp(8080));
        assert!(!multiaddr.is_tcp(), "ip6 + udp");

        let multiaddr = Multiaddr::empty().with(Protocol::Memory(123));
        assert!(!multiaddr.is_tcp(), "memory");
    }

    #[test]
    fn test_is_quic() {
        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Udp(8080))
            .with(Protocol::QuicV1);
        assert!(multiaddr.is_quic(), "ip4 + udp + quicv1");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Udp(8080))
            .with(Protocol::QuicV1);
        assert!(multiaddr.is_quic(), "ip6 + udp + quicv1");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Udp(8080))
            .with(Protocol::QuicV1);
        assert!(multiaddr.is_quic(), "dns + udp + quicv1");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(!multiaddr.is_quic(), "ip4 + tcp");

        let multiaddr = Multiaddr::empty().with(Protocol::Memory(123));
        assert!(!multiaddr.is_quic(), "memory");
    }

    #[test]
    fn test_is_memory() {
        let multiaddr = Multiaddr::empty().with(Protocol::Memory(123));
        assert!(multiaddr.is_memory(), "memory");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(!multiaddr.is_memory(), "ip4 + tcp");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(!multiaddr.is_memory(), "ip6 + tcp");

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Tcp(8080));
        assert!(!multiaddr.is_memory(), "dns + tcp");
    }

    #[test]
    fn test_get_transport_protocol() {
        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(
            matches!(multiaddr.get_transport_protocol(), Some(Protocol::Tcp(_))),
            "ip4 + tcp"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert!(
            matches!(multiaddr.get_transport_protocol(), Some(Protocol::Tcp(_))),
            "ip6 + tcp"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Tcp(8080));
        assert!(
            matches!(multiaddr.get_transport_protocol(), Some(Protocol::Tcp(_))),
            "dns + tcp"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Udp(8080))
            .with(Protocol::QuicV1);
        assert!(
            matches!(multiaddr.get_transport_protocol(), Some(Protocol::QuicV1)),
            "ip4 + udp"
        );

        let multiaddr = Multiaddr::empty().with(Protocol::Memory(123));
        assert!(
            matches!(
                multiaddr.get_transport_protocol(),
                Some(Protocol::Memory(_))
            ),
            "memory"
        );
    }

    #[test]
    fn test_without_p2p_protocol() {
        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080))
            .with(Protocol::P2p(PeerId::random()));
        let expected = Multiaddr::empty()
            .with(Protocol::Ip4(IP4_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert_eq!(
            multiaddr.without_p2p_protocol(),
            expected,
            "ip4 + tcp + p2p"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Tcp(8080))
            .with(Protocol::P2p(PeerId::random()));
        let expected = Multiaddr::empty()
            .with(Protocol::Ip6(IP6_LOOPBACK))
            .with(Protocol::Tcp(8080));
        assert_eq!(
            multiaddr.without_p2p_protocol(),
            expected,
            "ip6 + tcp + p2p"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Tcp(8080))
            .with(Protocol::P2p(PeerId::random()));
        let expected = Multiaddr::empty()
            .with(Protocol::Dns("localhost".into()))
            .with(Protocol::Tcp(8080));
        assert_eq!(
            multiaddr.without_p2p_protocol(),
            expected,
            "dns + tcp + p2p"
        );

        let multiaddr = Multiaddr::empty()
            .with(Protocol::Memory(123))
            .with(Protocol::P2p(PeerId::random()));
        let expected = Multiaddr::empty().with(Protocol::Memory(123));
        assert_eq!(multiaddr.without_p2p_protocol(), expected, "memory + p2p");
    }
}
