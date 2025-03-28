use std::{net::IpAddr, str::FromStr};

use clarity::{types::chainstate::StacksAddress, vm::types::PrincipalData};
use libp2p::Multiaddr;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::keys::PrivateKey;

use super::error::SignerConfigError;

/// A deserializer for the url::Url type. This will return an empty [`Vec`] if
/// there are no URLs to deserialize.
pub fn url_deserializer_vec<'de, D>(deserializer: D) -> Result<Vec<url::Url>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = Vec::new();
    for s in Vec::<String>::deserialize(deserializer)? {
        v.push(s.parse().map_err(serde::de::Error::custom)?);
    }
    Ok(v)
}

/// A deserializer for the url::Url type. Does not support deserializing a list,
/// only a single URL.
pub fn url_deserializer_single<'de, D>(deserializer: D) -> Result<url::Url, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// A deserializer for the std::time::Duration type.
/// Serde includes a default deserializer, but it expects a struct.
pub fn duration_seconds_deserializer<'de, D>(
    deserializer: D,
) -> Result<std::time::Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(std::time::Duration::from_secs(
        u64::deserialize(deserializer).map_err(serde::de::Error::custom)?,
    ))
}

/// A deserializer for the std::time::Duration type.
/// Serde includes a default deserializer, but it expects a struct.
pub fn duration_milliseconds_deserializer<'de, D>(
    deserializer: D,
) -> Result<std::time::Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(std::time::Duration::from_millis(
        u64::deserialize(deserializer).map_err(serde::de::Error::custom)?,
    ))
}

pub fn p2p_multiaddr_deserializer_vec<'de, D>(deserializer: D) -> Result<Vec<Multiaddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut addrs = Vec::new();

    let items = Vec::<String>::deserialize(deserializer)?;

    for s in items.iter().filter(|s| !s.is_empty()) {
        let addr = try_parse_p2p_multiaddr(s).map_err(serde::de::Error::custom)?;
        addrs.push(addr);
    }

    Ok(addrs)
}

/// A deserializer for the [`PrivateKey`] type. Returns an error if the private
/// key is not valid hex or is not the correct length.
pub fn private_key_deserializer<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let len = s.len();

    if ![64, 66].contains(&len) {
        Err(serde::de::Error::custom(
            SignerConfigError::InvalidStacksPrivateKeyLength(len),
        ))
    } else if len == 66 && &s[64..] != "01" {
        Err(serde::de::Error::custom(
            SignerConfigError::InvalidStacksPrivateKeyCompressionByte(s[64..].to_string()),
        ))
    } else {
        PrivateKey::from_str(&s[..64]).map_err(serde::de::Error::custom)
    }
}

pub fn try_parse_p2p_multiaddr(s: &str) -> Result<Multiaddr, SignerConfigError> {
    // Keeping these local here as this is the only place these should need to be used.
    use SignerConfigError::{
        InvalidP2PScheme, InvalidP2PUri, P2PHostRequired, P2PPasswordNotSupported,
        P2PPathsNotSupported, P2PPortRequired, P2PQueryStringsNotSupported,
        P2PUsernameNotSupported,
    };
    use libp2p::multiaddr::Protocol;

    // We parse to a Url first to take advantage of its initial validation
    // and so that we can more easily work with the URI components below.
    // Note that this will catch missing host errors.
    let url: Url = s.parse().map_err(InvalidP2PUri)?;

    if !["/", ""].contains(&url.path()) {
        return Err(P2PPathsNotSupported(url.path().into()));
    }

    let port = url.port().ok_or(P2PPortRequired)?;

    // We only support tcp and quic-v1 schemes as these are the only relevant
    // protocols (quic is a UDP-based protocol).
    if !["tcp", "quic-v1"].contains(&url.scheme()) {
        return Err(InvalidP2PScheme(url.scheme().into()));
    }

    // We don't currently support usernames. The signer pub key is used as the
    // peer identifier.
    if !url.username().is_empty() {
        return Err(P2PUsernameNotSupported(url.username().into()));
    }

    // We don't currently support passwords.
    if let Some(pass) = url.password() {
        return Err(P2PPasswordNotSupported(pass.into()));
    }

    // We don't currently support query strings. This could be extended in the
    // future if we need to add additional P2P configuration options.
    if let Some(query) = url.query() {
        return Err(P2PQueryStringsNotSupported(query.into()));
    }

    // Initialize the Multiaddr using the host. We support IPv4, IPv6, and
    // DNS host types. The URL parsing in `Url` doesn't seem to return the
    // correct type of address in `url.host()` (i.e. `0.0.0.0` ends up as a DNS
    // host), and thus an invalid Multiaddr. We work around this by parsing the
    // host string directly.
    let host_str = url
        .host_str()
        .ok_or(P2PHostRequired)?
        .trim_matches(['[', ']']); // `Url` includes brackets for IPv6 addresses

    let mut addr = if let Ok(addr) = IpAddr::from_str(host_str) {
        Multiaddr::empty().with(Protocol::from(addr))
    } else {
        Multiaddr::empty().with(Protocol::Dns(url.host_str().unwrap_or_default().into()))
    };

    // Update the Multiaddr with the correct protocol.
    match url.scheme() {
        "tcp" => addr = addr.with(Protocol::Tcp(port)),
        "quic-v1" => addr = addr.with(Protocol::Udp(port)).with(Protocol::QuicV1),
        s => return Err(InvalidP2PScheme(s.to_string())),
    };

    Ok(addr)
}

/// Parse the string into a StacksAddress.
///
/// The [`StacksAddress`] struct does not implement any string parsing or
/// c32 decoding. However, the [`PrincipalData::parse_standard_principal`]
/// function does the expected c32 decoding and the validation, so we go
/// through that.
pub fn parse_stacks_address<'de, D>(des: D) -> Result<StacksAddress, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let literal = <String>::deserialize(des)?;

    PrincipalData::parse_standard_principal(&literal)
        .map(StacksAddress::from)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_parse_p2p_multiaddr_ipv6_inaddr_any() {
        let addr = try_parse_p2p_multiaddr("tcp://[::]:4122/")
            .expect("failed to parse valid IPv6 address");
        assert_eq!(addr.to_string(), "/ip6/::/tcp/4122");
    }

    #[test]
    fn try_parse_p2p_multiaddr_ipv6_loopback() {
        let addr = try_parse_p2p_multiaddr("tcp://[::1]:4122/")
            .expect("failed to parse valid IPv6 address");
        assert_eq!(addr.to_string(), "/ip6/::1/tcp/4122");
    }

    #[test]
    fn try_parse_p2p_multiaddr_ipv6_long() {
        let addr = try_parse_p2p_multiaddr("tcp://[2001:db8:456:1122:a334:23fe:ff23:9988]:4122/")
            .expect("failed to parse valid IPv6 address");
        assert_eq!(
            addr.to_string(),
            "/ip6/2001:db8:456:1122:a334:23fe:ff23:9988/tcp/4122"
        );
    }

    #[test]
    fn try_parse_p2p_multiaddr_ipv4() {
        let addr = try_parse_p2p_multiaddr("tcp://0.0.0.0:4122/")
            .expect("failed to parse valid IPv4 address");
        assert_eq!(addr.to_string(), "/ip4/0.0.0.0/tcp/4122");
    }

    #[test]
    fn try_parse_p2p_multiaddr_dns_localhost() {
        let addr = try_parse_p2p_multiaddr("tcp://localhost:4122/")
            .expect("failed to parse valid DNS address");
        assert_eq!(addr.to_string(), "/dns/localhost/tcp/4122");
    }

    #[test]
    fn try_parse_p2p_multiaddr_dns_domain() {
        let addr = try_parse_p2p_multiaddr("tcp://example.com:4122/")
            .expect("failed to parse valid DNS address");
        assert_eq!(addr.to_string(), "/dns/example.com/tcp/4122");
    }
}
