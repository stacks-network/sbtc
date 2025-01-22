#![deny(missing_docs)]

//! # SBTC Common Library
//!
//! This library provides common functionality for the sBTC project, including logging setup
use std::sync::LazyLock;

use bitcoin::XOnlyPublicKey;

pub mod deposits;
pub mod error;
pub mod events;

#[cfg(feature = "webhooks")]
pub mod webhooks;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// The x-coordinate public key with no known discrete logarithm.
///
/// # Notes
///
/// This particular X-coordinate was discussed in the original taproot BIP
/// on spending rules BIP-0341[1]. Specifically, the X-coordinate is formed
/// by taking the hash of the standard uncompressed encoding of the 
/// secp256k1 base point G as the X-coordinate. In that BIP the authors
/// wrote the X-coordinate that is reproduced below.
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
#[rustfmt::skip] 
pub const NUMS_X_COORDINATE: [u8; 32] = [ 
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
];

/// This is the pubkey, derived from `NUMS_X_COORDINATE` using the derivation path "0/0".
#[rustfmt::skip]
pub const DERIVED_NUMS_X_COORDINATE: [u8; 32] = [
    0x4a ,0x30 ,0xb2 ,0xe4 ,0x61 ,0xb2 ,0x80, 0xc0,
    0xb1, 0x3a, 0x03, 0x79, 0x90, 0x96, 0xab, 0x12,
    0x56, 0x58, 0x91, 0x53, 0xfc, 0x4b, 0x9c, 0x8c,
    0xea, 0xd1, 0x6d, 0xc0, 0xb6, 0x42, 0x06, 0x97,
];

/// Returns a public key with no known private key, since it has no known
/// discrete logarithm.
///
/// # Notes
///
/// This function returns the public key to used in the key-spend path of
/// the taproot `scriptPubKey`. Since we do not want a key-spend path for
/// sBTC deposit transactions, this public key is such that it does not
/// have a known private key.
pub static UNSPENDABLE_TAPROOT_KEY: LazyLock<XOnlyPublicKey> =
    LazyLock::new(|| XOnlyPublicKey::from_slice(&DERIVED_NUMS_X_COORDINATE).unwrap());

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
    use secp256k1::{PublicKey, Secp256k1};
    use std::str::FromStr;

    /// This test proves, that the DERIVED_NUMS_X_COORDINATE is the correct,
    /// and is derived from the NUMS_X_COORDINATE using the derivation path "0/0".
    #[test]
    fn test_derivation() {
        let path = DerivationPath::from_str("0/0").unwrap();
        let secp = Secp256k1::new();
        let bip32master = Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Fingerprint::from(&[0u8; 4]),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: PublicKey::from_x_only_public_key(
                XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE).unwrap(),
                secp256k1::Parity::Even,
            ),
            chain_code: ChainCode::from(&[0u8; 32]),
        };
        let derived_pubkey = bip32master.derive_pub(&secp, &path).unwrap();
        let derived_bytes = derived_pubkey.to_x_only_pub().serialize();
        assert_eq!(derived_bytes, DERIVED_NUMS_X_COORDINATE);
    }
}
