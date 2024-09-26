#![deny(missing_docs)]

//! # SBTC Common Library
//!
//! This library provides common functionality for the sBTC project, including logging setup
use std::sync::LazyLock;

use bitcoin::XOnlyPublicKey;

pub mod deposits;
pub mod error;

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

/// Returns an address with no known private key, since it has no known
/// discrete logarithm.
///
/// # Notes
///
/// This function returns the public key to used in the key-spend path of
/// the taproot address. Since we do not want a key-spend path for sBTC
/// deposit transactions, this address is such that it does not have a
/// known private key.
pub static UNSPENDABLE_TAPROOT_KEY: LazyLock<XOnlyPublicKey> =
    LazyLock::new(|| XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE).unwrap());
