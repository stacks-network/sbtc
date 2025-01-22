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
    LazyLock::new(|| XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE).unwrap());
