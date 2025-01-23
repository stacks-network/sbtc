#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(
    clippy::unwrap_in_result,
    // clippy::unwrap_used, // TODO: There's one unwrap left
    // clippy::expect_used, // TODO: There's 14 expects left
)]

pub mod api;
pub mod bitcoin;
pub mod block_observer;
pub mod blocklist_client;
pub mod codec;
pub mod config;
pub mod context;
pub mod ecdsa;
pub mod emily_client;
pub mod error;
pub mod keys;
pub mod logging;
pub mod message;
pub mod metrics;
pub mod network;
pub mod proto;
pub mod request_decider;
pub mod signature;
pub mod stacks;
pub mod storage;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod transaction_coordinator;
pub mod transaction_signer;
pub mod util;
pub mod wsts_state_machine;

/// Package version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The maximum number of keys in the signers multi-sig wallet on Stacks.
///
/// There are a few practical limits on the maximum number of distinct
/// public keys:
/// 1. The maximum number of signatures allowed in a stacks transaction is
///    capped at u16::MAX, which is 65535.
/// 2. The maximum amount of data that can be sent as input into a clarity
///    contract call is capped at 1 MB. That limits the maximum number of
///    keys to ~31K.
/// 3. The signer bitmap in the clarity contract can take only 128 signers.
/// 4. The rotate-keys-wrapper public function in one of the clarity
///    contracts takes a maximum of 128 keys.
const MAX_KEYS: u16 = 128;

/// Each deposit has a reclaim script spend path that can be executed after
/// some "time". Right now this "time", the locktime, can only be
/// denominated in bitcoin blocks. Once locktime number of blocks have been
/// added to the blockchain after the deposit has been confirmed, the
/// depositor can reclaim the deposit transaction. Signers will not attempt
/// to sweep in the deposited funds if the number of blocks left is less
/// than or equal to this value.
///
/// If the current chain tip is at height 1000, the reclaim script on a
/// deposit can be spent on or after block 1001, and this constant value is
/// set to 1, then the signers WOULD NOT attempt to sweep the deposit. If
/// it were spendable on block 1002, then the signers WOULD attempt to sweep
/// the deposit.
pub const DEPOSIT_LOCKTIME_BLOCK_BUFFER: u16 = 3;

/// This is the capacity of the channel used for messages sent within the
/// signer.
pub const SIGNER_CHANNEL_CAPACITY: usize = 1024;

/// The maximum number of blocks that can be affected by a reorg on the
/// bitcoin blockchain. This is used when adding a buffer when searching
/// for the signers UTXO.
pub const MAX_REORG_BLOCK_COUNT: i64 = 10;

/// The maximum number of sweep transactions that the signers can confirm
/// per block.
///
/// This is the default maximum number of transactions in a transaction
/// package in the bitcoin mempool. This value is configurable in bitcoin
/// core as the `limitancestorcount` and/or `limitdescendantcount` limits.
///
/// <https://github.com/bitcoin/bitcoin/blob/228aba2c4d9ac0b2ca3edd3c2cdf0a92e55f669b/doc/policy/mempool-limits.md>
/// <https://bitcoincore.reviews/21800>
/// <https://github.com/bitcoin/bitcoin/blob/v25.0/src/policy/policy.h#L58-L59>
pub const MAX_MEMPOOL_PACKAGE_TX_COUNT: u64 = 25;

/// The default maximum number of deposit inputs per bitcoin transaction.
///
/// The default here is chosen so that there is a ~50% chance that the
/// signers finish signing all bitcoin inputs, before the arrival of the
/// next bitcoin block. This assumes signing rounds take ~16 seconds.
pub const DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX: u16 = 25;

/// This is the dust limit for deposits in the sBTC smart contracts.
/// Deposit amounts that is less than this amount will be rejected by the
/// smart contract.
pub const DEPOSIT_DUST_LIMIT: u64 = 546;

/// This is the default maximum virtual size of a bitcoin transaction
/// package. This value is the default limit set in bitcoin core, and
/// corresponds to the `limitancestorsize` and/or `limitdescendantsize`
/// configurable limits.
///
/// <https://github.com/bitcoin/bitcoin/blob/228aba2c4d9ac0b2ca3edd3c2cdf0a92e55f669b/doc/policy/mempool-limits.md>
/// <https://bitcoincore.reviews/21800>
/// <https://github.com/bitcoin/bitcoin/blob/v25.0/src/policy/policy.h#L60-L61>
pub const MAX_MEMPOOL_PACKAGE_SIZE: u64 = 101000;

/// This is an upper bound on the number of signer state machines that we
/// "could" need if we wanted to sign all inputs in parallel and running
/// DKG.
///
/// If the entire transaction package was nothing but donation inputs then
/// we would need this many state machines to sign the transaction in
/// parallel. We need to add one for DKG, hence plus 1. We then add a
/// little buff by going to the next power of 2.
pub const MAX_SIGNER_STATE_MACHINES: u64 = MAX_MEMPOOL_PACKAGE_SIZE
    .div_ceil(MIN_BITCOIN_INPUT_VSIZE)
    .saturating_add(1)
    .next_power_of_two();

/// This is the vsize of a signed key-spend taproot input on bitcoin, which
/// should be the smallest vsize that a signed taproot input could have on
/// bitcoin.
pub const MIN_BITCOIN_INPUT_VSIZE: u64 = 58;

/// These are all build info variables. Many of them are set in build.rs.

/// The name of the binary that is being run,
pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
/// The target environment ABI of the signer binary build.
pub const TARGET_ENV_ABI: &str = env!("CARGO_CFG_TARGET_ENV");
/// The CPU target architecture of the signer binary build.
pub const TARGET_ARCH: &str = env!("CARGO_CFG_TARGET_ARCH");
/// The version of rustc used to build the signer binary.
pub const RUSTC_VERSION: &str = env!("RUSTC_VERSION");
/// The git sha that the binary was built from.
pub const GIT_COMMIT: &str = env!("GIT_COMMIT");
