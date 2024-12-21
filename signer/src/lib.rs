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
pub const MAX_TX_PER_BITCOIN_BLOCK: i64 = 25;

/// This is the dust limit for deposits in the sBTC smart contracts.
/// Deposit amounts that is less than this amount will be rejected by the
/// smart contract.
pub const DEPOSIT_DUST_LIMIT: u64 = 546;

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
