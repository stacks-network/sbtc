//! Request structures for deposit api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Common request structures.
pub mod requests;

// Common Types ----------------------------------------------------------------

/// The status of the in-flight sBTC operation.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Transaction hasn't yet been addressed by the sBTC Signers.
    #[default]
    Pending,
    /// Transaction was dealt with by the signers at one point but is now being
    /// reprocessed. The Signers are aware of the operation request.
    Reprocessing,
    /// Transaction has been seen and accepted by the sBTC Signers, but is not
    /// yet included in any on chain artifact. The transaction can still fail
    /// at this point if the Signers fail to include the transaciton in an on
    /// chain artifact.
    ///
    /// For example, a deposit or withdrawal that has specified too low of a
    /// BTC fee may fail after being accepted.
    Accepted,
    /// The articacts that fulill the operation have been observed in a valid fork of
    /// both the Stacks blockchain and the Bitcoin blockchain by at least one signer.
    ///
    /// Note that if the signers detect a conflicting chainstate in which the operation
    /// is not confirmed this status will be reverted to either ACCEPTED or REEVALUATING
    /// depending on whether the conflicting chainstate calls the acceptance into question.
    Confirmed,
    /// The operation was not fulfilled.
    Failed,
}

/// Data about the fulfillment of an sBTC Operation.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "PascalCase")]
pub struct Fulfillment {
    /// Bitcoin transaction id of the Bitcoin transaction that fulfilled the operation.
    pub bitcoin_txid: String,
    /// Bitcoin transaction output index of the Bitcoin transaction that fulfilled the
    /// operation that corresponds to the fulfillment of this specific operation.
    pub bitcoin_tx_index: u32,
    /// Stacks transaction Id that fulfilled this operation.
    pub stacks_txid: String,
    /// Bitcoin block hash of the block that contains the bitcoin transaction that fulfilled
    /// this transaction.
    pub bitcoin_block_hash: String,
    /// Bitcoin block height of the block that contains the bitcoin transaction that fulfilled
    /// this transaction.
    pub bitcoin_block_height: u64,
    /// Satoshis consumed to fulfill the sBTC operation.
    pub btc_fee: u64,
}
