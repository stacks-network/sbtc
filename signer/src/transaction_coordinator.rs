//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for consctructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`TxCoordinatorEventLoop`] documentation.

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction coordinator event loop
///
/// This struct contains the implementation of the transaction coordinator logic.
/// Like the transaction signer, the coordinator event loop also subscribes to storage
/// update notifications from the block observer and listens to signer messages over
/// the signer network.
///
/// The transaction coordinator will look up the canonical chain tip from
/// the database upon receiving a storage update notification from the
/// block observer. This tip is used to decide whether this particular
/// signer is selected as the signers' coordinator or if it should be
/// passive in favor of another signer as the coordinator in the signer
/// network.
///
/// When the coordinator is selected, that coordinator will begin by looking up the signer UTXO, and
/// do a fee rate estimation for both Bitcoin and Stacks. With that in place it will
/// proceed to look up any pending[^1] and active[^2] requests to process.
///
/// The pending requests are used to construct a transaction package, which is a set of bitcoin
/// transactions fulfilling a subset of the requests. Which pending requests that end up in the
/// transaction package depends on the amount of singers deciding to accept the request, and on
/// the maximum fee allowed in the requests. Once the package has been constructed, the
/// coordinator proceeds by coordinating WSTS signing rounds for each of the transactions in the
/// package. The signed transactions are then broadcast to bitcoin.

/// Pending deposit and withdrawal requests are used to construct a Bitcoin
/// transaction package consisting of a set of inputs and outputs that
/// fulfill these requests. The fulfillment of pending requests in the
/// transaction package depends on the number of signers agreeing to accept
/// each request and the maximum fee stipulated in the request. Once the
/// package is assembled, the coordinator coordinates WSTS signing rounds for
/// each transaction within the package. The successfully signed
/// transactions are then broadcast to the Bitcoin network.
///
/// For the active requests, the coordinator will go over each one and create appropriate
/// stacks response transactions (which are the `withdrawal-accept`, `withdrawal-reject`
/// and `deposit-accept` contract calls). These transactions are sent through the
/// signers for signatures, and once enough signatures has been gathered,
/// the coordinator broadcasts them to the Stacks blockchain.
///
/// [^1]: A deposit or withdraw request is considered pending if it is confirmed
///       on chain but hasn't been fulfilled in an sBTC transaction yet.
/// [^2]: A deposit or withdraw request is considered active if has been fulfilled in an sBTC transaction,
///       but the result hasn't been acknowledged on Stacks as a `deposit-accept`,
///       `withdraw-accept` or `withdraw-reject` transaction.
///
/// The whole flow is illustrated in the following flowchart.
///
/// ```mermaid
/// flowchart TD
///     SM[Block observer notification] --> GCT(Get canonical chain tip)
///     GCT --> ISC{Is selected?}
///     ISC --> |No| DONE[Done]
///     ISC --> |Yes| GSU(Get signer UTXO)
///     GSU --> ESF(Estimate fee rates)
///
///     ESF --> GPR(Get accepted pending requests)
///     GPR --> CTP(Compute transaction package)
///     CTP --> CSR(Coordinate signing rounds)
///     CSR --> BST(Broadcast signed transactions)
///
///     ESF --> GAR(Get active requests)
///     GAR --> CRT(Construct response transactions)
///     CRT --> CMS(Coordinate multisig signature gather)
///     CMS --> BST
///     BST --> DONE
/// ```
pub struct TxCoordinatorEventLoop;
