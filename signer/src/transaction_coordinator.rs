//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for consctructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`EventLoop`] documentation.

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction coordinator event loop
///
/// This struct contains the implementation of the transaction coordinator logic.
/// Like the transaction signer, the coordinator event loop also subscribes to storage
/// update notifications from the block observer and listends to signer messages over
/// the signer network.
///
/// The transaction coordinator will upon receving a storage update notification from
/// the block observer look up the canonical chain tip from the database. This tip
/// is used to decide wheter or not this particular coordinator is selected to be active
/// or if it should be passive in favor of another coordinator in the signer network.
///
/// If the coordinator is selected, it will begin by looking up the signer UTXO, and
/// do a fee rate estimation for both Bitcoin and Stacks. With that in place it will
/// proceed to look up any pending[^1] and active[^2] requests to process.
///
/// The pending requests are used to construct a transaction package, which is a set of bitcoin
/// transactions fulfilling a subset of the requests. Which pending requests that end up in the
/// transaction package depends on the amount of singers deciding to accept the request, and on
/// the maximum fee allowed in the requests. Once the package has been constructed, the
/// coordinator proceeds by coordinating WSTS signing rounds for each of the transactions in the
/// package. The signed transactions are then broadcasted to bitcoin.
///
/// For the active requests, the coordinator will go over each one and create appropriate
/// response transactions. These transactions are sent through the signers for signatures, and
/// once enough signatures has been gathered, the coordinator broadcasts them to the Stacks
/// blockchain.
///
/// [^1]: A deposit or withdraw request is considered pending if it is confirmed on chain but hasn't been processed by the signers.
/// [^2]: A deposit or withdraw request is considered active if has been processed by the signers, but the result hasn't been acknowledged on Stacks as a `deposit_accept`, `withdraw_accept` or `withdraw_reject` transaction.
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
pub struct EventLoop;
