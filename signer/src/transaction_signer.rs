//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`EventLoop`] documentation.

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction signer event loop
///
/// This struct contains the implementation of the transaction signer logic.
/// The event loop subscribes to storage update notifications from the block observer,
/// and listens to signer messages from the signer network.
///
/// ## On block observer notification
///
/// When the signer receives a notification from the block observer, indicating that
/// new blocks have been added to the signer state, it must go over each of the pending
/// requests and decide whether to accept or reject it. The decision is then persisted
/// and broadcast to the other signers. The following flowchart illustrates the flow.
///
/// ```mermaid
/// flowchart TD
///     SU{Block observer notification} --> FPR(Fetch pending requests)
///     FPR --> NR(Next request)
///     NR --> |deposit/withdraw| DAR(Decide to accept/reject)
///     NR ----> |none| DONE{Done}
///     DAR --> PD(Persist decision)
///     PD --> BD(Broadcast decision)
///     BD --> NR
/// ```
///
/// ## On signer message
///
/// When the signer receives a message from another signer, it needs to do a few different things
/// depending on the type of the message.
///
/// - **Signer decision**: When receiving a signer decision, the transaction signer
/// only needs to persist the decision to its database.
/// - **Stacks sign request**: When receiving a request to sign a stacks transaction,
/// the signer must verify that it has decided to sign the transaction, and if it has,
/// send a transaction signature back over the network.
/// - **Bitcoin sign request**: When receiving a request to sign a bitcoin transaction,
/// the signer must verify that it has decided to accept all requests that the
/// transaction fulfills. Once verified, the transaction signer creates a dedicated
/// WSTS state machine to participate in a signing round for this transaction. Thereafter,
/// the signer sends a bitcoin transaction sign ack message back over the network to signal
/// its readiness.
/// - **WSTS message**: When receiving a WSTS message, the signer will look up the corresponding
/// state machine and dispatch the WSTS message to it.
///
/// The following flowchart illustrates the process.
///
/// ```mermaid
/// flowchart TD
///     SM{Signer message received} --> |Signer decision| PD(Persist decision)
///
///     SM --> |Stacks sign request| CD1(Check decision)
///     CD1 --> SS(Send signature)
///
///     SM --> |Bitcoin sign request| CD2(Check decision)
///     CD2 --> WSM(Create WSTS state machine)
///     WSM --> ACK(Send Ack message)
///
///     SM --> |WSTS message| RWSM(Relay to WSTS state machine)
/// ```
pub struct EventLoop;

impl EventLoop {
    /// Run the signer event loop
    pub async fn run() {}
}
