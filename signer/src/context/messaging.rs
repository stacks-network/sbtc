//! This module contains types related to the application's internal
//! messaging via the [`Context`].

/// Signals that can be sent within the signer binary.
#[derive(Debug, Clone, PartialEq)]
pub enum SignerSignal {
    /// Send a command to the application.
    Command(SignerCommand),
    /// Signal an event to the application.
    Event(SignerEvent),
}

impl SignerSignal {
    /// Return the message that was generated from a [`TxSignerEventLoop`]
    /// task and None otherwise.
    pub fn tx_signer_generated(self) -> Option<crate::network::Msg> {
        match self {
            Self::Event(SignerEvent::TxSigner(TxSignerEvent::MessageGenerated(msg))) => Some(msg),
            _ => None,
        }
    }
}

/// Commands that can be sent on the signalling channel.
#[derive(Debug, Clone, PartialEq)]
pub enum SignerCommand {
    /// Signals to the application to publish a message to the P2P network.
    P2PPublish(crate::network::Msg),
}

/// Events that can be received on the signalling channel.
#[derive(Debug, Clone, PartialEq)]
pub enum SignerEvent {
    /// Signals that a P2P event has occurred.
    P2P(P2PEvent),
    /// Signals that a block observer event has occurred.
    BitcoinBlockObserved,
    /// Transaction signer events
    TxSigner(TxSignerEvent),
    /// Transaction coordinator events
    TxCoordinator(TxCoordinatorEvent),
}

/// Events that can be triggered from the P2P network.
#[derive(Debug, Clone, PartialEq)]
pub enum P2PEvent {
    /// Signals to the application that the P2P publish failed for the given message.
    PublishFailure(crate::network::MsgId),
    /// Signals to the application that the P2P publish for the given message id
    /// was successful.
    PublishSuccess(crate::network::MsgId),
    /// Signals to the application that a message was received from the P2P network.
    MessageReceived(crate::network::Msg),
    /// Signals to the application that a new peer has connected to the P2P network.
    PeerConnected(libp2p::PeerId),
}

/// Events that can be triggered from the transaction signer.
#[derive(Debug, Clone, PartialEq)]
pub enum TxSignerEvent {
    /// Received a deposit decision
    ReceivedDepositDecision,
    /// Received a withdrawal decision
    ReceivedWithdrawalDecision,
    /// A new pending withdrawal request has been handled.
    PendingWithdrawalRequestRegistered,
    /// A new pending deposit request has been handled.
    PendingDepositRequestRegistered,
    /// New pending requests have been handled. This is primarily used as a
    /// trigger for the transaction coordinator to process the new blocks.
    NewRequestsHandled,
    /// Event which occurs when the transaction signer has sent a message to
    /// the P2P network.
    MessageGenerated(crate::network::Msg),
    /// Event which occurs when the transaction signer has started its event
    /// loop.
    EventLoopStarted,
}

/// Events that can be triggered from the transaction coordinator.
#[derive(Debug, Clone, PartialEq)]
pub enum TxCoordinatorEvent {
    /// Event which occurs when the transaction coordinator has sent a message
    /// to the P2P network.
    MessageGenerated(crate::network::Msg),
}

impl From<SignerCommand> for SignerSignal {
    fn from(command: SignerCommand) -> Self {
        SignerSignal::Command(command)
    }
}

impl From<TxCoordinatorEvent> for SignerSignal {
    fn from(event: TxCoordinatorEvent) -> Self {
        SignerSignal::Event(SignerEvent::TxCoordinator(event))
    }
}

impl From<TxSignerEvent> for SignerSignal {
    fn from(event: TxSignerEvent) -> Self {
        SignerSignal::Event(SignerEvent::TxSigner(event))
    }
}

impl From<SignerEvent> for SignerSignal {
    fn from(event: SignerEvent) -> Self {
        SignerSignal::Event(event)
    }
}

impl From<P2PEvent> for SignerSignal {
    fn from(event: P2PEvent) -> Self {
        SignerSignal::Event(SignerEvent::P2P(event))
    }
}
