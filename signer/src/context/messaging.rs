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
