//! Contains WSTS helper types and impls for use within the DKG module.

/// A helper enum to represent the different types of WSTS messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WstsNetMessageType {
    /// A DKG begin message.
    DkgBegin,
    /// A DKG public shares message.
    DkgPublicShares,
    /// A DKG private begin message.
    DkgPrivateBegin,
    /// A DKG private shares message.
    DkgPrivateShares,
    /// A DKG end begin message.
    DkgEndBegin,
    /// A DKG end message.
    DkgEnd,
    /// A nonce request message.
    NonceRequest,
    /// A nonce response message.
    NonceResponse,
    /// A signature share request message.
    SignatureShareRequest,
    /// A signature share response message.
    SignatureShareResponse,
}

impl From<&wsts::net::Message> for WstsNetMessageType {
    fn from(message: &wsts::net::Message) -> Self {
        match message {
            wsts::net::Message::DkgBegin(_) => WstsNetMessageType::DkgBegin,
            wsts::net::Message::DkgEndBegin(_) => WstsNetMessageType::DkgEndBegin,
            wsts::net::Message::DkgEnd(_) => WstsNetMessageType::DkgEnd,
            wsts::net::Message::DkgPrivateBegin(_) => WstsNetMessageType::DkgPrivateBegin,
            wsts::net::Message::DkgPrivateShares(_) => WstsNetMessageType::DkgPrivateShares,
            wsts::net::Message::DkgPublicShares(_) => WstsNetMessageType::DkgPublicShares,
            wsts::net::Message::NonceRequest(_) => WstsNetMessageType::NonceRequest,
            wsts::net::Message::NonceResponse(_) => WstsNetMessageType::NonceResponse,
            wsts::net::Message::SignatureShareRequest(_) => {
                WstsNetMessageType::SignatureShareRequest
            }
            wsts::net::Message::SignatureShareResponse(_) => {
                WstsNetMessageType::SignatureShareResponse
            }
        }
    }
}
