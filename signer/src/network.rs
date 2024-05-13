use crate::ecdsa::Signed;
use crate::message::SignerMessage;

pub(crate) trait Client {
    type Error;
    /// Send `msg` to all other signers
    async fn broadcast(&self, msg: Signed<SignerMessage>) -> Result<(), Self::Error>;
    /// Receive a message from the network
    async fn receive(&mut self) -> Result<Signed<SignerMessage>, Self::Error>;
}
