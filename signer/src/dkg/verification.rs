//! This module contains logic specific to the verification of DKG shares.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use secp256k1::XOnlyPublicKey;
use wsts::state_machine::{coordinator::Coordinator, OperationResult, SignError};

use crate::{
    keys::PublicKey,
    signature::TaprootSignature,
    wsts_state_machine::{FrostCoordinator, WstsCoordinator},
};

use super::wsts::WstsNetMessageType;

/// Errors that can occur when using a [`StateMachine`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The state machine has expired and can no longer be used.
    #[error("the state machine has expired and can no longer be used.")]
    Expired,

    /// The state machine is in an end-state and can no longer be used.
    #[error("the state machine is in an end-state and can no longer be used: {0}")]
    EndState(Box<State>),

    /// The FROST coordinator returned an error.
    #[error("a signing error occurred: {0}")]
    SigningFailure(Box<SignError>),

    /// The FROST coordinator returned an unexpected result.
    #[error("unexpected WSTS result: {0:?}")]
    UnexpectedWstsResult(Box<OperationResult>),

    /// An error occurred in the WSTS coordinator.
    #[error("WSTS coordinator error: {0}")]
    Coordinator(Box<dyn std::error::Error + 'static + Send + Sync>),

    /// The FROST coordinator is in an invalid state. Signing rounds are allowed
    /// to be in a specific subset of WSTS coordinator states.
    #[error("the FROST coordinator is in an invalid state: {0:?}")]
    InvalidCoordinatorState(wsts::state_machine::coordinator::State),

    /// The sender is not part of the signing set.
    #[error("the sender is not part of the signing set: {0}")]
    UnknownSender(PublicKey),

    /// One or more of the public keys in the signing set are invalid. This error
    /// can be returned when converting the public keys from the coordinator's
    /// [`p256k1::point::Point`] types to [`PublicKey`] types.
    #[error("one or more of the public keys in the signing set are invalid")]
    InvalidPublicKeys,

    /// The public key of the signer does not match the public key of the sender.
    #[error("signer public key mismatch: signer_id: {signer_id}, wsts: {wsts}, sender: {sender}")]
    SignerPublicKeyMismatch {
        /// The signer ID according to the FROST coordinator.
        signer_id: u32,
        /// The public key expected by the FROST coordinator.
        wsts: Box<PublicKey>,
        /// The public key of the sender.
        sender: Box<PublicKey>,
    },
}

/// Represents the state of a DKG verification.
#[derive(Debug, Clone)]
pub enum State {
    /// The DKG verification has been created but not yet been used to process
    /// any messages.
    Idle,
    /// The DKG verification signing round has begun but has not yet finalized.
    Signing,
    /// The DKG verification has completed successfully, and the resulting
    /// signature is stored.
    Success(TaprootSignature),
    /// The DKG verification has failed due an an error or unexpected result
    /// from the FROST coordinator.
    Error,
    /// The DKG verification has expired and can no longer be used.
    Expired,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Idle => write!(f, "idle"),
            State::Signing => write!(f, "signing"),
            State::Success(_) => write!(f, "success"),
            State::Error => write!(f, "error"),
            State::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug)]
pub(super) struct QueuedMessage {
    pub(super) processed: bool,
    message: wsts::net::Message,
}

impl QueuedMessage {
    fn new(message: wsts::net::Message) -> Self {
        Self { processed: false, message }
    }

    fn mark_processed(&mut self) {
        self.processed = true;
    }
}

/// Represents the state of a DKG verification. This implementation is designed
/// to be able to span across multiple Bitcoin blocks, being limited by
/// wall-clock time instead of Bitcoin block cadence.
///
/// NOTE: The signer currently stops messages from being processed if the
/// received message doesn't match the current chain tip, so that needs to be
/// changed for cross-block functionality to work.
#[derive(Debug)]
pub struct StateMachine {
    /// The aggregate key that is being verified.
    aggregate_key: secp256k1::XOnlyPublicKey,
    /// The state machine that is being used to verify the aggregate key.
    pub(super) coordinator: FrostCoordinator,
    /// WSTS messages that have been received from other signers. We keep them
    /// in a [`HashMap`] where messages are organized by their type.
    pub(super) wsts_messages: HashMap<WstsNetMessageType, Vec<QueuedMessage>>,
    /// The [`Instant`] at which this state was created. This is used to limit
    /// the time that a [`StateMachine`] can be used, according to the
    /// specified timeout, which allows the verification to span multiple
    /// Bitcoin blocks, being limited by wall-clock time instead of Bitcoin
    /// block cadence.
    created_at: Instant,
    /// Specifies the amount of time elapsed since `created_at` that this
    /// verification should be valid.
    timeout: Option<Duration>,
    /// The current state of this state machine. If the state is
    /// [`State::Success`] then the signature will be stored in the variant.
    state: State,
}

impl StateMachine {
    /// Creates a new [`StateMachine`] with the given [`FrostCoordinator`],
    /// aggregate key, and timeout.
    pub fn new<X>(
        coordinator: FrostCoordinator,
        aggregate_key: X,
        timeout: Option<Duration>,
    ) -> Result<Self, Error>
    where
        X: Into<XOnlyPublicKey>,
    {
        let aggregate_key = aggregate_key.into();

        Ok(Self {
            aggregate_key,
            coordinator,
            wsts_messages: HashMap::new(),
            created_at: Instant::now(),
            timeout,
            state: State::Idle,
        })
    }

    /// Enqueues a message to be processed by the [`StateMachine`]'s internal
    /// [`FrostCoordinator`] when in the correct state. If the message can be
    /// processed now, it will be.
    ///
    /// - This will also process all eligible pending messages given the current
    ///   state of the [`FrostCoordinator`].
    /// - Will return an error if an invalid operation is attempted given the
    ///   current state of the [`StateMachine`]. For example, if the state
    ///   machine is in an end-state.
    /// - You can poll [`Self::state`] after calling this function to get the
    ///   current state of the [`StateMachine`], which will be updated as
    ///   messages are processed. Upon success, the resulting signature will be
    ///   stored in the [`State::Success`] variant.
    pub fn process_message<M>(&mut self, sender: PublicKey, msg: M) -> Result<(), Error>
    where
        M: Into<wsts::net::Message> + std::fmt::Debug,
    {
        // Set our state to expired if we've passed the timeout.
        if self.is_expired() {
            self.state = State::Expired;
        }

        // Assert that we're in a valid state to process messages.
        self.assert_valid_state_for_processing()?;

        // Validate that the sender is a valid signer in the signing set.
        self.assert_is_known_sender(sender)?;

        // Enqueue the message to be processed. If the constraints for
        // enqueueing the message are not met, an error will be returned and we
        // don't make any further updates or process anything.
        self.enqueue_message(msg.into())?;

        // We've enqueued at least 1 message, so just make sure we're in the
        // `Signing` state.
        self.state = State::Signing;

        // Iterate through all of the queued messages and process the relevant
        // ones. This loop will first process all messages applicable for the
        // current state, and then continue to process messages until there are
        // no more state changes. This is necessary because the state machine
        // can receive out-of-order messages, and we need to ensure that we
        // process all messages that we can before returning, including handling
        // state transitions.
        while self.process_queued_messages()? {}

        Ok(())
    }

    /// Validates that the sender of a message is a valid signer in the signing
    /// set.
    pub fn validate_sender(&self, signer_id: u32, sender: PublicKey) -> Result<(), Error> {
        let config = self.coordinator.get_config();
        let wsts: PublicKey = config
            .signer_public_keys
            .get(&signer_id)
            .ok_or(Error::UnknownSender(sender))?
            .try_into()
            .map_err(|_| Error::InvalidPublicKeys)?;

        if wsts != sender {
            return Err(Error::SignerPublicKeyMismatch {
                signer_id,
                wsts: wsts.into(),
                sender: sender.into(),
            });
        }

        Ok(())
    }

    /// Checks whether or not the given public key is a known sender in the
    /// signing set. Returns an error if the public key is invalid or the
    /// sender is not known to the underlying [`FrostCoordinator`].
    fn assert_is_known_sender(&self, sender: PublicKey) -> Result<(), Error> {
        let is_known = self
            .coordinator
            .get_config()
            .signer_public_keys
            .values()
            .any(|key| {
                PublicKey::try_from(key)
                    .map(|pub_key| pub_key == sender)
                    .unwrap_or(false)
            });

        if !is_known {
            return Err(Error::UnknownSender(sender));
        }

        Ok(())
    }

    /// Resets the [`StateMachine`] to its initial state, clearing all messages,
    /// setting its creation time to the current time, its state to
    /// [`State::Idle`] and also calling [`Coordinator::reset`] on the
    /// [`FrostCoordinator`].
    pub fn reset(&mut self) {
        self.wsts_messages.clear();
        self.created_at = Instant::now();
        self.state = State::Idle;
        self.coordinator.reset();
    }

    /// Gets the current state of the [`StateMachine`].
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Gets the aggregate key that is being verified.
    pub fn aggregate_key(&self) -> XOnlyPublicKey {
        self.aggregate_key
    }

    /// Gets whether or not this [`StateMachine`] has expired.
    fn is_expired(&self) -> bool {
        match self.timeout {
            None => false,
            Some(timeout) => self.created_at.elapsed() > timeout,
        }
    }

    /// Asserts that the [`StateMachine`] is in a state where it
    /// can process messages.
    fn assert_valid_state_for_processing(&self) -> Result<(), Error> {
        match self.state {
            State::Expired => Err(Error::Expired),
            State::Success(_) | State::Error => Err(Error::EndState(self.state.clone().into())),
            State::Idle | State::Signing => Ok(()),
        }
    }

    /// Determines the [`WstsNetMessageType`] of messages that can be processed
    /// given the current state of the [`FrostCoordinator`].
    ///
    /// The allowed message types per [`FrostCoordinator`] state are as follows:
    /// 1. If the coordinator is in the `Idle` state, it can only process
    ///    `NonceRequest` messages.
    /// 2. Upon receiving a `NonceRequest`, the coordinator transitions to the
    ///    `NonceGather` state. In this state, the coordinator can process
    ///    `NonceResponse` messages until it has received a number of nonces
    ///    equal to the number of signers.
    /// 3. Once this condition is met, the coordinator transitions to the
    ///    `SignatureShareRequest` state, after which it can process
    ///    `SignatureShareResponse` messages until it has received a number of
    ///    signature shares equal to the number of signers.
    /// 4. Once this condition is met, the coordinator will transition to either
    ///    the `Success` or `Error` state, depending on the result of the
    ///    signing operation.
    pub(super) fn current_processable_message_type(&self) -> Result<WstsNetMessageType, Error> {
        let msg_type = match self.coordinator.state {
            wsts::state_machine::coordinator::State::Idle => WstsNetMessageType::NonceRequest,
            wsts::state_machine::coordinator::State::NonceGather(_) => {
                WstsNetMessageType::NonceResponse
            }
            wsts::state_machine::coordinator::State::SigShareGather(_) => {
                WstsNetMessageType::SignatureShareResponse
            }
            ref invalid => return Err(Error::InvalidCoordinatorState(invalid.clone())),
        };

        Ok(msg_type)
    }

    /// Enqueues a message to be processed by the [`FrostCoordinator`] when
    /// in the correct state.
    fn enqueue_message(&mut self, msg: wsts::net::Message) -> Result<(), Error> {
        let msg_type: WstsNetMessageType = (&msg).into();

        // Enqueue the message under its message type.
        self.wsts_messages
            .entry(msg_type)
            .or_default()
            .push(QueuedMessage::new(msg));

        Ok(())
    }

    /// Processes all queued messages that can be processed given the current
    /// state of the [`FrostCoordinator`].
    fn process_queued_messages(&mut self) -> Result<bool, Error> {
        let message_type_to_process = self.current_processable_message_type()?;

        // Get references to all pending (unprocessed) messages of the given type.
        let messages = self
            .wsts_messages
            .entry(message_type_to_process)
            .or_default()
            .iter_mut()
            .filter(|msg| !msg.processed);

        // Record the current state of the coordinator before processing the
        // message. This is used below to determine if the coordinator has
        // transitioned to a new state after processing the message.
        let coordinator_state_pre_processing = self.coordinator.state.clone();

        // For keeping track of if we processed any messages for the return value.
        let mut processed_any = false;

        // Process all of the messages that we determined could be processed.
        for msg in messages {
            // Mark the message as processed so that even if it fails we don't
            // try to process it again.
            msg.mark_processed();

            // Pass the message to the coordinator.
            let (_, result) = self
                .coordinator
                .process_message(&msg.message)
                .map_err(|error| Error::Coordinator(Box::new(error)))?;

            processed_any = true;

            // Check the result of the operation and handle accordingly.
            match result {
                Some(OperationResult::SignTaproot(sig)) => {
                    self.state = State::Success(sig.into());
                    break;
                }
                Some(OperationResult::SignError(error)) => {
                    self.state = State::Error;
                    return Err(Error::SigningFailure(error.into()));
                }
                Some(result) => {
                    // We know exactly what the coordinator should be returning
                    // here, so if it's not one of the two expected results, we
                    // know that something has gone wrong.
                    self.state = State::Error;
                    return Err(Error::UnexpectedWstsResult(result.into()));
                }
                None => {
                    // If the coordinator state has changed, then it will ignore
                    // any further messages of this type, so we break early.
                    if self.coordinator.state != coordinator_state_pre_processing {
                        break;
                    }
                }
            }
        }

        Ok(processed_any)
    }
}

#[cfg(test)]
mod tests {
    use wsts::net::Message;

    use crate::{dkg::testing::*, testing::IterTestExt};

    use super::{
        State, WstsNetMessageType, WstsNetMessageType::NonceRequest,
        WstsNetMessageType::NonceResponse, WstsNetMessageType::SignatureShareResponse,
    };

    #[test]
    fn test_initial_state() {
        let signers = TestSetup::setup(5);
        let state_machine = signers.state_machine;

        assert_eq!(state_machine.signer_count(), 5);
        assert_state!(state_machine, State::Idle);

        state_machine
            .assert_valid_state_for_processing()
            .expect("should be able to process");

        assert_message_counts!(state_machine,
            NonceRequest => all: 0;
            NonceResponse => all: 0;
            SignatureShareRequest => all: 0;
            SignatureShareResponse => all: 0;
        );
        assert_allowed_msg_type!(state_machine, NonceRequest);
    }

    #[test]
    fn test_reset() {
        let mut setup = TestSetup::setup(5);
        let sender1 = setup.next_signer().as_public_key();
        let mut state_machine = setup.state_machine;

        state_machine
            .process_message(sender1, nonce_request(1, 1, 1))
            .expect("should be able to enqueue message");

        assert_message_counts!(state_machine,
            NonceRequest => total: 1, pending: 0;
            NonceResponse => all: 0;
            SignatureShareRequest => all: 0;
            SignatureShareResponse => all: 0;
        );
        assert_state!(state_machine, State::Signing);
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        state_machine.reset();

        assert_message_counts!(state_machine,
            NonceRequest => all: 0;
            NonceResponse => all: 0;
            SignatureShareRequest => all: 0;
            SignatureShareResponse => all: 0;
        );
        assert_state!(state_machine, State::Idle);
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::Idle
        ));

        // We asserted above that the reset gives us the values we expect, but
        // let's also try running some of the other tests that are a little more
        // complex to ensure that the state machine is in a good state.
        test_nonce_phase_with_in_order_messages();
        state_machine.reset();
        test_out_of_order_messages();
    }

    #[test]
    fn test_enqueue_message() {
        let setup = TestSetup::setup(2);
        let mut state_machine = setup.state_machine;

        let dkg_id = 0;
        let sign_id = 0;
        let sign_iter_id = 0;

        let request = nonce_request(dkg_id, sign_id, sign_iter_id);
        let response1 = nonce_response(dkg_id, sign_id, sign_iter_id, 1);
        let response2 = nonce_response(dkg_id, sign_id, sign_iter_id, 2);

        // Insert a couple of messages with the same sender.
        assert_message_counts!(state_machine, NonceRequest => all: 0);

        state_machine.enqueue_message(request.clone()).unwrap();
        state_machine.enqueue_message(response1.clone()).unwrap();
        assert_message_counts!(state_machine,
            NonceRequest => all: 1;
            NonceResponse => all: 1;
        );

        // Insert a message with a different sender.
        state_machine.enqueue_message(response2.clone()).unwrap();
        assert_message_counts!(state_machine,
            NonceRequest => all: 1;
            NonceResponse => all: 2;
        );
    }

    #[test]
    fn test_out_of_order_messages() {
        let mut setup = TestSetup::setup(2);
        let mut signer1 = setup.next_signer();
        let mut signer2 = setup.next_signer();
        let sender1 = signer1.as_public_key();
        let sender2 = signer2.as_public_key();
        let mut state_machine = setup.state_machine;

        let nonce_request = nonce_request(1, 1, 1);
        let nonce_response1 = signer1.process(&nonce_request).unwrap().single();
        let nonce_response2 = signer2.process(&nonce_request).unwrap().single();

        assert_state!(state_machine, State::Idle);

        // Enqueue a single nonce response.
        state_machine
            .process_message(sender1, nonce_response1)
            .unwrap();
        assert_allowed_msg_type!(state_machine, NonceRequest);
        assert_state!(state_machine, State::Signing);
        assert_message_counts!(state_machine,
            NonceRequest => all: 0;
            NonceResponse => all: 1;
        );

        // Enqueue a second nonce response.
        state_machine
            .process_message(sender2, nonce_response2)
            .unwrap();
        assert_allowed_msg_type!(state_machine, NonceRequest);
        assert_state!(state_machine, State::Signing);
        assert_message_counts!(state_machine,
            NonceRequest => all: 0;
            NonceResponse => all: 2;
        );

        // The first two messages were out of order, since we haven't received
        // a nonce request yet. But this should trigger the transition to
        // signature share gather, since we have 2 signers in the set and have now
        // received a nonce request and both nonce responses.
        state_machine
            .process_message(sender1, nonce_request)
            .unwrap();
        assert_allowed_msg_type!(state_machine, SignatureShareResponse);
        assert_state!(state_machine, State::Signing);
        assert_message_counts!(state_machine,
            NonceRequest => total: 1, pending: 0;
            NonceResponse => total: 2, pending: 0;
        );
    }

    #[test]
    fn test_nonce_phase_with_in_order_messages() {
        let mut setup = TestSetup::setup(2);
        let mut signer1 = setup.next_signer();
        let mut signer2 = setup.next_signer();
        let sender1 = signer1.as_public_key();
        let sender2 = signer2.as_public_key();
        let mut state_machine = setup.state_machine;

        assert_eq!(state_machine.signer_count(), 2);

        let nonce_request = nonce_request(1, 1, 1);

        // Process the nonce request with signer 1 and 2 to get their nonce
        // responses.
        let nonce_response1 = signer1
            .process(&nonce_request)
            .expect("signer1 should be able to process message")
            .single();
        assert!(matches!(nonce_response1, Message::NonceResponse(_)));
        let nonce_response2 = signer2
            .process(&nonce_request)
            .expect("signer2 should be able to process message")
            .single();
        assert!(matches!(nonce_response2, Message::NonceResponse(_)));

        // The state machine should be able to process the nonce request.
        state_machine
            .process_message(sender1, nonce_request)
            .expect("should be able to process message");

        assert_message_counts!(state_machine, NonceRequest => total: 1, pending: 0);
        assert_state!(state_machine, State::Signing);
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        // Process nonce responses from signer 1 and signer 2.
        state_machine
            .process_message(sender1, nonce_response1.clone())
            .expect("should be able to process message");
        assert_state!(state_machine, State::Signing);
        assert_allowed_msg_type!(state_machine, NonceResponse);
        state_machine
            .process_message(sender2, nonce_response2.clone())
            .expect("should be able to process message");
        assert_state!(state_machine, State::Signing);

        // We should have processed all the nonce responses, so we should now be
        // able to process signature share requests.
        assert_allowed_msg_type!(state_machine, SignatureShareResponse);
    }

    #[test]
    fn test_dkg_verification_state_machine() {
        let mut setup = TestSetup::setup(2);
        let mut signer1 = setup.next_signer();
        let mut signer2 = setup.next_signer();
        let sender1 = signer1.as_public_key();
        let sender2 = signer2.as_public_key();
        let mut state_machine = setup.state_machine;

        let nonce_request = nonce_request(1, 1, 1);

        // Process the nonce request with signer 1 and 2 to get their responses.
        let nonce_response1 = signer1.process(&nonce_request).unwrap().single();
        let nonce_response2 = signer2.process(&nonce_request).unwrap().single();

        // Process the nonce request in the state machine and assert.
        state_machine
            .process_message(sender1, nonce_request)
            .unwrap();
        assert_message_counts!(state_machine, NonceRequest => total: 1, pending: 0);
        assert_state!(state_machine, State::Signing);
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        // Process both nonce responses in the state machine and assert.
        state_machine
            .process_message(sender1, nonce_response1.clone())
            .expect("should be able to process message");
        assert_state!(state_machine, State::Signing);
        assert_allowed_msg_type!(state_machine, NonceResponse);
        state_machine
            .process_message(sender2, nonce_response2.clone())
            .expect("should be able to process message");
        assert_state!(state_machine, State::Signing);
        assert_allowed_msg_type!(state_machine, SignatureShareResponse);

        // Unwrap our nonce responses.
        let Message::NonceResponse(nonce_response1) = nonce_response1 else {
            panic!("expected nonce response, got {:?}", nonce_response1);
        };
        let Message::NonceResponse(nonce_response2) = nonce_response2 else {
            panic!("expected nonce response, got {:?}", nonce_response2);
        };

        // Create signature share requests, populated with the nonce responses
        // from the signers.
        let sig_share_request = signature_share_request(
            1,
            1,
            1,
            vec![nonce_response1.clone(), nonce_response2.clone()],
        );

        // Process the signature share request
        let sig_share_response1 = signer1
            .process(&sig_share_request)
            .expect("should be able to process message")
            .single();
        let sig_share_response2 = signer2
            .process(&sig_share_request)
            .expect("should be able to process message")
            .single();

        // Process the first signature share response in the state machine --
        // this should succeed.
        state_machine
            .process_message(sender1, sig_share_response1)
            .expect("should be able to process message");

        // Process the second signature share response -- this should result
        // in the FROST coordinator transitioning into an end-state and thus
        // also the state machine.
        state_machine
            .process_message(sender2, sig_share_response2)
            .expect("should be able to process message");

        // ... which should be SUCCESS!
        assert_state!(state_machine, State::Success(_));
    }
}
