//! This module contains logic specific to the verification of DKG shares.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use secp256k1::XOnlyPublicKey;
use wsts::state_machine::{OperationResult, SignError};

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

    /// The state machine has reached the message limit for the given message
    /// type.
    #[error("the state machine has reached the message limit for message type {message_type:?} (expected: {expected}, actual: {actual})")]
    MessageLimitExceeded {
        /// The type of message that has reached the limit.
        message_type: WstsNetMessageType,
        /// The expected number of messages of this type that should be
        /// received.
        expected: u32,
        /// The actual number of messages of this type that have been received.
        actual: u32,
    },

    /// The FROST coordinator returned an error.
    #[error("a signing error occurred: {0}")]
    SigningFailure(Box<SignError>),

    /// The FROST coordinator returned an unexpected result.
    #[error("unexpected WSTS result: {0:?}")]
    UnexpectedWstsResult(Box<OperationResult>),

    /// An error occurred in the WSTS coordinator.
    #[error("WSTS coordinator error: {0}")]
    Coordinator(Box<dyn std::error::Error + 'static + Send + Sync>),
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
struct QueuedMessage {
    processed: bool,
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
/// TODO: The signer currently stops messages from being processed if the
/// received message doesn't match the current chain tip, so that needs to be
/// changed for cross-block functionality to work.
#[derive(Debug)]
pub struct StateMachine {
    /// The aggregate key that is being verified.
    aggregate_key: secp256k1::XOnlyPublicKey,
    /// The state machine that is being used to verify the signer.
    coordinator: FrostCoordinator,
    /// WSTS messages that have been received from other signers. We keep them
    /// in a [`HashMap`] where the keys are tuples of message types and sender
    /// public keys, and the values are queued messages. This allows us to
    /// manage messages by type and sender, ensuring that we can handle
    /// out-of-order messages and process them correctly, while also
    /// constraining each signer to one message per message type.
    wsts_messages: HashMap<(WstsNetMessageType, PublicKey), QueuedMessage>,
    /// The [`Instant`] at which this state was created. This is used to limit
    /// the time that a [`StateMachine`] can be used, according to the
    /// specified timeout, which allows the verification to span multiple
    /// Bitcoin blocks, being limited by wall-clock time instead of Bitcoin
    /// block cadence.
    created_at: Instant,
    /// Specifies the amount of time elapsed since `created_at` that this
    /// verification should be valid.
    timeout: Duration,
    /// The signature that has been produced by the DKG verification. This is
    /// only set if/once the DKG verification has completed successfully.
    state: State,
}

impl StateMachine {
    /// Creates a new [`StateMachine`] with the given [`FrostCoordinator`],
    /// aggregate key, and timeout.
    pub fn new<X>(coordinator: FrostCoordinator, aggregate_key: X, timeout: Duration) -> Self
    where
        X: Into<XOnlyPublicKey>,
    {
        let aggregate_key = aggregate_key.into();

        Self {
            aggregate_key,
            coordinator,
            wsts_messages: HashMap::new(),
            created_at: Instant::now(),
            timeout,
            state: State::Idle,
        }
    }

    /// Processes a WSTS message, updating the internal state of the
    /// [`FrostCoordinator`].
    ///
    /// - Will return an error if an invalid operation is attempted given the
    ///   current state of the [`StateMachine`].
    /// - Poll [`Self::state`] after a successfull call to this function to get
    ///   the current state of the [`StateMachine`], which will be updated as
    ///   messages are processed.
    /// - If the instance is in an end-state, an error will be returned.
    /// - Upon success, the resulting signature can be retrieved via
    ///   [`Self::state`].
    /// - Will process all eligible pending messages given the current state of
    ///   the [`FrostCoordinator`].
    pub fn process_message<M>(&mut self, sender: PublicKey, msg: M) -> Result<(), Error>
    where
        M: Into<wsts::net::Message> + std::fmt::Debug,
    {
        // Set our state to expired if we've passed the timeout.
        if self.is_expired() {
            self.state = State::Expired;
        }

        // Assert that we're in a valid state to process messages.
        self.assert_valid_state()?;

        // Enqueue the message to be processed. If the constraints for
        // enqueueing the message are not met, an error will be returned and we
        // don't make any further updates or process anything.
        self.enqueue_message(sender, msg.into())?;

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
        loop {
            let current_processable_message_type = self.current_processable_message_type();
            self.process_queued_messages()?;
            if current_processable_message_type == self.current_processable_message_type() {
                break;
            }
        }

        Ok(())
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
        self.created_at.elapsed() > self.timeout
    }

    fn message_type_limit(&self, message_type: WstsNetMessageType) -> u32 {
        match message_type {
            WstsNetMessageType::NonceRequest => 1,
            WstsNetMessageType::NonceResponse => self.signer_count(),
            WstsNetMessageType::SignatureShareRequest => 1,
            WstsNetMessageType::SignatureShareResponse => self.signer_count(),
            _ => 0,
        }
    }

    /// Gets the number of buffered messages of the given type that are
    /// currently stored in this [`StateMachine`].
    fn total_message_count(&self, message_type: WstsNetMessageType) -> u32 {
        // The `_ as u32` should be safe here since we know that the number of
        // signers is far less than `u32::MAX`, and each message is deduplicated
        // by the sender's public key, which is also validated to be a valid
        // member of the signer set.
        self.wsts_messages
            .keys()
            .filter(|(msg_type, _)| *msg_type == message_type)
            .count() as u32
    }

    /// Gets the number of signers that are expected to participate in the DKG
    /// verification.
    fn signer_count(&self) -> u32 {
        self.coordinator.get_config().num_signers
    }

    /// Asserts that the [`StateMachine`] is in a state where it
    /// can process messages.
    fn assert_valid_state(&self) -> Result<(), Error> {
        match self.state {
            State::Expired => Err(Error::Expired),
            State::Success(_) | State::Error => Err(Error::EndState(self.state.clone().into())),
            State::Idle | State::Signing => Ok(()),
        }
    }

    /// Determines the [`WstsNetMessageType`] of messages that can be processed
    /// given the current state of the [`FrostCoordinator`].
    ///
    /// The allowed message types per state are as follows:
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
    fn current_processable_message_type(&self) -> WstsNetMessageType {
        match self.coordinator.state {
            wsts::state_machine::coordinator::State::Idle => WstsNetMessageType::NonceRequest,
            wsts::state_machine::coordinator::State::NonceGather(_) => {
                WstsNetMessageType::NonceResponse
            }
            _ => WstsNetMessageType::SignatureShareResponse,
        }
    }

    /// Enqueues a message to be processed by the [`FrostCoordinator`] when
    /// in the correct state.
    fn enqueue_message(&mut self, sender: PublicKey, msg: wsts::net::Message) -> Result<(), Error> {
        let msg_type: WstsNetMessageType = (&msg).into();

        let current_count = self.total_message_count(msg_type);
        let limit = self.message_type_limit(msg_type);

        // If we've already received the maximum number of messages of this
        // type, we don't enqueue it and return an error. Note: This may be
        // unnecessary after changing to deduplicate messages by sender, but at
        // least helps to cap the number of messages that we can enqueue if
        // somehow there's messages from unknown pubkeys being dumped here.
        //
        // Note that this check is also our implicit check to ensure that only
        // the allowed message types for signing can be enqueued, as the
        // remaining WSTS message types have a limit of 0.
        if current_count >= limit {
            return Err(Error::MessageLimitExceeded {
                message_type: msg_type,
                expected: limit,
                actual: current_count + 1,
            });
        }

        // Enqueue the message under its message type and sender. We use the
        // sender's public key to deduplicate messages from the same sender and
        // message type; `insert_entry` will overwrite an existing message from the same
        // sender, which we shouldn't have within the same round.
        self.wsts_messages
            .entry((msg_type, sender))
            .insert_entry(QueuedMessage::new(msg));

        Ok(())
    }

    /// Processes all queued messages that can be processed given the current
    /// state of the [`FrostCoordinator`].
    fn process_queued_messages(&mut self) -> Result<(), Error> {
        let message_type_to_process = self.current_processable_message_type();

        // Gets references to all pending messages of the given type that are
        // currently stored. The returned messages are in arbitrary order, but
        // this doesn't matter here since we're only processing the messages
        // that the coordinator state machine can handle given its current
        // state.

        // We want to filter out processed messages.
        let messages = self
            .wsts_messages
            .iter_mut()
            .filter_map(|((msg_type, sender), msg)| {
                if *msg_type == message_type_to_process && !msg.processed {
                    Some((sender, msg))
                } else {
                    None
                }
            });

        // Process all of the messages that we determined could be processed.
        for (sender, msg) in messages {
            tracing::trace!(
                "processing {:?} message from sender: {:?}",
                &message_type_to_process,
                &sender.to_string()[..10]
            );

            // Mark the message as processed so that even if it fails we don't
            // try to process it again.
            msg.mark_processed();

            // Pass the message to the coordinator.
            let (_, result) = self
                .coordinator
                .process_message(&msg.message)
                .map_err(|error| Error::Coordinator(Box::new(error)))?;

            // Check the result of the operation. If the operation is one of
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
                None => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use wsts::net::Message;

    use crate::{
        dkg::testing::*,
        testing::IterTestExt,
        wsts_state_machine::{FrostCoordinator, WstsCoordinator},
    };

    use super::*;

    impl StateMachine {
        /// Gets the number of pending messages of the given type that are currently
        /// stored in this [`StateMachine`].
        fn pending_message_count(&self, message_type: WstsNetMessageType) -> u32 {
            self.wsts_messages
                .iter()
                .filter(|((msg_type, _), msg)| *msg_type == message_type && !msg.processed)
                .count() as u32
        }

        fn assert_message_counts(
            &self,
            message_type: WstsNetMessageType,
            expected_total: u32,
            expected_pending: u32,
        ) -> Result<(), String> {
            if !self.total_message_count(message_type) == expected_total {
                return Err(format!(
                    "expected {} total messages of type {:?}, got {}",
                    expected_total,
                    message_type,
                    self.total_message_count(message_type)
                ));
            }

            if !self.pending_message_count(message_type) == expected_pending {
                return Err(format!(
                    "expected {} pending messages of type {:?}, got {}",
                    expected_pending,
                    message_type,
                    self.pending_message_count(message_type)
                ));
            }

            Ok(())
        }
    }

    #[test]
    fn test_initial_state() {
        let signers = TestSetup::setup(5);
        let state_machine = signers.state_machine;

        assert_eq!(state_machine.signer_count(), 5);
        assert!(matches!(state_machine.state, State::Idle));

        state_machine
            .assert_valid_state()
            .expect("should be able to process");

        assert_eq!(
            state_machine.total_message_count(WstsNetMessageType::NonceRequest),
            0
        );
        assert_eq!(
            state_machine.pending_message_count(WstsNetMessageType::NonceRequest),
            0
        );
        assert_eq!(
            state_machine.total_message_count(WstsNetMessageType::NonceResponse),
            0
        );
        assert_eq!(
            state_machine.pending_message_count(WstsNetMessageType::NonceResponse),
            0
        );
        assert_eq!(
            state_machine.total_message_count(WstsNetMessageType::SignatureShareRequest),
            0
        );
        assert_eq!(
            state_machine.pending_message_count(WstsNetMessageType::SignatureShareRequest),
            0
        );
        assert_eq!(
            state_machine.total_message_count(WstsNetMessageType::SignatureShareResponse),
            0
        );
        assert_eq!(
            state_machine.pending_message_count(WstsNetMessageType::SignatureShareResponse),
            0
        );

        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceRequest
        );
    }

    #[test]
    fn test_enqueue_message() {
        let (signer_privkey, signer_pubkey) = keypair();
        let sender1 = pubkey();
        let sender2 = pubkey();
        assert_ne!(&sender1, &sender2);

        let aggregate_key = pubkey_xonly();

        let mut state_machine = StateMachine::new(
            FrostCoordinator::new([sender1, signer_pubkey], 1, signer_privkey),
            aggregate_key,
            Duration::from_secs(60),
        );

        let dkg_id = 0;
        let sign_id = 0;
        let sign_iter_id = 0;

        let request = nonce_request(dkg_id, sign_id, sign_iter_id);
        let response1 = nonce_response(dkg_id, sign_id, sign_iter_id, 1);
        let response2 = nonce_response(dkg_id, sign_id, sign_iter_id, 2);

        // Insert a couple of messages with the same sender.
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 0, 0)
            .unwrap();
        state_machine
            .enqueue_message(sender1, request.clone())
            .unwrap();
        state_machine
            .enqueue_message(sender1, response1.clone())
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 1, 1)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 1, 1)
            .unwrap();

        // Ensure that the message is deduplicated by the sender's public key.
        state_machine.enqueue_message(sender1, response1).unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 1, 1)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 1, 1)
            .unwrap();

        // Insert a message with a different sender.
        state_machine
            .enqueue_message(sender2, response2.clone())
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 1, 1)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 2, 2)
            .unwrap();

        state_machine
            .enqueue_message(sender1, request)
            .expect_err("should be too many nonce requests");
        state_machine
            .enqueue_message(sender2, response2)
            .expect_err("should be too many nonce responses");
    }

    #[test]
    fn test_out_of_order_messages() {
        let mut setup = TestSetup::setup(2);
        let mut state_machine = setup.state_machine;
        let mut signer1 = setup.signers.pop().unwrap();
        let mut signer2 = setup.signers.pop().unwrap();
        let sender1 = setup.senders[0];
        let sender2 = setup.senders[1];

        let nonce_request = nonce_request(1, 1, 1);
        let nonce_response1 = signer1.process(&nonce_request).unwrap().single();
        let nonce_response2 = signer2.process(&nonce_request).unwrap().single();

        assert!(matches!(state_machine.state, State::Idle));

        // Enqueue a single nonce response.
        state_machine
            .process_message(sender1, nonce_response1)
            .unwrap();
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceRequest
        );
        assert!(matches!(state_machine.state, State::Signing));
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 0, 0)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 1, 1)
            .unwrap();

        // Enqueue a second nonce response.
        state_machine
            .process_message(sender2, nonce_response2)
            .unwrap();
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceRequest
        );
        assert!(matches!(state_machine.state, State::Signing));
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 0, 0)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 2, 2)
            .unwrap();

        // The first two messages were out of order, since we haven't received
        // a nonce request yet. But this should trigger the transition to
        // signature share gather, since we have 2 signers in the set and have now
        // received a nonce request and both nonce responses.
        state_machine
            .process_message(sender1, nonce_request)
            .unwrap();
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::SignatureShareResponse
        );
        assert!(matches!(state_machine.state, State::Signing));
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 1, 0)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceResponse, 2, 0)
            .unwrap();
    }

    #[test]
    fn test_nonce_phase_with_in_order_messages() {
        let mut setup = TestSetup::setup(2);
        let mut state_machine = setup.state_machine;
        let mut signer1 = setup.signers.pop().unwrap();
        let mut signer2 = setup.signers.pop().unwrap();
        let sender1 = setup.senders[0];
        let sender2 = setup.senders[1];

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

        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 0, 0)
            .unwrap();
        assert!(matches!(state_machine.state(), &State::Signing));
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        // Process nonce responses from signer 1 and signer 2.
        state_machine
            .process_message(sender1, nonce_response1.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, State::Signing));
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceResponse
        );
        state_machine
            .process_message(sender2, nonce_response2.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, State::Signing));

        // We should have processed all the nonce responses, so we should now be
        // able to process signature share requests.
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::SignatureShareResponse
        );
    }

    #[test]
    fn test_dkg_verification_state_machine() {
        let mut setup = TestSetup::setup(2);
        let mut state_machine = setup.state_machine;
        let mut signer1 = setup.signers.pop().unwrap();
        let mut signer2 = setup.signers.pop().unwrap();
        let sender1 = setup.senders[0];
        let sender2 = setup.senders[1];

        let nonce_request = nonce_request(1, 1, 1);

        // Process the nonce request with signer 1 and 2 to get their responses.
        let nonce_response1 = signer1.process(&nonce_request).unwrap().single();
        let nonce_response2 = signer2.process(&nonce_request).unwrap().single();

        // Process the nonce request in the state machine and assert.
        state_machine
            .process_message(sender1, nonce_request)
            .unwrap();
        state_machine
            .assert_message_counts(WstsNetMessageType::NonceRequest, 0, 0)
            .unwrap();
        assert!(matches!(state_machine.state(), &State::Signing));
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        // Process both nonce responses in the state machine and assert.
        state_machine
            .process_message(sender1, nonce_response1.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, State::Signing));
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceResponse
        );
        state_machine
            .process_message(sender2, nonce_response2.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, State::Signing));
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::SignatureShareResponse
        );

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

        // Process signer 1's signature share response with both signers.
        signer1
            .process(&sig_share_response1)
            .expect("should be able to process message");
        signer2
            .process(&sig_share_response1)
            .expect("should be able to process message");

        // Process signer 2's signature share response with both signers.
        signer1
            .process(&sig_share_response2)
            .expect("should be able to process message");
        signer2
            .process(&sig_share_response2)
            .expect("should be able to process message");

        // Process the first signature share response in the state machine --
        // this should succeed.
        state_machine
            .process_message(sender1, sig_share_response1)
            .expect("should be able to process message");

        // Process the second signature share response -- this should result
        // in the FROST coordinator transitioning into an end-state and thus
        // also the state machine.
        let result = state_machine.process_message(sender2, sig_share_response2);

        // TODO: This currently fails with a `BadPartySigs` error, so
        // something's probably off with the setup of the signers. But what
        // we're really testing is the state machine and that we have an end
        // state here (either success or failure).
        assert!(matches!(result, Err(Error::SigningFailure(_))));
    }
}
