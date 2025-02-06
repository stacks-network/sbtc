//! This module contains logic specific to the distributed key generation (DKG)
//! protocol.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use wsts::state_machine::{OperationResult, SignError};

use crate::{
    bitcoin::utxo::UnsignedMockTransaction,
    error::Error,
    keys::PublicKey,
    signature::TaprootSignature,
    wsts_state_machine::{FrostCoordinator, StateMachineId, WstsCoordinator},
};

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

/// Errors that can occur when using a [`DkgVerificationStateMachine`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum DkgVerificationStateMachineError {
    /// The state machine has expired and can no longer be used.
    #[error("the state machine has expired and can no longer be used.")]
    Expired,

    /// The state machine is in an end-state and can no longer be used.
    #[error("the state machine is in an end-state and can no longer be used: {0}")]
    EndState(Box<DkgVerificationState>),

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
}

/// Represents the state of a DKG verification.
#[derive(Debug, Clone)]
pub enum DkgVerificationState {
    /// The DKG verification has been created but not yet been used to process
    /// any messages.
    Idle,
    /// The DKG verification is currently gathering nonces. This is the initi
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

impl std::fmt::Display for DkgVerificationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkgVerificationState::Idle => write!(f, "idle"),
            DkgVerificationState::Signing => write!(f, "signing"),
            DkgVerificationState::Success(_) => write!(f, "success"),
            DkgVerificationState::Error => write!(f, "error"),
            DkgVerificationState::Expired => write!(f, "expired"),
        }
    }
}

/// Represents the state of a DKG verification. This implementation is designed
/// to be able to span across multiple Bitcoin blocks, being limited by
/// wall-clock time instead of Bitcoin block cadence.
///
/// TODO: The signer currently stops messages from being processed if the
/// received message doesn't match the current chain tip, so that needs to be
/// changed for cross-block functionality to work.
#[allow(dead_code)]
pub struct DkgVerificationStateMachine {
    /// The aggregate key that is being verified.
    aggregate_key: secp256k1::XOnlyPublicKey,
    /// The state machine that is being used to verify the signer.
    coordinator: FrostCoordinator,
    /// The mock transaction that is being used to verify the signer.
    mock_tx: UnsignedMockTransaction,
    /// WSTS messages that have been received from other signers. We keep them
    /// in a [`VecDeque`] so that we can pop the oldest messages first if we
    /// find that we need to drop messages due to size constraints (we know how
    /// many of each message type we should be receiving).
    /// TODO: Update this comment
    wsts_messages: HashMap<WstsNetMessageType, HashMap<PublicKey, wsts::net::Message>>,
    /// The [`Instant`] at which this state was created. This is used to limit
    /// the time that a [`DkgVerificationState`] can be used, according to the
    /// specified timeout, which allows the verification to span multiple
    /// Bitcoin blocks, being limited by wall-clock time instead of Bitcoin
    /// block cadence.
    created_at: Instant,
    /// Specifies the amount of time elapsed since `created_at` that this
    /// verification should be valid.
    timeout: Duration,
    /// The signature that has been produced by the DKG verification. This is
    /// only set if/once the DKG verification has completed successfully.
    state: DkgVerificationState,
}

impl DkgVerificationStateMachine {
    /// Creates a new [`DkgVerificationStateMachine`] with the given [`FrostCoordinator`],
    /// aggregate key, and timeout.
    pub fn new<X>(coordinator: FrostCoordinator, aggregate_key: X, timeout: Duration) -> Self
    where
        X: Into<secp256k1::XOnlyPublicKey>,
    {
        let aggregate_key = aggregate_key.into();

        Self {
            aggregate_key,
            coordinator,
            mock_tx: UnsignedMockTransaction::new(aggregate_key),
            wsts_messages: HashMap::new(),
            created_at: Instant::now(),
            timeout,
            state: DkgVerificationState::Idle,
        }
    }

    /// Processes a WSTS message, updating the internal state of the
    /// [`FrostCoordinator`]. Upon successful completion of the DKG
    /// verification, the signature both stored on this instance for later use as well as returned.
    #[tracing::instrument(skip_all)]
    fn process_message<M>(
        &mut self,
        sender: PublicKey,
        msg: M,
    ) -> Result<DkgVerificationState, Error>
    where
        M: Into<wsts::net::Message> + std::fmt::Debug,
    {
        if self.is_expired() {
            self.state = DkgVerificationState::Expired;
        }

        self.assert_valid_state()?;

        self.enqueue_message(sender, msg.into())?;

        self.state = DkgVerificationState::Signing;

        self.process_queued_messages()
    }

    /// Gets whether or not this [`DkgVerificationStateMachine`] has expired.
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
    /// currently stored in this [`DkgVerificationStateMachine`].
    fn message_type_count(&self, message_type: WstsNetMessageType) -> u32 {
        // The `_ as u32` should be safe here since we know that the number of
        // signers is far less than `u32::MAX`, and each message is deduplicated
        // by the sender's public key, which is also validated to be a valid
        // member of the signer set.
        self.wsts_messages
            .get(&message_type)
            .map(|messages| messages.len() as u32)
            .unwrap_or(0)
    }

    /// Gets the number of signers that are expected to participate in the DKG
    /// verification.
    fn signer_count(&self) -> u32 {
        self.coordinator.get_config().num_signers
    }

    /// Asserts that the [`DkgVerificationStateMachine`] is in a state where it
    /// can process messages.
    fn assert_valid_state(&self) -> Result<(), Error> {
        match self.state {
            DkgVerificationState::Expired => Err(Error::DkgVerificationStateMachine(
                StateMachineId::RotateKey(self.aggregate_key.into()),
                DkgVerificationStateMachineError::Expired,
            )),
            DkgVerificationState::Success(_) | DkgVerificationState::Error => {
                Err(Error::DkgVerificationStateMachine(
                    StateMachineId::RotateKey(self.aggregate_key.into()),
                    DkgVerificationStateMachineError::EndState(self.state.clone().into()),
                ))
            }
            DkgVerificationState::Idle | DkgVerificationState::Signing => Ok(()),
        }
    }

    /// Gets the [`WstsNetMessageType`] of messages that can be processed given
    /// the current state of the [`FrostCoordinator`].
    ///
    /// The allowed message types per state are as follows:
    /// 1. If the coordinator is in the `Idle` state, the only message which it
    ///    can process is a `NonceRequest`.
    /// 2. Upon receiving a `NonceRequest`, the coordinator transitions to the
    ///    `NonceGather` state. In this state, the coordinator can process
    ///    `NonceResponse` messages until it has received a number of nonces
    ///    equal to the number of signers. Once this condition is met, the
    ///    coordinator transitions to the `SignatureShareRequest` state.
    fn current_processable_message_type(&self) -> WstsNetMessageType {
        let num_signers = self.signer_count();
        tracing::debug!(num_signers, "current_processable_message_type");

        match self.coordinator.state {
            wsts::state_machine::coordinator::State::Idle => WstsNetMessageType::NonceRequest,
            wsts::state_machine::coordinator::State::NonceGather(_) => {
                if self.message_type_count(WstsNetMessageType::NonceResponse) >= num_signers {
                    WstsNetMessageType::SignatureShareRequest
                } else {
                    WstsNetMessageType::NonceResponse
                }
            }
            _ => WstsNetMessageType::SignatureShareResponse,
        }
    }

    /// Enqueues a message to be processed by the [`FrostCoordinator`] when
    /// in the correct state by [`Self::process_queued_messages`].
    fn enqueue_message(&mut self, sender: PublicKey, msg: wsts::net::Message) -> Result<(), Error> {
        let msg_type: WstsNetMessageType = (&msg).into();

        // If we've already received the maximum number of messages of this
        // type, we should drop the message.
        let current_count = self.message_type_count(msg_type);
        let limit = self.message_type_limit(msg_type);

        if current_count >= limit {
            return Err(Error::DkgVerificationStateMachine(
                StateMachineId::RotateKey(self.aggregate_key.into()),
                DkgVerificationStateMachineError::MessageLimitExceeded {
                    message_type: msg_type,
                    expected: limit,
                    actual: current_count + 1,
                },
            ));
        }

        self.wsts_messages
            .entry(msg_type)
            .or_default()
            .entry(sender)
            .insert_entry(msg);

        Ok(())
    }

    /// Processes all queued messages that can be processed given the current
    /// state of the [`FrostCoordinator`].
    fn process_queued_messages(&mut self) -> Result<DkgVerificationState, Error> {
        let message_type_to_process = self.current_processable_message_type();
        dbg!(&message_type_to_process);

        // Gets references all pending messages of the given type that are
        // currently stored. The returned messages are in arbitrary order, but
        // this doesn't matter here since we're only processing the messages
        // that the coordinator state machine can handle given its current
        // state.
        let messages = self.wsts_messages.get_mut(&message_type_to_process);
        dbg!(&messages);
        let Some(messages) = messages else {
            return Ok(self.state.clone());
        };

        let mut processed_senders = HashSet::new();

        // Process all of the messages that we determined could be processed.
        for (sender, msg) in messages.iter() {
            // Pass the message to the coordinator.
            let (_, result) = self.coordinator.process_message(msg)?;
            dbg!(&result);
            dbg!(&self.coordinator.state);
            processed_senders.insert(*sender);

            // Check the result of the operation. If the operation is one of
            match result {
                Some(OperationResult::SignTaproot(sig)) => {
                    self.state = DkgVerificationState::Success(sig.into());
                    break;
                }
                Some(OperationResult::SignError(error)) => {
                    self.state = DkgVerificationState::Error;
                    return Err(Error::DkgVerificationStateMachine(
                        StateMachineId::RotateKey(self.aggregate_key.into()),
                        DkgVerificationStateMachineError::SigningFailure(error.into()),
                    ));
                }
                Some(result) => {
                    // We know exactly what the coordinator should be returning
                    // here, so if it's not one of the two expected results, we
                    // know that something has gone wrong.
                    self.state = DkgVerificationState::Error;
                    return Err(Error::DkgVerificationStateMachine(
                        StateMachineId::RotateKey(self.aggregate_key.into()),
                        DkgVerificationStateMachineError::UnexpectedWstsResult(result.into()),
                    ));
                }
                None => {}
            }
        }

        // Remove the processed messages from the queue.
        for sender in processed_senders {
            messages.remove(&sender);
        }

        Ok(self.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use wsts::{
        net::{Message, NonceRequest, NonceResponse, SignatureShareRequest, SignatureType},
        state_machine::coordinator::{frost, test as wsts_test},
        v2,
    };

    use crate::{
        keys::PrivateKey,
        wsts_state_machine::{FrostCoordinator, WstsCoordinator},
    };

    use super::*;

    fn pubkey() -> PublicKey {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        PublicKey::from_private_key(&PrivateKey::from(keypair.secret_key()))
    }

    fn pubkey_xonly() -> secp256k1::XOnlyPublicKey {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        keypair.x_only_public_key().0
    }

    fn keypair() -> (PrivateKey, PublicKey) {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key = PrivateKey::from(keypair.secret_key());
        let public_key = PublicKey::from_private_key(&private_key);
        (private_key, public_key)
    }

    fn nonce_request(dkg_id: u64, sign_id: u64, sign_iter_id: u64) -> Message {
        Message::NonceRequest(NonceRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            message: vec![0; 5],
            signature_type: SignatureType::Taproot(None),
        })
    }

    fn nonce_response(dkg_id: u64, sign_id: u64, sign_iter_id: u64, signer_id: u32) -> Message {
        Message::NonceResponse(NonceResponse {
            dkg_id,
            sign_id,
            sign_iter_id,
            signer_id,
            nonces: vec![],
            key_ids: vec![],
            message: vec![],
        })
    }

    fn signature_share_request(
        dkg_id: u64,
        sign_id: u64,
        sign_iter_id: u64,
        nonce_responses: Vec<NonceResponse>,
    ) -> Message {
        Message::SignatureShareRequest(SignatureShareRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            message: vec![],
            signature_type: SignatureType::Taproot(None),
            nonce_responses,
        })
    }

    #[test]
    fn test_enqueue_message() {
        let (signer_privkey, signer_pubkey) = keypair();
        let sender1 = pubkey();
        let sender2 = pubkey();
        assert_ne!(&sender1, &sender2);

        let aggregate_key = pubkey_xonly();

        let mut state_machine = DkgVerificationStateMachine::new(
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
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            0
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceResponse),
            0
        );
        state_machine
            .enqueue_message(sender1, request.clone())
            .unwrap();
        state_machine
            .enqueue_message(sender1, response1.clone())
            .unwrap();
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            1
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceResponse),
            1
        );

        // Ensure that the message is deduplicated by the sender's public key.
        state_machine.enqueue_message(sender1, response1).unwrap();
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            1
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceResponse),
            1
        );

        // Insert a message with a different sender.
        state_machine
            .enqueue_message(sender2, response2.clone())
            .unwrap();
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            1
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceResponse),
            2
        );

        state_machine
            .enqueue_message(sender1, request)
            .expect_err("should be too many nonce requests");
        state_machine
            .enqueue_message(sender2, response2)
            .expect_err("should be too many nonce responses");
    }

    #[test]
    fn test_dkg_verification_state_machine() {
        let (mut coordinators, mut signers) =
            wsts_test::run_dkg::<frost::Coordinator<v2::Aggregator>, v2::Party>(2, 5);

        let coordinator1: FrostCoordinator = coordinators.pop().unwrap().into();
        // let coordinator2: FrostCoordinator = coordinators.pop().unwrap().into();
        let mut signer1 = signers.pop().unwrap();
        let mut signer2 = signers.pop().unwrap();

        let sender1 = pubkey();
        let sender2 = pubkey();

        let mut state_machine =
            DkgVerificationStateMachine::new(coordinator1, pubkey_xonly(), Duration::from_secs(60));

        state_machine
            .assert_valid_state()
            .expect("should be able to process");

        assert!(matches!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceRequest
        ));

        assert!(matches!(state_machine.state, DkgVerificationState::Idle));
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            0
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceResponse),
            0
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::SignatureShareRequest),
            0
        );
        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::SignatureShareResponse),
            0
        );
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceRequest
        );

        assert_eq!(state_machine.signer_count(), 2);

        let nonce_request = nonce_request(1, 1, 1);

        let nonce_response1 = signer1
            .process(&nonce_request)
            .expect("should be able to process message")
            .pop()
            .expect("signer 1 should have a nonce response");

        let nonce_response2 = signer2
            .process(&nonce_request)
            .expect("should be able to process message")
            .pop()
            .expect("signer 2 should have a nonce response");

        let result = state_machine
            .process_message(sender1, nonce_request)
            .expect("should be able to process message");

        assert_eq!(
            state_machine.message_type_count(WstsNetMessageType::NonceRequest),
            0
        );
        assert!(matches!(result, DkgVerificationState::Signing));
        assert!(matches!(
            state_machine.coordinator.state,
            wsts::state_machine::coordinator::State::NonceGather(_)
        ));

        state_machine
            .process_message(sender1, nonce_response1.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, DkgVerificationState::Signing));
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::NonceResponse
        );
        state_machine
            .process_message(sender2, nonce_response2.clone())
            .expect("should be able to process message");
        assert!(matches!(state_machine.state, DkgVerificationState::Signing));
        dbg!(&state_machine.coordinator.state);
        assert_eq!(
            state_machine.current_processable_message_type(),
            WstsNetMessageType::SignatureShareResponse
        );

        let Message::NonceResponse(nonce_response1) = nonce_response1 else {
            panic!("expected nonce response, got {:?}", nonce_response1);
        };
        let Message::NonceResponse(nonce_response2) = nonce_response2 else {
            panic!("expected nonce response, got {:?}", nonce_response2);
        };

        let sig_share_request1 = signature_share_request(
            1,
            1,
            1,
            vec![nonce_response1.clone(), nonce_response2.clone()],
        );
        let sig_share_request2 = signature_share_request(
            1,
            1,
            1,
            vec![nonce_response1.clone(), nonce_response2.clone()],
        );

        let sig_share_response1 = signer1
            .process(&sig_share_request1)
            .expect("should be able to process message")
            .pop()
            .expect("signer 1 should have a signature share response");
        let sig_share_response2 = signer2
            .process(&sig_share_request2)
            .expect("should be able to process message")
            .pop()
            .expect("signer 2 should have a signature share response");

        let result = state_machine
            .process_message(sender1, sig_share_response1)
            .expect("should be able to process message");
        dbg!(result);
        let result = state_machine
            .process_message(sender2, sig_share_response2)
            .expect("should be able to process message");
        dbg!(result);
        dbg!(&state_machine.coordinator.state);
    }
}
