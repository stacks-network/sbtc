//! Helper types and functions for testing.

use std::{collections::HashMap, time::Duration};

use rand::rngs::OsRng;
use secp256k1::XOnlyPublicKey;
use wsts::{
    net::{Message, NonceRequest, NonceResponse, SignatureShareRequest, SignatureType},
    state_machine::{
        coordinator::{frost, test as wsts_test},
        signer::Signer,
    },
    v2,
};

use crate::{
    keys::PublicKey,
    wsts_state_machine::{FrostCoordinator, WstsCoordinator as _},
};

use super::{verification::StateMachine, wsts::WstsNetMessageType};

pub struct TestSetup {
    pub state_machine: StateMachine,
    pub signers: Vec<Signer<v2::Party>>,
    #[allow(dead_code)]
    pub aggregate_key: XOnlyPublicKey,
}

impl TestSetup {
    pub fn setup(num_parties: u32) -> Self {
        if num_parties == 0 {
            panic!("must have at least 1 parties");
        }

        let (coordinators, signers) =
            wsts_test::run_dkg::<frost::Coordinator<v2::Aggregator>, v2::Party>(num_parties, 5);

        let aggregate_key = pubkey_xonly();
        let coordinator: FrostCoordinator = coordinators.into_iter().next().unwrap().into();
        let state_machine = StateMachine::new(coordinator, aggregate_key, Duration::from_secs(60))
            .expect("failed to create new dkg verification state machine");

        Self {
            state_machine,
            signers,
            aggregate_key,
        }
    }

    pub fn sender(&self, index: usize) -> PublicKey {
        self.state_machine
            .coordinator
            .get_config()
            .signer_public_keys
            .iter()
            .map(|(_, point)| crate::keys::PublicKey::try_from(point))
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to convert public keys")[index]
    }
}

pub fn pubkey_xonly() -> secp256k1::XOnlyPublicKey {
    let keypair = secp256k1::Keypair::new_global(&mut OsRng);
    keypair.x_only_public_key().0
}

pub fn nonce_request(dkg_id: u64, sign_id: u64, sign_iter_id: u64) -> Message {
    Message::NonceRequest(NonceRequest {
        dkg_id,
        sign_id,
        sign_iter_id,
        message: vec![0; 5],
        signature_type: SignatureType::Taproot(None),
    })
}

pub fn nonce_response(dkg_id: u64, sign_id: u64, sign_iter_id: u64, signer_id: u32) -> Message {
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

pub fn signature_share_request(
    dkg_id: u64,
    sign_id: u64,
    sign_iter_id: u64,
    nonce_responses: Vec<NonceResponse>,
) -> Message {
    Message::SignatureShareRequest(SignatureShareRequest {
        dkg_id,
        sign_id,
        sign_iter_id,
        message: vec![0; 5],
        signature_type: SignatureType::Taproot(None),
        nonce_responses,
    })
}

/// Helpers for the [`StateMachine`] type.
impl StateMachine {
    /// Asserts the message counts for the given message type. Returns
    /// `true` if the counts match the expected values, and `false`
    /// otherwise, printing the mismatches to stderr. Intended to be used
    /// together with [`assert!`].
    pub fn message_counts(
        &self,
        message_type: WstsNetMessageType,
        expected_total: usize,
        expected_pending: usize,
    ) -> bool {
        let total_count = self.total_message_count(message_type);
        let pending_count = self.pending_message_count(message_type);

        let mut results = Vec::new();

        // Check the total counts.
        if total_count != expected_total {
            results.push(format!(
                "expected {} total messages of type {:?}, got {}",
                expected_total, message_type, total_count
            ));
        }

        // Check the pending counts.
        if pending_count != expected_pending {
            results.push(format!(
                "expected {} pending messages of type {:?}, got {}",
                expected_pending, message_type, pending_count
            ));
        }

        if results.is_empty() {
            true
        } else {
            eprintln!("!! message count assertions failed:");
            for result in results {
                eprintln!(" - {}", result);
            }
            false
        }
    }

    /// Prints message statistics for this [`StateMachine`] to `stderr`.
    pub fn print_message_stats(&self) {
        let message_types = vec![
            WstsNetMessageType::NonceRequest,
            WstsNetMessageType::NonceResponse,
            WstsNetMessageType::SignatureShareRequest,
            WstsNetMessageType::SignatureShareResponse,
        ];

        eprintln!("-- MESSAGE STATS --");
        for message_type in &message_types {
            eprintln!(
                "{:?} messages: total: {}, pending: {}",
                message_type,
                self.total_message_count(*message_type),
                self.pending_message_count(*message_type),
            );
        }

        eprintln!();
        for message_type in message_types {
            let stats: HashMap<PublicKey, (usize, usize)> = HashMap::new();
            let messages = self
                .wsts_messages
                .get(&message_type)
                .unwrap_or(&vec![])
                .iter()
                .fold(stats, |mut acc, msg| {
                    let entry = acc.entry(msg.sender).or_insert((0, 0));
                    entry.0 += 1;
                    if msg.processed {
                        entry.1 += 1;
                    }
                    acc
                });

            eprintln!("{:?} messages:", message_type);
            for (sender, processed) in messages {
                eprintln!(
                    " - sender: {:?}: total: {}, processed: {}",
                    &sender.to_string()[..16],
                    processed.0,
                    processed.1,
                );
            }
        }
    }

    /// Gets the number of pending messages of the given type that are currently
    /// stored in this [`StateMachine`].
    pub fn pending_message_count(&self, message_type: WstsNetMessageType) -> usize {
        self.wsts_messages
            .get(&message_type)
            .unwrap_or(&vec![])
            .iter()
            .filter(|msg| !msg.processed)
            .count()
    }

    /// Gets the number of buffered messages of the given type that are
    /// currently stored in this [`StateMachine`].
    #[cfg(test)]
    pub fn total_message_count(&self, message_type: WstsNetMessageType) -> usize {
        // The `_ as u32` should be safe here since we know that the number of
        // signers is far less than `u32::MAX`, and each message is deduplicated
        // by the sender's public key, which is also validated to be a valid
        // member of the signer set.
        self.wsts_messages
            .get(&message_type)
            .unwrap_or(&vec![])
            .len()
    }

    /// Gets the number of signers that are expected to participate in the DKG
    /// verification.
    #[cfg(test)]
    pub fn signer_count(&self) -> u32 {
        self.coordinator.get_config().num_signers
    }
}

/// Macro to assert the state of a state machine.
///
/// # Arguments
/// * `$state_machine:expr` - The state machine to check
/// * `$expected_state:pat` - The expected state pattern to match against
///
/// # Examples
/// ```
/// assert_state!(state_machine, State::Signing);
/// ```
macro_rules! assert_state {
    ($state_machine:expr, $expected_state:pat) => {
        assert!(matches!($state_machine.state, $expected_state))
    };
}

/// Macro to assert the allowed message type for a state machine.
///
/// # Arguments
/// * `$state_machine:expr` - The state machine to check
/// * `$expected_type:expr` - The expected message type
///
/// # Examples
/// ```
/// assert_allowed_msg_type!(state_machine, WstsNetMessageType::NonceRequest);
/// ```
macro_rules! assert_allowed_msg_type {
    ($state_machine:expr, $expected_type:expr) => {{
        let current_allowed_message_type =
            $state_machine.current_processable_message_type().unwrap();
        assert_eq!(
            current_allowed_message_type, $expected_type,
            "expected allowed message type {:?}, got {:?}",
            $expected_type, current_allowed_message_type
        )
    }};
}

/// Convenience macro for asserting the message counts for a [`StateMachine`].
///
/// # Example
/// ```rust
/// assert_message_counts!(state_machine,
///     NonceRequest => all: 0;
///     NonceResponse => total: 0;
///     SignatureShareRequest => pending: 0;
///     SignatureShareResponse => total: 0, pending: 0;
/// );
/// ```
macro_rules! assert_message_counts {
    ($state_machine:expr, $($msg_type:ident => $($field:ident: $value:expr),* $(, )?);* $(;)?) => {
        $({
            let mut expected_total = None;
            let mut expected_pending = None;
            $(
                match stringify!($field) {
                    "total" => expected_total = Some($value),
                    "pending" => expected_pending = Some($value),
                    "all" => {
                        if expected_total.is_some() || expected_pending.is_some() {
                            panic!("cannot specify 'all' together with 'total' or 'pending'");
                        }
                        expected_total = Some($value);
                        expected_pending = Some($value);
                    }
                    _ => panic!("unknown field: {}. Expected 'all', 'total', or 'pending'", stringify!($field)),
                }
            )*
            let expected_total = expected_total.expect("expected 'total' or 'all' to be specified");
            let expected_pending = expected_pending.expect("expected 'pending' or 'all' to be specified");
            assert!(
                $state_machine.message_counts(
                    WstsNetMessageType::$msg_type,
                    expected_total,
                    expected_pending
                ),
                "message count assertion failed for {:?}",
                WstsNetMessageType::$msg_type
            );
        })*
    };
}
