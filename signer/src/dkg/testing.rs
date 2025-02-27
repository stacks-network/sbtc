//! Helper types and functions for testing.

use std::collections::VecDeque;

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

/// A trait for converting a type to a [`PublicKey`].
pub trait AsPublicKey {
    /// Converts the implementing type to a [`PublicKey`].
    fn as_public_key(&self) -> PublicKey;
}

impl AsPublicKey for Signer<v2::Party> {
    fn as_public_key(&self) -> PublicKey {
        self.public_keys.signers[&self.signer_id].into()
    }
}

pub struct TestSetup {
    pub state_machine: StateMachine,
    signers: VecDeque<Signer<v2::Party>>,
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

        let signers = signers.into();
        let aggregate_key = pubkey_xonly();
        let coordinator: FrostCoordinator = coordinators.into_iter().next().unwrap().into();
        let state_machine = StateMachine::new(coordinator, aggregate_key, None)
            .expect("failed to create new dkg verification state machine");

        Self {
            state_machine,
            signers,
            aggregate_key,
        }
    }

    pub fn next_signer(&mut self) -> Signer<v2::Party> {
        self.signers.pop_front().expect("no more signers")
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
    /// Checks the message counts for the given message type. Returns
    /// `true` if the counts match the expected values, and `false`
    /// otherwise, printing the mismatches to stderr. Intended to be used
    /// together with [`assert!`].
    pub fn message_counts(
        &self,
        message_type: WstsNetMessageType,
        expected_total: Option<usize>,
        expected_pending: Option<usize>,
    ) -> bool {
        let total_count = self.total_message_count(message_type);
        let pending_count = self.pending_message_count(message_type);

        let mut results = Vec::new();

        // Check the total counts, if specified.
        if let Some(expected_total) = expected_total {
            // Check the total counts.
            if total_count != expected_total {
                results.push(format!(
                    "expected {expected_total} total messages of type {message_type:?}, got {total_count}"
                ));
            }
        }

        // Check the pending counts, if specified.
        if let Some(expected_pending) = expected_pending {
            if pending_count != expected_pending {
                results.push(format!(
                    "expected {expected_pending} pending messages of type {message_type:?}, got {pending_count}"
                ));
            }
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
    pub fn total_message_count(&self, message_type: WstsNetMessageType) -> usize {
        self.wsts_messages
            .get(&message_type)
            .unwrap_or(&vec![])
            .len()
    }

    /// Gets the number of signers that are expected to participate in the DKG
    /// verification.
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
/// To specify that both `total` and `pending` counts should be $value, the
/// format is:
/// ```rust
/// [`WstsMessageType`] => all: $value;
/// ```
///
/// To specify either `total`, `pending`, or both, the format is:
/// ```rust
/// [`WstsMessageType`] => total: $value, pending: $value;
/// ```
///
/// The `WstsMessageType` must be one of the variants of [`WstsNetMessageType`],
/// without the prefix.
///
/// # Example
///
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
        // For each "MessageType => field: value [,..];"" line...
        $({
            let mut expected_total = None;
            let mut expected_pending = None;
            // For each "field: value" pair...
            $(
                // Match the field and set the expected value, or panic if the
                // field is unknown.
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
            // If no field was specified, panic.
            if expected_total.is_none() && expected_pending.is_none() {
                panic!("expected 'total', 'pending' or 'all' to be specified");
            }
            // Perform our assertion.
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
