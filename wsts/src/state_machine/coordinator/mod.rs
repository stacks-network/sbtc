use crate::{
    common::PolyCommitment,
    curve::{point::Point, scalar::Scalar},
    errors::AggregatorError,
    net::{Message, NonceResponse, SignatureType},
    state_machine::{DkgFailure, OperationResult, StateMachine},
};
use core::{cmp::PartialEq, fmt::Debug};
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Default, Debug, PartialEq)]
/// Coordinator states
pub enum State {
    /// The coordinator is idle
    #[default]
    Idle,
    /// The coordinator is asking signers to send public shares
    DkgPublicDistribute,
    /// The coordinator is gathering public shares
    DkgPublicGather,
    /// The coordinator is asking signers to send private shares
    DkgPrivateDistribute,
    /// The coordinator is gathering private shares
    DkgPrivateGather,
    /// The coordinator is asking signers to compute shares and send end
    DkgEndDistribute,
    /// The coordinator is gathering DKG End messages
    DkgEndGather,
    /// The coordinator is requesting nonces
    NonceRequest(SignatureType),
    /// The coordinator is gathering nonces
    NonceGather(SignatureType),
    /// The coordinator is requesting signature shares
    SigShareRequest(SignatureType),
    /// The coordinator is gathering signature shares
    SigShareGather(SignatureType),
}

#[derive(thiserror::Error, Clone, Debug)]
#[allow(clippy::large_enum_variant)]
/// The error type for the coordinator
pub enum Error {
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
    /// A bad dkg_id in received message
    #[error("Bad dkg_id: got {0} expected {1}")]
    BadDkgId(u64, u64),
    /// A bad sign_id in received message
    #[error("Bad sign_id: got {0} expected {1}")]
    BadSignId(u64, u64),
    /// A bad sign_iter_id in received message
    #[error("Bad sign_iter_id: got {0} expected {1}")]
    BadSignIterId(u64, u64),
    /// A malicious signer sent the received message
    #[error("Malicious signer {0}")]
    MaliciousSigner(u32),
    /// SignatureAggregator error
    #[error("Aggregator: {0}")]
    Aggregator(AggregatorError),
    /// Schnorr proof failed to verify
    #[error("Schnorr Proof failed to verify")]
    SchnorrProofFailed,
    /// No aggregate public key set
    #[error("No aggregate public key set")]
    MissingAggregatePublicKey,
    /// No schnorr proof set
    #[error("No schnorr proof set")]
    MissingSchnorrProof,
    /// No signature set
    #[error("No signature set")]
    MissingSignature,
    /// Missing message response information for a signing round
    #[error("Missing message nonce information")]
    MissingMessageNonceInfo,
    /// DKG failure from signers
    #[error("DKG failure from signers")]
    DkgFailure(HashMap<u32, DkgFailure>),
    /// Aggregate key does not match supplied party polynomial
    #[error(
        "Aggregate key and computed key from party polynomials mismatch: got {0}, expected {1}"
    )]
    AggregateKeyPolynomialMismatch(Point, Point),
    /// Supplied party polynomial contained duplicate party IDs
    #[error("Supplied party polynomials contained a duplicate party ID")]
    DuplicatePartyId,
}

impl From<AggregatorError> for Error {
    fn from(err: AggregatorError) -> Self {
        Error::Aggregator(err)
    }
}

/// Config fields common to all Coordinators
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Config {
    /// total number of signers
    pub num_signers: u32,
    /// total number of keys
    pub num_keys: u32,
    /// threshold of keys needed to form a valid signature
    pub threshold: u32,
    /// threshold of keys needed to complete DKG (must be >= threshold)
    pub dkg_threshold: u32,
    /// private key used to sign network messages
    pub message_private_key: Scalar,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
    /// ECDSA public keys as Point objects indexed by signer_id
    pub signer_public_keys: HashMap<u32, Point>,
}

impl Config {
    /// Create a new config object with no timeouts
    pub fn new(
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold: num_keys,
            message_private_key,
            signer_key_ids: Default::default(),
            signer_public_keys: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
/// The info for a sign round over specific message bytes
pub struct SignRoundInfo {
    /// the nonce response of a signer id
    pub public_nonces: BTreeMap<u32, NonceResponse>,
    /// which key_ids we've received nonces for this iteration
    pub nonce_recv_key_ids: HashSet<u32>,
    /// which key_ids we're received sig shares for this iteration
    pub sign_recv_key_ids: HashSet<u32>,
    /// which signer_ids we're expecting sig shares from this iteration
    pub sign_wait_signer_ids: HashSet<u32>,
}

/// Coordinator trait for handling the coordination of DKG and sign messages
pub trait Coordinator: Clone + Debug + PartialEq + StateMachine<State, Error> {
    /// Create a new Coordinator
    fn new(config: Config) -> Self;

    /// Retrieve the config
    fn get_config(&self) -> Config;

    /// Initialize Coordinator from partial saved state
    fn set_key_and_party_polynomials(
        &mut self,
        aggregate_key: Point,
        party_polynomials: Vec<(u32, PolyCommitment)>,
    ) -> Result<(), Error>;

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        messages: &[Message],
    ) -> Result<(Vec<Message>, Vec<OperationResult>), Error>;

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point>;

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>);

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8>;

    /// Retrive the current state
    fn get_state(&self) -> State;

    /// Trigger a DKG round
    fn start_dkg_round(&mut self) -> Result<Message, Error>;

    /// Trigger a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
    ) -> Result<Message, Error>;

    /// Reset internal state
    fn reset(&mut self);
}

/// The coordinator for the FROST algorithm
pub mod frost;

/// The coordinator for the FIRE algorithm
pub mod fire;

#[allow(missing_docs)]
pub mod test {
    use rand_core::OsRng;
    use std::collections::{HashMap, HashSet};
    use std::sync::Once;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use crate::{
        common::SignatureShare,
        compute,
        curve::{ecdsa, point::Point, point::G, scalar::Scalar},
        errors::AggregatorError,
        net::{DkgFailure, Message, SignatureShareResponse, SignatureType},
        state_machine::{
            coordinator::{Config, Coordinator as CoordinatorTrait, Error, State},
            signer::{Error as SignerError, Signer},
            DkgError, Error as StateMachineError, OperationResult, PublicKeys, SignError,
            StateMachine,
        },
        util::create_rng,
    };

    static INIT: Once = Once::new();

    pub fn new_coordinator<Coordinator: CoordinatorTrait>() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let coordinator = Coordinator::new(config.clone());

        assert_eq!(coordinator.get_config().num_signers, config.num_signers);
        assert_eq!(coordinator.get_config().num_keys, config.num_keys);
        assert_eq!(coordinator.get_config().threshold, config.threshold);
        assert_eq!(
            coordinator.get_config().message_private_key,
            config.message_private_key
        );
        assert_eq!(coordinator.get_state(), State::Idle);
    }

    pub fn coordinator_state_machine<Coordinator: CoordinatorTrait + StateMachine<State, Error>>() {
        let mut rng = create_rng();
        let config = Config::new(3, 3, 3, Scalar::random(&mut rng));
        let mut coordinator = Coordinator::new(config);
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicGather).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_ok());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateGather).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgEndDistribute).unwrap();
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_ok());

        coordinator.move_to(State::DkgEndGather).unwrap();
        assert!(coordinator.can_move_to(&State::Idle).is_ok());
    }

    pub fn start_dkg_round<Coordinator: CoordinatorTrait>() {
        let mut rng = create_rng();
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = Coordinator::new(config);
        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        if let Message::DkgBegin(dkg_begin) = result.unwrap() {
            assert_eq!(dkg_begin.dkg_id, 1);
        } else {
            panic!("Bad dkg_id");
        }
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
    }

    pub fn setup<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<Coordinator>, Vec<Signer>) {
        INIT.call_once(|| {
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .init();
        });

        let mut rng = create_rng();
        let num_keys = num_signers * keys_per_signer;
        let threshold = (num_keys * 7) / 10;
        let dkg_threshold = (num_keys * 9) / 10;
        let key_pairs = (0..num_signers)
            .map(|_| {
                let private_key = Scalar::random(&mut rng);
                let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
                (private_key, public_key)
            })
            .collect::<Vec<(Scalar, ecdsa::PublicKey)>>();
        let mut key_id: u32 = 1;
        let mut signer_ids_map = HashMap::new();
        let mut signer_key_ids = HashMap::new();
        let mut signer_key_ids_set = HashMap::new();
        let mut signer_public_keys = HashMap::new();
        let mut key_ids_map = HashMap::new();
        for (i, (private_key, public_key)) in key_pairs.iter().enumerate() {
            let mut key_ids = Vec::new();
            let mut key_ids_set = HashSet::new();
            for _ in 0..keys_per_signer {
                key_ids_map.insert(key_id, *public_key);
                key_ids.push(key_id);
                key_ids_set.insert(key_id);
                key_id += 1;
            }
            signer_ids_map.insert(i as u32, *public_key);
            signer_key_ids.insert(i as u32, key_ids);
            signer_key_ids_set.insert(i as u32, key_ids_set);
            signer_public_keys.insert(i as u32, Point::from(private_key));
        }
        let public_keys = PublicKeys {
            signers: signer_ids_map,
            key_ids: key_ids_map,
            signer_key_ids: signer_key_ids_set.clone(),
        };

        let signers = key_pairs
            .iter()
            .enumerate()
            .map(|(signer_id, (private_key, _public_key))| {
                Signer::new(
                    threshold,
                    dkg_threshold,
                    num_signers,
                    num_keys,
                    signer_id as u32,
                    signer_key_ids[&(signer_id as u32)].clone(),
                    *private_key,
                    public_keys.clone(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect::<Vec<Signer>>();
        let coordinators = key_pairs
            .into_iter()
            .map(|(private_key, _public_key)| {
                let config = Config {
                    num_signers,
                    num_keys,
                    threshold,
                    dkg_threshold,
                    message_private_key: private_key,
                    signer_key_ids: signer_key_ids_set.clone(),
                    signer_public_keys: signer_public_keys.clone(),
                };
                Coordinator::new(config)
            })
            .collect::<Vec<Coordinator>>();
        (coordinators, signers)
    }

    /// Helper function for feeding messages back from the processor into the signing rounds and coordinators
    pub fn feedback_messages<Coordinator: CoordinatorTrait>(
        coordinators: &mut [Coordinator],
        signers: &mut [Signer],
        messages: &[Message],
    ) -> (Vec<Message>, Vec<OperationResult>) {
        feedback_mutated_messages(coordinators, signers, messages, |_signer, msgs| msgs)
    }

    /// Helper function for feeding mutated messages back from the processor into the signing rounds and coordinators
    pub fn feedback_mutated_messages<C, F>(
        coordinators: &mut [C],
        signers: &mut [Signer],
        messages: &[Message],
        signer_mutator: F,
    ) -> (Vec<Message>, Vec<OperationResult>)
    where
        F: Fn(&Signer, Vec<Message>) -> Vec<Message>,
        C: CoordinatorTrait,
    {
        feedback_mutated_messages_with_errors(coordinators, signers, messages, signer_mutator)
            .unwrap()
    }

    /// Helper function for feeding mutated messages back from the processor into the signing rounds and coordinators
    pub fn feedback_messages_with_errors<Coordinator: CoordinatorTrait>(
        coordinators: &mut [Coordinator],
        signers: &mut [Signer],
        messages: &[Message],
    ) -> Result<(Vec<Message>, Vec<OperationResult>), StateMachineError> {
        feedback_mutated_messages_with_errors(coordinators, signers, messages, |_signer, msgs| msgs)
    }

    /// Helper function for feeding mutated messages back from the processor into the signing rounds and coordinators
    pub fn feedback_mutated_messages_with_errors<C, F>(
        coordinators: &mut [C],
        signers: &mut [Signer],
        messages: &[Message],
        signer_mutator: F,
    ) -> Result<(Vec<Message>, Vec<OperationResult>), StateMachineError>
    where
        F: Fn(&Signer, Vec<Message>) -> Vec<Message>,
        C: CoordinatorTrait,
    {
        let mut inbound_messages = vec![];
        let mut feedback_messages = vec![];
        let mut rng = create_rng();
        for signer in signers.iter_mut() {
            let outbound_messages = signer.process_inbound_messages(messages, &mut rng)?;
            let outbound_messages = signer_mutator(signer, outbound_messages);
            feedback_messages.extend_from_slice(outbound_messages.as_slice());
            inbound_messages.extend(outbound_messages);
        }
        for signer in signers.iter_mut() {
            let outbound_messages =
                signer.process_inbound_messages(&feedback_messages, &mut rng)?;
            inbound_messages.extend(outbound_messages);
        }
        for coordinator in coordinators.iter_mut() {
            // Process all coordinator messages, but don't bother with propogating these results
            let _ = coordinator.process_inbound_messages(messages)?;
        }
        let mut results = vec![];
        let mut messages = vec![];
        for (i, coordinator) in coordinators.iter_mut().enumerate() {
            let (outbound_messages, outbound_results) =
                coordinator.process_inbound_messages(&inbound_messages)?;
            // Only propogate a single coordinator's messages and results
            if i == 0 {
                messages.extend(outbound_messages);
                results.extend(outbound_results);
            }
        }
        Ok((messages, results))
    }

    pub fn run_dkg<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<Coordinator>, Vec<Signer>) {
        let (mut coordinators, mut signers) = setup::<Coordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in coordinators.iter() {
                    assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                    assert_eq!(coordinator.get_state(), State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // clear the polynomials before persisting
        for signer in &mut signers {
            signer.signer.clear_polys();
        }

        (coordinators, signers)
    }

    pub fn run_sign<Coordinator: CoordinatorTrait>(
        coordinators: &mut [Coordinator],
        signers: &mut [Signer],
        msg: &[u8],
        signature_type: SignatureType,
    ) -> OperationResult {
        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(coordinators, signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(coordinators, signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                if let SignatureType::Frost = signature_type {
                    for coordinator in coordinators.iter() {
                        assert!(sig.verify(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!"),
                            msg
                        ));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::Sign");
                }
            }
            OperationResult::SignSchnorr(sig) => {
                if let SignatureType::Schnorr = signature_type {
                    for coordinator in coordinators.iter() {
                        assert!(sig.verify(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!")
                                .x(),
                            msg
                        ));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::SignSchnorr");
                }
            }
            OperationResult::SignTaproot(sig) => {
                if let SignatureType::Taproot = signature_type {
                    for coordinator in coordinators.iter() {
                        let tweaked_public_key = compute::tweaked_public_key(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!"),
                            None,
                        );

                        assert!(sig.verify(&tweaked_public_key.x(), msg));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::SignTaproot");
                }
            }
            _ => panic!("Expected OperationResult"),
        }

        operation_results[0].clone()
    }

    pub fn run_dkg_sign<Coordinator: CoordinatorTrait>(num_signers: u32, keys_per_signer: u32) {
        let (mut coordinators, mut signers) = run_dkg::<Coordinator>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();

        run_sign::<Coordinator>(&mut coordinators, &mut signers, &msg, SignatureType::Frost);
        run_sign::<Coordinator>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Schnorr,
        );
        run_sign::<Coordinator>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Taproot,
        );
    }

    /// Run DKG then sign a message, but alter the signature shares for signer 0.  This should trigger the aggregator internal check_signature_shares function to run and determine which parties signatures were bad.
    /// Because of the differences between how parties are represented in v1 and v2, we need to pass in a vector of the expected bad parties.
    pub fn check_signature_shares<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
        signature_type: SignatureType,
        bad_parties: Vec<u32>,
    ) {
        let (mut coordinators, mut signers) = run_dkg::<Coordinator>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &outbound_messages,
            |signer, messages| {
                if signer.signer_id == 0 {
                    messages
                        .iter()
                        .map(|message| {
                            if let Message::SignatureShareResponse(response) = message {
                                // mutate one of the shares
                                let sshares: Vec<SignatureShare> = response
                                    .signature_shares
                                    .iter()
                                    .map(|share| SignatureShare {
                                        id: share.id,
                                        key_ids: share.key_ids.clone(),
                                        z_i: share.z_i + Scalar::from(1),
                                    })
                                    .collect();
                                Message::SignatureShareResponse(SignatureShareResponse {
                                    dkg_id: response.dkg_id,
                                    sign_id: response.sign_id,
                                    sign_iter_id: response.sign_iter_id,
                                    signer_id: response.signer_id,
                                    signature_shares: sshares,
                                })
                            } else {
                                message.clone()
                            }
                        })
                        .collect()
                } else {
                    messages.clone()
                }
            },
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::SignError(SignError::Coordinator(Error::Aggregator(AggregatorError::BadPartySigs(parties)))) => {
		if parties != &bad_parties {
		    panic!("Expected BadPartySigs from {:?}, got {:?}", &bad_parties, &operation_results[0]);
		}
	    }
            _ => panic!("Expected OperationResult::SignError(SignError::Coordinator(Error::Aggregator(AggregatorError::BadPartySigs(parties))))"),
        }
    }

    /// Test that a signer will not sign twice with the same nonce. This is
    /// a defense against a malicious coordinator who requests multiple
    /// signing rounds with no nonce round in between to generate a new
    /// nonce.
    ///
    /// So we test that:
    /// * signers will not return a signature share unless they have
    ///   received a nonce request first.
    /// * signers will return at most one signature share after they have
    ///   received a nonce request.
    pub fn gen_nonces<Coordinator: CoordinatorTrait>(num_signers: u32, keys_per_signer: u32) {
        let mut rng = OsRng;

        let (mut coordinators, mut signers) = run_dkg::<Coordinator>(num_signers, keys_per_signer);

        let all_thresholds = coordinators
            .iter()
            .map(|c| c.get_config().threshold)
            .collect::<std::collections::BTreeSet<u32>>();
        let threshold = *all_thresholds.first().unwrap() as usize;

        assert_eq!(all_thresholds.len(), 1);
        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();

        let signature_type = SignatureType::Frost;

        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the NonceRequest to the first three signers and gather
        // NonceResponses by sharing with all other signers and
        // coordinator. Later we will send signature share requests to all
        // signers, and the first three will sign exactly once, the last
        // two will not.
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers[..threshold], &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        // Once the coordinator has received sufficient NonceResponses,
        // it should send out a SignatureShareRequest
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // The last signers haven't seen the nonce request yet, so they
        // will return an error if given a signature share request where
        // they think that they are part of the signing set. However, by
        // default they won't think they are part of the signing set, so we
        // need to modify the message a little.
        signers.iter_mut().skip(threshold).for_each(|signer| {
            let mut outbound_messages = outbound_messages.clone();
            if let Message::SignatureShareRequest(ref mut request) = outbound_messages[0] {
                request.nonce_responses[0].signer_id = signer.signer_id;
            } else {
                panic!("failed to match message");
            }

            let response = signer.process(&outbound_messages[0], &mut rng).unwrap_err();

            assert!(matches!(
                response,
                SignerError::Aggregator(AggregatorError::MissingNonce)
            ));
        });

        // For the signers that are part of the signing set, they should
        // successfully return a signature share. We check that the
        // signature shares are distinct.
        let z_is = signers
            .iter_mut()
            .take(threshold)
            .map(|signer| {
                let response = signer.process(&outbound_messages[0], &mut rng).unwrap();

                assert_eq!(response.len(), 1);

                let Message::SignatureShareResponse(response) = &response[0] else {
                    panic!("Message should have been SignatureShareResponse");
                };
                assert_eq!(response.signature_shares.len(), 1);
                response.signature_shares[0].z_i
            })
            .collect::<HashSet<Scalar>>();

        // Are they distinct?
        assert_eq!(z_is.len(), threshold);

        // Now if these signers get another signature share request, they
        // should return an error.
        signers.iter_mut().take(threshold).for_each(|signer| {
            let response = signer.process(&outbound_messages[0], &mut rng).unwrap_err();

            assert!(matches!(
                response,
                SignerError::Aggregator(AggregatorError::MissingNonce)
            ));
        });
    }

    pub fn bad_signature_share_request<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (mut coordinators, mut signers) = run_dkg::<Coordinator>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();

        // Start a signing round
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        let messages = outbound_messages.clone();
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &messages);
        assert!(result.is_ok());

        // test request with no NonceResponses
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            request.nonce_responses.clear();
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }

        // test request with a duplicate NonceResponse
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            request
                .nonce_responses
                .push(request.nonce_responses[0].clone());
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }

        // test request with an out of range signer_id
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            request.nonce_responses[0].signer_id = num_signers;
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }
    }

    pub fn invalid_nonce<Coordinator: CoordinatorTrait>(num_signers: u32, keys_per_signer: u32) {
        let (mut coordinators, mut signers) = run_dkg::<Coordinator>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();

        // Start a signing round
        let signature_type = SignatureType::Frost;
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        let messages = outbound_messages.clone();
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &messages);
        assert!(result.is_ok());

        // test request with NonceResponse having zero nonce
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            for nonce_response in &mut request.nonce_responses {
                for nonce in &mut nonce_response.nonces {
                    nonce.D = Point::new();
                    nonce.E = Point::new();
                }
            }
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }

        // test request with NonceResponse having generator nonce
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            for nonce_response in &mut request.nonce_responses {
                for nonce in &mut nonce_response.nonces {
                    nonce.D = G;
                    nonce.E = G;
                }
            }
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }

        // test request with a duplicate NonceResponse
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            request
                .nonce_responses
                .push(request.nonce_responses[0].clone());
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }

        // test request with an out of range signer_id
        let mut packet = outbound_messages[0].clone();
        if let Message::SignatureShareRequest(ref mut request) = packet {
            request.nonce_responses[0].signer_id = num_signers;
        } else {
            panic!("failed to match message");
        }

        // Send the SignatureShareRequest message to all signers and share
        // their responses with the coordinator and signers
        let result = feedback_messages_with_errors(&mut coordinators, &mut signers, &[packet]);
        if !matches!(
            result,
            Err(StateMachineError::Signer(SignerError::InvalidNonceResponse))
        ) {
            panic!("Should have received signer invalid nonce response error, got {result:?}");
        }
    }

    pub fn empty_public_shares<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (mut coordinators, mut signers) = setup::<Coordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[message],
            |signer, packets| {
                if signer.signer_id == 0 {
                    packets
                        .iter()
                        .map(|packet| {
                            if let Message::DkgPublicShares(shares) = &packet {
                                let public_shares = crate::net::DkgPublicShares {
                                    dkg_id: shares.dkg_id,
                                    signer_id: shares.signer_id,
                                    comms: vec![],
                                };
                                Message::DkgPublicShares(public_shares)
                            } else {
                                packet.clone()
                            }
                        })
                        .collect()
                } else {
                    packets.clone()
                }
            },
        );
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message")
            }
        }

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => {
                if let DkgError::DkgEndFailure(dkg_failures) = dkg_error {
                    if dkg_failures.len() != num_signers as usize {
                        panic!(
                            "Expected {num_signers} DkgFailures got {}",
                            dkg_failures.len()
                        );
                    }
                    let expected_signer_ids = (0..1).collect::<HashSet<u32>>();
                    for dkg_failure in dkg_failures {
                        if let (_, DkgFailure::MissingPublicShares(signer_ids)) = dkg_failure {
                            if &expected_signer_ids != signer_ids {
                                panic!(
                                    "Expected signer_ids {:?} got {:?}",
                                    expected_signer_ids, signer_ids
                                );
                            }
                        } else {
                            panic!(
                                "Expected DkgFailure::MissingPublicShares got {:?}",
                                dkg_failure
                            );
                        }
                    }
                } else {
                    panic!("Expected DkgError::DkgEndFailure got {:?}", dkg_error);
                }
            }
            msg => panic!("Expected OperationResult::DkgError got {:?}", msg),
        }
    }

    pub fn empty_private_shares<Coordinator: CoordinatorTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (mut coordinators, mut signers) = setup::<Coordinator>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[outbound_messages[0].clone()],
            |signer, packets| {
                if signer.signer_id == 0 {
                    packets
                        .iter()
                        .map(|packet| {
                            if let Message::DkgPrivateShares(shares) = &packet {
                                let private_shares = crate::net::DkgPrivateShares {
                                    dkg_id: shares.dkg_id,
                                    signer_id: shares.signer_id,
                                    shares: vec![],
                                };
                                Message::DkgPrivateShares(private_shares)
                            } else {
                                packet.clone()
                            }
                        })
                        .collect()
                } else {
                    packets.clone()
                }
            },
        );
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0] {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::DkgError(dkg_error) => {
                if let DkgError::DkgEndFailure(dkg_failures) = dkg_error {
                    if dkg_failures.len() != num_signers as usize {
                        panic!(
                            "Expected {num_signers} DkgFailures got {}",
                            dkg_failures.len()
                        );
                    }
                    let expected_signer_ids = (0..1).collect::<HashSet<u32>>();
                    for dkg_failure in dkg_failures {
                        if let (_, DkgFailure::MissingPrivateShares(signer_ids)) = dkg_failure {
                            if &expected_signer_ids != signer_ids {
                                panic!(
                                    "Expected signer_ids {:?} got {:?}",
                                    expected_signer_ids, signer_ids
                                );
                            }
                        } else {
                            panic!(
                                "Expected DkgFailure::MissingPublicShares got {:?}",
                                dkg_failure
                            );
                        }
                    }
                } else {
                    panic!("Expected DkgError::DkgEndFailure got {:?}", dkg_error);
                }
            }
            msg => panic!("Expected OperationResult::DkgError got {:?}", msg),
        }
    }
}
