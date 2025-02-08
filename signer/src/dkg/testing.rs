//! Helper types and functions for testing.

use std::time::Duration;

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
    keys::{PrivateKey, PublicKey},
    wsts_state_machine::FrostCoordinator,
};

use super::verification::StateMachine;

pub struct TestSetup {
    pub state_machine: StateMachine,
    pub signers: Vec<Signer<v2::Party>>,
    pub senders: Vec<PublicKey>,
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
        let state_machine = StateMachine::new(coordinator, aggregate_key, Duration::from_secs(60));

        Self {
            state_machine,
            signers,
            senders: (0..num_parties).map(|_| pubkey()).collect(),
            aggregate_key,
        }
    }
}

pub fn pubkey() -> PublicKey {
    let keypair = secp256k1::Keypair::new_global(&mut OsRng);
    PublicKey::from_private_key(&PrivateKey::from(keypair.secret_key()))
}

pub fn pubkey_xonly() -> secp256k1::XOnlyPublicKey {
    let keypair = secp256k1::Keypair::new_global(&mut OsRng);
    keypair.x_only_public_key().0
}

pub fn keypair() -> (PrivateKey, PublicKey) {
    let keypair = secp256k1::Keypair::new_global(&mut OsRng);
    let private_key = PrivateKey::from(keypair.secret_key());
    let public_key = PublicKey::from_private_key(&private_key);
    (private_key, public_key)
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
        message: vec![],
        signature_type: SignatureType::Taproot(None),
        nonce_responses,
    })
}
