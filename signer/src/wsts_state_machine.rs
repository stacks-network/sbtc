//! Utilities for constructing and loading WSTS state machines

use crate::error;
use crate::storage;

use crate::codec::Decode as _;
use wsts::state_machine::coordinator::Coordinator as _;
use wsts::traits::Signer as _;

/// Wrapper around a WSTS signer state machine
#[derive(Debug, Clone, PartialEq)]
pub struct SignerStateMachine(wsts::state_machine::signer::Signer<wsts::v2::Party>);

type WstsStateMachine = wsts::state_machine::signer::Signer<wsts::v2::Party>;

impl SignerStateMachine {
    /// Create a new state machine
    pub fn new(
        signers: impl IntoIterator<Item = p256k1::ecdsa::PublicKey>,
        threshold: u32,
        signer_private_key: p256k1::scalar::Scalar,
    ) -> Result<Self, error::Error> {
        let signer_pub_key = p256k1::ecdsa::PublicKey::new(&signer_private_key)?;
        let signers: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(id, key)| {
                id.try_into()
                    .map(|id| (id, key))
                    .map_err(|_| error::Error::TypeConversion)
            })
            .collect::<Result<_, _>>()?;

        let key_ids = signers
            .clone()
            .into_iter()
            .map(|(id, key)| (id + 1, key))
            .collect();

        let num_parties = signers
            .len()
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;
        let num_keys = num_parties;

        let id: u32 = *signers
            .iter()
            .find(|(_, key)| *key == &signer_pub_key)
            .ok_or_else(|| error::Error::MissingPublicKey)?
            .0;

        let public_keys = wsts::state_machine::PublicKeys { signers, key_ids };

        let key_ids = vec![id + 1];

        if threshold > num_keys {
            return Err(error::Error::InvalidConfiguration);
        };

        let state_machine = WstsStateMachine::new(
            threshold,
            num_parties,
            num_keys,
            id,
            key_ids,
            signer_private_key,
            public_keys,
        );

        Ok(Self(state_machine))
    }

    /// Create a state machine from loaded DKG shares for the given aggregate key
    pub async fn load<S>(
        storage: &mut S,
        aggregate_key: p256k1::point::Point,
        signers: impl IntoIterator<Item = p256k1::ecdsa::PublicKey>,
        threshold: u32,
        signer_private_key: p256k1::scalar::Scalar,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead + storage::DbWrite,
        error::Error: From<<S as storage::DbRead>::Error>,
        error::Error: From<<S as storage::DbWrite>::Error>,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(&aggregate_key.x().to_bytes().to_vec())
            .await?
            .ok_or(error::Error::MissingDkgShares)?;

        let decrypted = wsts::util::decrypt(
            &signer_private_key.to_bytes(),
            &encrypted_shares.encrypted_shares,
        )
        .map_err(|_| error::Error::Encryption)?;

        let saved_state =
            wsts::traits::SignerState::decode(decrypted.as_slice()).map_err(error::Error::Codec)?;

        // This may panic if the saved state doesn't contain exactly one party,
        // however, that should never be the case since wsts maintains this invariant
        // when we save the state.
        let signer = wsts::v2::Party::load(&saved_state);

        let mut state_machine = Self::new(signers, threshold, signer_private_key)?;

        state_machine.0.signer = signer;

        Ok(state_machine)
    }
}

impl std::ops::Deref for SignerStateMachine {
    type Target = WstsStateMachine;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SignerStateMachine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Wrapper around a WSTS coordinator state machine
#[derive(Debug, Clone, PartialEq)]
pub struct CoordinatorStateMachine(WstsCoordinator);

type WstsCoordinator = wsts::state_machine::coordinator::frost::Coordinator<wsts::v2::Aggregator>;

impl CoordinatorStateMachine {
    /// Create a new state machine
    pub fn new(
        signers: impl IntoIterator<Item = p256k1::ecdsa::PublicKey>,
        threshold: u32,
        message_private_key: p256k1::scalar::Scalar,
    ) -> Result<Self, error::Error> {
        let signer_public_keys: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(idx, key)| {
                (
                    idx.try_into().unwrap(),
                    (&p256k1::point::Compressed::from(key.to_bytes()))
                        .try_into()
                        .expect("failed to convert public key"),
                )
            })
            .collect();

        let num_signers = signer_public_keys.len().try_into().unwrap();
        let num_keys = num_signers;
        let dkg_threshold = num_keys;
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id).collect()))
            .collect();
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            signer_key_ids,
            signer_public_keys,
        };

        let wsts_coordinator = WstsCoordinator::new(config);
        Ok(Self(wsts_coordinator))
    }

    /// Create a new coordinator state machine from loaded DkgPublicShares messages
    /// for the given aggregate key
    pub async fn load<S>(
        _storage: &mut S,
        _aggregate_key: p256k1::point::Point,
        _signers: impl IntoIterator<Item = p256k1::ecdsa::PublicKey>,
        _threshold: u32,
        _message_private_key: p256k1::scalar::Scalar,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead + storage::DbWrite,
        error::Error: From<<S as storage::DbRead>::Error>,
        error::Error: From<<S as storage::DbWrite>::Error>,
    {
        // TODO(317): (Link ticket) - add storage implementation for DKG public shares,
        // ensure they are persisted in the signer and implement this function.
        //
        // Note that while the WSTS coordinator struct holds a lot of ephemeral state,
        // the `party_polynomials` is the only field we need to load to coordinate signing
        // rounds. There is no interface to write this directly, so a workaround to set this is to
        // call `.gather_public_shares` on persisted public shares to get this in place.
        todo!();
    }
}

impl std::ops::Deref for CoordinatorStateMachine {
    type Target = WstsCoordinator;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for CoordinatorStateMachine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
