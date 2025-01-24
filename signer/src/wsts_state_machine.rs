//! Utilities for constructing and loading WSTS state machines

use std::collections::BTreeMap;

use crate::codec::Decode as _;
use crate::codec::Encode as _;
use crate::error;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::keys::SignerScriptPubKey as _;
use crate::storage;
use crate::storage::model;
use crate::storage::model::SigHash;

use bitcoin::hashes::Hash as _;
use hashbrown::HashMap;
use hashbrown::HashSet;
use wsts::common::PolyCommitment;
use wsts::state_machine::coordinator::Coordinator as _;
use wsts::state_machine::coordinator::State as WstsState;
use wsts::state_machine::StateMachine as _;
use wsts::traits::Signer as _;

/// An identifier for signer state machines.
///
/// Signer state machines are used for either DKG or signing rounds on
/// bitcoin. For DKG, the state machine is identified by the bitcoin block
/// hash bytes while for the signing rounds we identify the state machine
/// by the sighash bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateMachineId([u8; 32]);

impl From<&model::BitcoinBlockHash> for StateMachineId {
    fn from(value: &model::BitcoinBlockHash) -> Self {
        StateMachineId(value.to_byte_array())
    }
}

impl From<SigHash> for StateMachineId {
    fn from(value: SigHash) -> Self {
        StateMachineId(value.to_byte_array())
    }
}

#[cfg(any(test, feature = "testing"))]
impl StateMachineId {
    /// Create a new identifier
    pub fn new(value: [u8; 32]) -> Self {
        StateMachineId(value)
    }
}

/// Wrapper around a WSTS signer state machine
#[derive(Debug, Clone, PartialEq)]
pub struct SignerStateMachine(wsts::state_machine::signer::Signer<wsts::v2::Party>);

type WstsStateMachine = wsts::state_machine::signer::Signer<wsts::v2::Party>;

impl SignerStateMachine {
    /// Create a new state machine
    pub fn new(
        signers: impl IntoIterator<Item = PublicKey>,
        threshold: u32,
        signer_private_key: PrivateKey,
    ) -> Result<Self, error::Error> {
        let signer_pub_key = PublicKey::from_private_key(&signer_private_key);
        let signers: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(id, key)| (id as u32, p256k1::keys::PublicKey::from(&key)))
            .collect();

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
        let dkg_threshold = num_parties;

        let p256k1_public_key = p256k1::keys::PublicKey::from(&signer_pub_key);
        let id: u32 = *signers
            .iter()
            .find(|(_, key)| *key == &p256k1_public_key)
            .ok_or_else(|| error::Error::MissingPublicKey)?
            .0;

        let signer_key_ids: HashMap<u32, HashSet<u32>> = signers
            .iter()
            .map(|(&signer_id, _)| {
                let mut keys = HashSet::new();
                keys.insert(signer_id + 1);
                (signer_id, keys)
            })
            .collect();
        let public_keys = wsts::state_machine::PublicKeys {
            signers,
            key_ids,
            signer_key_ids,
        };

        let key_ids = vec![id + 1];

        if threshold > num_keys {
            return Err(error::Error::InvalidConfiguration);
        };

        let state_machine = WstsStateMachine::new(
            threshold,
            dkg_threshold,
            num_parties,
            num_keys,
            id,
            key_ids,
            signer_private_key.into(),
            public_keys,
        )
        .map_err(Error::Wsts)?;

        Ok(Self(state_machine))
    }

    /// Create a state machine from loaded DKG shares for the given aggregate key
    pub async fn load<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        threshold: u32,
        signer_private_key: PrivateKey,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(aggregate_key)
            .await?
            .ok_or_else(|| error::Error::MissingDkgShares(aggregate_key))?;

        let decrypted = wsts::util::decrypt(
            &signer_private_key.to_bytes(),
            &encrypted_shares.encrypted_private_shares,
        )
        .map_err(|_| error::Error::Encryption)?;

        let saved_state = wsts::traits::SignerState::decode(decrypted.as_slice())?;

        // This may panic if the saved state doesn't contain exactly one party,
        // however, that should never be the case since wsts maintains this invariant
        // when we save the state.
        let signer = wsts::v2::Party::load(&saved_state);
        let signers = encrypted_shares.signer_set_public_keys;

        let mut state_machine = Self::new(signers, threshold, signer_private_key)?;

        state_machine.0.signer = signer;

        Ok(state_machine)
    }

    /// Get the encrypted DKG shares
    pub fn get_encrypted_dkg_shares<Rng: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut Rng,
    ) -> Result<model::EncryptedDkgShares, error::Error> {
        let saved_state = self.signer.save();
        let aggregate_key = PublicKey::try_from(&saved_state.group_key)?;

        // When creating a new Self, the `public_keys` field gets populated
        // using the `signers` input iterator. It represents the public
        // keys for all signers in the signing set for DKG, including the
        // coordinator.
        let mut signer_set_public_keys = self
            .public_keys
            .signers
            .values()
            .map(PublicKey::from)
            .collect::<Vec<PublicKey>>();

        // We require the public keys to be stored sorted in db
        signer_set_public_keys.sort();

        let encoded = saved_state.encode_to_vec();
        let public_shares = self.dkg_public_shares.clone().encode_to_vec();

        // After DKG, each of the signers will have "new public keys".
        let encrypted_private_shares =
            wsts::util::encrypt(&self.0.network_private_key.to_bytes(), &encoded, rng)
                .map_err(|_| error::Error::Encryption)?;

        let signature_share_threshold: u16 = self
            .threshold
            .try_into()
            .map_err(|_| Error::TypeConversion)?;

        Ok(model::EncryptedDkgShares {
            aggregate_key,
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey()?,
            script_pubkey: aggregate_key.signers_script_pubkey().into(),
            encrypted_private_shares,
            public_shares,
            signer_set_public_keys,
            signature_share_threshold,
        })
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

type WstsCoordinator = wsts::state_machine::coordinator::fire::Coordinator<wsts::v2::Aggregator>;

impl CoordinatorStateMachine {
    /// Create a new state machine
    pub fn new<I>(signers: I, threshold: u16, message_private_key: PrivateKey) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let signer_public_keys: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(idx, key)| (idx as u32, key.into()))
            .collect();

        // The number of possible signers is capped at a number well below
        // u32::MAX, so this conversion should always work.
        let num_signers: u32 = signer_public_keys
            .len()
            .try_into()
            .expect("the number of signers is greater than u32::MAX?");
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id + 1).collect()))
            .collect();
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys: num_signers,
            threshold: threshold as u32,
            dkg_threshold: num_signers,
            message_private_key: message_private_key.into(),
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            signer_key_ids,
            signer_public_keys,
        };

        let wsts_coordinator = WstsCoordinator::new(config);
        Self(wsts_coordinator)
    }

    /// Create a new coordinator state machine from the given aggregate
    /// key.
    ///
    /// # Notes
    ///
    /// The `WstsCoordinator` is a state machine that is responsible for
    /// DKG and for facilitating signing rounds. When created the
    /// `WstsCoordinator` state machine starts off in the `IDLE` state,
    /// where you can either start a signing round or start DKG. This
    /// function is for loading the state with the assumption that DKG has
    /// already been successfully completed.
    pub async fn load<I, S, X>(
        storage: &mut S,
        aggregate_key: X,
        signers: I,
        threshold: u16,
        message_private_key: PrivateKey,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PublicKey>,
        S: storage::DbRead + storage::DbWrite,
        X: Into<PublicKeyXOnly>,
    {
        let x_only_aggregate_key: PublicKeyXOnly = aggregate_key.into();
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(x_only_aggregate_key)
            .await?
            .ok_or(Error::MissingDkgShares(x_only_aggregate_key))?;

        let public_dkg_shares: BTreeMap<u32, wsts::net::DkgPublicShares> =
            BTreeMap::decode(encrypted_shares.public_shares.as_slice())?;
        let party_polynomials = public_dkg_shares
            .iter()
            .flat_map(|(_, share)| share.comms.clone())
            .collect::<Vec<(u32, PolyCommitment)>>();

        let mut coordinator = Self::new(signers, threshold, message_private_key);

        let aggregate_key = encrypted_shares.aggregate_key.into();
        coordinator
            .set_key_and_party_polynomials(aggregate_key, party_polynomials)
            .map_err(Error::wsts_coordinator)?;
        coordinator.current_dkg_id = 1;

        coordinator
            .move_to(WstsState::Idle)
            .map_err(Error::wsts_coordinator)?;

        Ok(coordinator)
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
