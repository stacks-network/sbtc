//! Utilities for constructing and loading WSTS state machines

use std::collections::BTreeMap;

use crate::codec::Decode as _;
use crate::codec::Encode as _;
use crate::error;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::storage;
use crate::storage::model;

use wsts::state_machine::coordinator::Coordinator as _;
use wsts::state_machine::coordinator::State as WstsState;
use wsts::state_machine::StateMachine as _;
use wsts::traits::Signer as _;

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

        let p256k1_public_key = p256k1::keys::PublicKey::from(&signer_pub_key);
        let id: u32 = *signers
            .iter()
            .find(|(_, key)| *key == &p256k1_public_key)
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
            signer_private_key.into(),
            public_keys,
        );

        Ok(Self(state_machine))
    }

    /// Create a state machine from loaded DKG shares for the given aggregate key
    pub async fn load<S>(
        storage: &S,
        aggregate_key: PublicKey,
        threshold: u32,
        signer_private_key: PrivateKey,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead + storage::DbWrite,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(&aggregate_key)
            .await?
            .ok_or(error::Error::MissingDkgShares(aggregate_key))?;

        let decrypted = wsts::util::decrypt(
            &signer_private_key.to_bytes(),
            &encrypted_shares.encrypted_private_shares,
        )
        .map_err(|_| error::Error::Encryption)?;

        let saved_state =
            wsts::traits::SignerState::decode(decrypted.as_slice()).map_err(error::Error::Codec)?;

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

        // We do not depend on the fact that these keys are sorted in the
        // database, but it doesn't hurt much either.
        signer_set_public_keys.sort();

        let encoded = saved_state.encode_to_vec().map_err(error::Error::Codec)?;
        let public_shares = self
            .dkg_public_shares
            .encode_to_vec()
            .map_err(error::Error::Codec)?;

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

type WstsCoordinator = wsts::state_machine::coordinator::frost::Coordinator<wsts::v2::Aggregator>;

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
            .expect("The number of signers is greater than u32::MAX?");
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id).collect()))
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
    pub async fn load<I, S>(
        storage: &mut S,
        aggregate_key: PublicKey,
        signers: I,
        threshold: u16,
        message_private_key: PrivateKey,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PublicKey>,
        S: storage::DbRead + storage::DbWrite,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(&aggregate_key)
            .await?
            .ok_or(Error::MissingDkgShares(aggregate_key))?;

        let public_dkg_shares: BTreeMap<u32, wsts::net::DkgPublicShares> =
            BTreeMap::decode(encrypted_shares.public_shares.as_slice()).map_err(Error::Codec)?;

        let mut coordinator = Self::new(signers, threshold, message_private_key);

        // The `coordinator` is a state machine that starts off in the
        // `IDLE` state, but we need to move it into a state where it can
        // accept the above public DKG shares. To do that we need to move
        // it to the `DKG_PUBLIC_GATHER` state and make sure that it is
        // properly initialized. The way to do that is to process a
        // `DKG_BEGIN` message, it will automatically move the state of the
        // machine to the `DKG_PUBLIC_GATHER` state.
        let packet = wsts::net::Packet {
            msg: wsts::net::Message::DkgBegin(wsts::net::DkgBegin { dkg_id: 1 }),
            sig: Vec::new(),
        };
        // If WSTS thinks that the we've already completed DKG for the
        // given ID, then it will return with `(None, None)`. This only
        // happens when the coordinator's `dkg_id` is greater than or equal
        // to the value given in the message. But the coordinator's dkg_id
        // starts at 0 and we start our's at 1.
        let (Some(_), _) = coordinator
            .process_message(&packet)
            .map_err(Error::wsts_coordinator)?
        else {
            let msg = "Bad DKG id given".to_string();
            let err = wsts::state_machine::coordinator::Error::BadStateChange(msg);
            return Err(Error::wsts_coordinator(err));
        };

        // TODO(338): Replace this for-loop with a simpler method to set
        // the public DKG shares.
        //
        // In this part we are trying to set the party_polynomials of the
        // WstsCoordinator given all of the known public keys that we
        // stored in the database.
        for mut msg in public_dkg_shares.values().cloned() {
            msg.dkg_id = 1;
            let packet = wsts::net::Packet {
                msg: wsts::net::Message::DkgPublicShares(msg),
                sig: Vec::new(),
            };

            // We're in the state that can accept public keys, let's
            // process them.
            coordinator
                .process_message(&packet)
                .map_err(Error::wsts_coordinator)?;
        }

        // Once we've processed all DKG public shares for all participants,
        // WSTS moves the state to `DKG_PRIVATE_GATHER` automatically.
        // If this fails then we know that there is a mismatch between the
        // stored public shares and the size of the input `signers`
        // variable.
        debug_assert_eq!(coordinator.0.state, WstsState::DkgPrivateGather);

        // Okay we've already gotten the private keys, and we've set the
        // `party_polynomials` variable in the `WstsCoordinator`. Now we
        // can just set the aggregate key and move the state to the `IDLE`,
        // which is the state after a successful DKG round.
        coordinator.set_aggregate_public_key(Some(aggregate_key.into()));

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
