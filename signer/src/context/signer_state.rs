//! Module for signer state

use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    RwLock,
};

use bitcoin::Amount;
use hashbrown::HashSet;
use libp2p::PeerId;

use crate::keys::PublicKey;

/// A struct for holding internal signer state. This struct is served by
/// the [`SignerContext`] and can be used to cache global state instead of
/// fetching it via I/O for frequently accessed information.
#[derive(Debug)]
pub struct SignerState {
    current_signer_set: SignerSet,
    current_limits: RwLock<SbtcLimits>,
    current_aggregate_key: RwLock<Option<PublicKey>>,
    sbtc_contracts_deployed: AtomicBool,
    sbtc_bitcoin_start_height: AtomicU64,
    is_sbtc_bitcoin_start_height_set: AtomicBool,
}

impl SignerState {
    /// Get the current signer set.
    pub fn current_signer_set(&self) -> &SignerSet {
        &self.current_signer_set
    }

    /// Return the public keys of the current signer set.
    pub fn current_signer_public_keys(&self) -> BTreeSet<PublicKey> {
        self.current_signer_set
            .get_signers()
            .into_iter()
            .map(|signer| signer.public_key)
            .collect()
    }

    /// Replace the current signer set with the given set of public keys.
    pub fn update_current_signer_set(&self, public_keys: BTreeSet<PublicKey>) {
        self.current_signer_set.replace_signers(public_keys);
    }

    /// Return the current aggregate key from the cache.
    #[allow(clippy::unwrap_in_result)]
    pub fn current_aggregate_key(&self) -> Option<PublicKey> {
        self.current_aggregate_key
            .read()
            .expect("BUG: Failed to acquire read lock")
            .as_ref()
            .copied()
    }

    /// Set the current aggregate key to the given public key.
    pub fn set_current_aggregate_key(&self, aggregate_key: PublicKey) {
        self.current_aggregate_key
            .write()
            .expect("BUG: Failed to acquire write lock")
            .replace(aggregate_key);
    }

    /// Get the current sBTC limits.
    pub fn get_current_limits(&self) -> SbtcLimits {
        // We should never fail to acquire a lock from the RwLock so that it panics.
        self.current_limits
            .read()
            .expect("BUG: Failed to acquire read lock")
            .clone()
    }

    /// Update the current sBTC limits.
    pub fn update_current_limits(&self, new_limits: SbtcLimits) {
        // We should never fail to acquire a lock from the RwLock so that it panics.
        let mut limits = self
            .current_limits
            .write()
            .expect("BUG: Failed to acquire write lock");
        *limits = new_limits;
    }

    /// Returns true if sbtc smart contracts are deployed
    pub fn sbtc_contracts_deployed(&self) -> bool {
        self.sbtc_contracts_deployed.load(Ordering::SeqCst)
    }

    /// Set the sbtc smart contracts deployed flag
    pub fn set_sbtc_contracts_deployed(&self) {
        self.sbtc_contracts_deployed.store(true, Ordering::SeqCst);
    }

    /// Get the sbtc start height
    pub fn get_sbtc_bitcoin_start_height(&self) -> u64 {
        self.sbtc_bitcoin_start_height.load(Ordering::SeqCst)
    }

    /// Set the sbtc start height
    pub fn set_sbtc_bitcoin_start_height(&self, height: u64) {
        self.is_sbtc_bitcoin_start_height_set
            .store(true, Ordering::SeqCst);
        self.sbtc_bitcoin_start_height
            .store(height, Ordering::SeqCst);
    }

    /// Return whether the sbtc start height has been set.
    pub fn is_sbtc_bitcoin_start_height_set(&self) -> bool {
        self.is_sbtc_bitcoin_start_height_set.load(Ordering::SeqCst)
    }
}

impl Default for SignerState {
    fn default() -> Self {
        Self {
            current_signer_set: Default::default(),
            current_limits: RwLock::new(SbtcLimits::zero()),
            current_aggregate_key: RwLock::new(None),
            sbtc_contracts_deployed: Default::default(),
            sbtc_bitcoin_start_height: Default::default(),
            is_sbtc_bitcoin_start_height_set: Default::default(),
        }
    }
}

/// Represents the current sBTC limits.
#[derive(Debug, Clone, PartialEq)]
pub struct SbtcLimits {
    /// Represents the total cap for all pegged-in BTC/sBTC.
    total_cap: Option<Amount>,
    /// Represents the minimum amount of BTC allowed to be pegged-in per transaction.
    per_deposit_minimum: Option<Amount>,
    /// Represents the maximum amount of BTC allowed to be pegged-in per transaction.
    per_deposit_cap: Option<Amount>,
    /// Represents the maximum amount of sBTC allowed to be pegged-out per transaction.
    per_withdrawal_cap: Option<Amount>,
    /// Represents the maximum amount of sBTC that can currently be minted.
    max_mintable_cap: Option<Amount>,
}

impl std::fmt::Display for SbtcLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[total cap: {:?}, per-deposit min: {:?}, per-deposit cap: {:?}, per-withdrawal cap: {:?}, max-mintable cap: {:?}]",
            self.total_cap, self.per_deposit_minimum, self.per_deposit_cap, self.per_withdrawal_cap, self.max_mintable_cap
        )
    }
}

impl SbtcLimits {
    /// Create a new `SbtcLimits` object.
    pub fn new(
        total_cap: Option<Amount>,
        per_deposit_minimum: Option<Amount>,
        per_deposit_cap: Option<Amount>,
        per_withdrawal_cap: Option<Amount>,
        max_mintable_cap: Option<Amount>,
    ) -> Self {
        Self {
            total_cap,
            per_deposit_minimum,
            per_deposit_cap,
            per_withdrawal_cap,
            max_mintable_cap,
        }
    }

    /// Create a new `SbtcLimits` object with limits set to zero (fully constraining)
    pub fn zero() -> Self {
        Self::new(
            Some(Amount::ZERO),
            Some(Amount::MAX_MONEY),
            Some(Amount::ZERO),
            Some(Amount::ZERO),
            Some(Amount::ZERO),
        )
    }

    /// Get the total cap for all pegged-in BTC/sBTC.
    pub fn total_cap(&self) -> Amount {
        self.total_cap.unwrap_or(Amount::MAX_MONEY)
    }

    /// Check if total cap is set
    pub fn total_cap_exists(&self) -> bool {
        self.total_cap.is_some()
    }

    /// Get the minimum amount of BTC allowed to be pegged-in per transaction.
    pub fn per_deposit_minimum(&self) -> Amount {
        self.per_deposit_minimum.unwrap_or(Amount::ZERO)
    }

    /// Get the maximum amount of BTC allowed to be pegged-in per transaction.
    pub fn per_deposit_cap(&self) -> Amount {
        self.per_deposit_cap.unwrap_or(Amount::MAX_MONEY)
    }

    /// Get the maximum amount of sBTC allowed to be pegged-out per transaction.
    pub fn per_withdrawal_cap(&self) -> Amount {
        self.per_withdrawal_cap.unwrap_or(Amount::MAX_MONEY)
    }

    /// Get the maximum amount of sBTC that can currently be minted.
    pub fn max_mintable_cap(&self) -> Amount {
        self.max_mintable_cap.unwrap_or(Amount::MAX_MONEY)
    }
}

#[cfg(any(test, feature = "testing"))]
impl SbtcLimits {
    /// Create a new `SbtcLimits` object without any limits
    pub fn unlimited() -> Self {
        Self {
            total_cap: Some(Amount::MAX_MONEY),
            per_deposit_minimum: Some(Amount::ZERO),
            per_deposit_cap: Some(Amount::MAX_MONEY),
            per_withdrawal_cap: Some(Amount::MAX_MONEY),
            max_mintable_cap: Some(Amount::MAX_MONEY),
        }
    }

    /// Create a new Self with only the given deposit minimum and maximums
    /// set.
    pub fn new_per_deposit(min: u64, max: u64) -> Self {
        Self {
            total_cap: None,
            per_deposit_minimum: Some(Amount::from_sat(min)),
            per_deposit_cap: Some(Amount::from_sat(max)),
            per_withdrawal_cap: None,
            max_mintable_cap: None,
        }
    }

    /// Create a new Self with only the given withdrawal maximum set.
    pub fn new_per_withdrawal(max: u64) -> Self {
        Self {
            total_cap: None,
            per_deposit_minimum: None,
            per_deposit_cap: None,
            per_withdrawal_cap: Some(Amount::from_sat(max)),
            max_mintable_cap: None,
        }
    }
}

/// Represents a signer in the current signer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    public_key: PublicKey,
    peer_id: PeerId,
}

// We want to hash on the signer's public key.
impl std::hash::Hash for Signer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
    }
}

// We implement Borrow so that we don't need to reconstruct a full `Signer`
// object (which involves hashing) when we lookup a signer in the set.
impl std::borrow::Borrow<PublicKey> for Signer {
    fn borrow(&self) -> &PublicKey {
        &self.public_key
    }
}

impl Signer {
    /// Create a new signer from a public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            peer_id: public_key.into(),
        }
    }

    /// Gets the public key of the signer.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Gets the LibP2P peer ID of the signer.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// A struct for holding the set of signers that are currently part of the
/// active signing set.
#[derive(Debug, Default)]
pub struct SignerSet {
    signers: RwLock<HashSet<Signer>>,
    peer_ids: RwLock<HashSet<PeerId>>,
}

/// NOTE: We should never fail to acquire a lock from the RwLock so that it panics.
/// If we do, then things have gone very wrong.
impl SignerSet {
    /// Add a signer (public key) to the known active signer set.
    pub fn add_signer(&self, signer: PublicKey) {
        // Create a new signer object.
        let signer = Signer::new(signer);

        // Insert the peer ID into the set.
        #[allow(clippy::expect_used)]
        self.peer_ids
            .write()
            .expect("BUG: Failed to acquire write lock")
            .insert(signer.peer_id);

        // Insert the signer into the set.
        #[allow(clippy::expect_used)]
        self.signers
            .write()
            .expect("BUG: Failed to acquire write lock")
            .insert(signer);
    }

    /// Replace the current signer set with the given set of public keys.
    pub fn replace_signers(&self, public_keys: BTreeSet<PublicKey>) {
        let inner_signer_set = self.get_signers();

        // Get a guard for the peer IDs.
        #[allow(clippy::expect_used)]
        let mut inner_peer_ids = self
            .peer_ids
            .write()
            .expect("BUG: Failed to acquire write lock");

        // Get a guard for the Signer objects the signer into the set.
        #[allow(clippy::expect_used)]
        let mut inner_public_keys = self
            .signers
            .write()
            .expect("BUG: Failed to acquire write lock");

        // Remove the old signer set
        for signer in inner_signer_set {
            inner_peer_ids.remove(signer.peer_id());
            inner_public_keys.remove(signer.public_key());
        }

        // Add the new signer set
        for public_key in public_keys {
            let signer = Signer::new(public_key);
            inner_peer_ids.insert(signer.peer_id);
            inner_public_keys.insert(signer);
        }
    }

    /// Remove a signer (public key) from the known active signer set.
    pub fn remove_signer(&self, signer: &PublicKey) {
        if self.is_signer(signer) {
            let peer_id: PeerId = (*signer).into();
            #[allow(clippy::expect_used)]
            self.peer_ids
                .write()
                .expect("BUG: Failed to acquire write lock")
                .remove(&peer_id);

            #[allow(clippy::expect_used)]
            self.signers
                .write()
                .expect("BUG: Failed to acquire write lock")
                .remove(signer);
        }
    }

    /// Returns the current set of public keys for the known active signers.
    pub fn get_signers(&self) -> Vec<Signer> {
        #[allow(clippy::expect_used)]
        self.signers
            .read()
            .expect("BUG: Failed to acquire read lock")
            .iter()
            .cloned()
            .collect()
    }

    /// Returns whether or not the given public key is a known signer in the
    /// active set.
    pub fn is_signer(&self, signer: &PublicKey) -> bool {
        #[allow(clippy::expect_used)]
        self.signers
            .read()
            .expect("BUG: Failed to acquire read lock")
            .contains(signer)
    }

    /// Returns whether or not the given peer ID is a known signer in the
    /// active set.
    pub fn is_allowed_peer(&self, peer_id: &PeerId) -> bool {
        #[allow(clippy::expect_used)]
        self.peer_ids
            .read()
            .expect("BUG: Failed to acquire read lock")
            .contains(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use crate::keys::PrivateKey;

    #[test]
    fn test_signer_set() {
        use super::*;

        let signer_set = SignerSet::default();
        let public_key = PublicKey::from_private_key(&PrivateKey::new(&mut OsRng));

        assert!(!signer_set.is_signer(&public_key));
        signer_set.add_signer(public_key.clone());
        assert!(signer_set.is_signer(&public_key));
        signer_set.remove_signer(&public_key);
        assert!(!signer_set.is_signer(&public_key));
    }

    #[test]
    fn test_is_allowed_peer() {
        use super::*;

        let signer_set = SignerSet::default();
        let public_key = PublicKey::from_private_key(&PrivateKey::new(&mut OsRng));

        assert!(!signer_set.is_allowed_peer(&public_key.into()));
        signer_set.add_signer(public_key.clone());
        assert!(signer_set.is_allowed_peer(&public_key.into()));
        signer_set.remove_signer(&public_key);
        assert!(!signer_set.is_allowed_peer(&public_key.into()));
    }
}
