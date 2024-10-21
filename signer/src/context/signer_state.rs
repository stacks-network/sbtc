//! Module for signer state

use std::sync::RwLock;

use hashbrown::HashSet;
use libp2p::PeerId;

use crate::keys::PublicKey;

/// A struct for holding internal signer state. This struct is served by
/// the [`SignerContext`] and can be used to cache global state instead of
/// fetching it via I/O for frequently accessed information.
#[derive(Debug, Default)]
pub struct SignerState {
    current_signer_set: SignerSet,
}

impl SignerState {
    /// Get the current signer set.
    pub fn current_signer_set(&self) -> &SignerSet {
        &self.current_signer_set
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
