use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use crate::{
    common::{PolyCommitment, PublicNonce, SignatureShare, TupleProof},
    curve::point::Point,
};

#[derive(Clone, Debug, PartialEq)]
/// A bad private share
pub struct BadPrivateShare {
    /// the DH shared key between these participants
    pub shared_key: Point,
    /// Proof that the shared key is a valid DH tuple as per Chaum-Pedersen.
    pub tuple_proof: TupleProof,
}

#[derive(Clone, Debug, PartialEq)]
/// Final DKG status after receiving public and private shares
pub enum DkgFailure {
    /// DKG threshold not met
    Threshold,
    /// Signer was in the wrong internal state to complete DKG
    BadState,
    /// DKG public shares were missing from these signer_ids
    MissingPublicShares(HashSet<u32>),
    /// DKG public shares were bad from these signer_ids
    BadPublicShares(HashSet<u32>),
    /// DKG private shares were missing from these signer_ids
    MissingPrivateShares(HashSet<u32>),
    /// DKG private shares were bad from these signer_ids
    BadPrivateShares(HashMap<u32, BadPrivateShare>),
}

#[derive(Clone, Debug, PartialEq)]
/// Final DKG status after receiving public and private shares
pub enum DkgStatus {
    /// DKG completed successfully
    Success,
    /// DKG failed
    Failure(DkgFailure),
}

#[derive(Clone, Debug, PartialEq)]
/// Encapsulation of all possible network message types
pub enum Message {
    /// Tell signers to begin DKG by sending DKG public shares
    DkgBegin(DkgBegin),
    /// Send DKG public shares
    DkgPublicShares(DkgPublicShares),
    /// Tell signers to send DKG private shares
    DkgPrivateBegin(DkgPrivateBegin),
    /// Send DKG private shares
    DkgPrivateShares(DkgPrivateShares),
    /// Tell signers to compute shares and send DKG end
    DkgEndBegin(DkgEndBegin),
    /// Tell coordinator that DKG is complete
    DkgEnd(DkgEnd),
    /// Tell signers to send signing nonces
    NonceRequest(NonceRequest),
    /// Tell coordinator signing nonces
    NonceResponse(NonceResponse),
    /// Tell signers to construct signature shares
    SignatureShareRequest(SignatureShareRequest),
    /// Tell coordinator signature shares
    SignatureShareResponse(SignatureShareResponse),
}

#[derive(Clone, Debug, PartialEq)]
/// DKG begin message from coordinator to signers
pub struct DkgBegin {
    /// DKG round ID
    pub dkg_id: u64,
}

#[derive(Clone, Debug, PartialEq)]
/// DKG public shares message from signer to all signers and coordinator
pub struct DkgPublicShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (party_id, commitment)
    pub comms: Vec<(u32, PolyCommitment)>,
}

#[derive(Clone, Debug, PartialEq)]
/// DKG private begin message from signer to all signers and coordinator
pub struct DkgPrivateBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}

impl DkgPrivateShares {
    /// Verify that the shares are good
    pub fn verify() -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq)]
/// DKG end begin message from signer to all signers and coordinator
pub struct DkgEndBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
/// DKG end message from signers to coordinator
pub struct DkgEnd {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// DKG status for this Signer after receiving public/private shares
    pub status: DkgStatus,
}

#[derive(Clone, PartialEq)]
/// Nonce request message from coordinator to signers
pub struct NonceRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// The message to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}

impl Debug for NonceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceRequest")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("message", &hex::encode(&self.message))
            .field("signature_type", &self.signature_type)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
/// Nonce response message from signers to coordinator
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}

impl Debug for NonceResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceResponse")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("signer_id", &self.signer_id)
            .field("key_ids", &self.key_ids)
            .field(
                "nonces",
                &self
                    .nonces
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>(),
            )
            .field("message", &hex::encode(&self.message))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Signature type
pub enum SignatureType {
    /// FROST signature
    Frost,
    /// BIP-340 Schnorr proof
    Schnorr,
    /// BIP-341 Taproot style schnorr proof without a merkle root
    Taproot,
}

#[derive(Clone, PartialEq)]
/// Signature share request message from coordinator to signers
pub struct SignatureShareRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Nonces responses used for this signature
    pub nonce_responses: Vec<NonceResponse>,
    /// Bytes to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}

impl Debug for SignatureShareRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureShareRequest")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("nonce_responses", &self.nonce_responses)
            .field("message", &hex::encode(&self.message))
            .field("signature_type", &self.signature_type)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
/// Signature share response message from signers to coordinator
pub struct SignatureShareResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Signature shares from this Signer
    pub signature_shares: Vec<SignatureShare>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::ecdsa;
    use crate::curve::scalar::Scalar;
    use crate::state_machine::PublicKeys;
    use crate::util::create_rng;
    use rand_core::{CryptoRng, RngCore};

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    pub struct TestConfig {
        pub coordinator_private_key: Scalar,
        pub coordinator_public_key: ecdsa::PublicKey,
        pub signer_private_key: Scalar,
        pub signer_public_key: ecdsa::PublicKey,
        pub public_keys: PublicKeys,
    }

    impl TestConfig {
        pub fn new<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
            let coordinator_private_key = Scalar::random(rng);
            let coordinator_public_key = ecdsa::PublicKey::new(&coordinator_private_key).unwrap();
            let signer_private_key = Scalar::random(rng);
            let signer_public_key = ecdsa::PublicKey::new(&signer_private_key).unwrap();

            let mut signer_ids_map = HashMap::new();
            let mut signer_key_ids = HashMap::new();
            let mut key_ids_map = HashMap::new();
            let mut key_ids_set = HashSet::new();
            signer_ids_map.insert(0, signer_public_key);
            key_ids_map.insert(1, signer_public_key);
            key_ids_set.insert(1);
            signer_key_ids.insert(0, key_ids_set);

            let public_keys = PublicKeys {
                signers: signer_ids_map,
                key_ids: key_ids_map,
                signer_key_ids,
            };

            Self {
                coordinator_private_key,
                coordinator_public_key,
                signer_private_key,
                signer_public_key,
                public_keys,
            }
        }
    }

    impl Default for TestConfig {
        fn default() -> Self {
            let mut rng = create_rng();
            Self::new(&mut rng)
        }
    }
}
