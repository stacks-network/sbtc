//! Test utilities for running a wsts signer and coordinator.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Duration;

use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::types::PrincipalData;
use fake::Fake;
use rand::rngs::OsRng;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use stacks_common::types::chainstate::StacksAddress;
use wsts::net::SignatureType;
use wsts::state_machine::StateMachine as _;
use wsts::state_machine::coordinator;
use wsts::state_machine::coordinator::Coordinator as _;
use wsts::state_machine::coordinator::fire;

use crate::ecdsa::SignEcdsa as _;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::WstsMessageId;
use crate::network;
use crate::network::MessageTransfer as _;
use crate::storage;
use crate::storage::model;
use crate::storage::model::EncryptedDkgShares;
use crate::storage::model::StacksPrincipal;
use crate::wsts_state_machine;

/// Signer info
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Private key of the signer
    pub signer_private_key: PrivateKey,
    /// Public keys of all signers in the signer set
    pub signer_public_keys: BTreeSet<PublicKey>,
}

/// Generate a set of public keys for a group of signers
pub fn generate_signer_set_public_keys<R>(rng: &mut R, num_signers: usize) -> Vec<PublicKey>
where
    R: rand::RngCore + rand::CryptoRng,
{
    // Generate the signer set. Each SignerInfo object returned from the
    // `generate_signer_info` function the public keys of
    // other signers, so we take one of them and get the signing set from
    // that one.
    let mut signer_set: Vec<PublicKey> = generate_signer_info(rng, num_signers)
        .into_iter()
        .take(1)
        .flat_map(|signer_info| signer_info.signer_public_keys.into_iter())
        .collect();

    signer_set.sort();
    signer_set
}

/// Generate a new signer set
pub fn generate_signer_info<Rng: rand::RngCore + rand::CryptoRng>(
    rng: &mut Rng,
    num_signers: usize,
) -> Vec<SignerInfo> {
    let signer_keys: BTreeMap<_, _> = (0..num_signers)
        .map(|_| {
            let private = PrivateKey::new(rng);
            let public = PublicKey::from_private_key(&private);

            (public, private)
        })
        .collect();

    let signer_public_keys: BTreeSet<_> = signer_keys.keys().cloned().collect();

    signer_keys
        .into_values()
        .map(|signer_private_key| SignerInfo {
            signer_private_key,
            signer_public_keys: signer_public_keys.clone(),
        })
        .collect()
}

/// Test coordinator that can operate over an `in_memory` network
pub struct Coordinator {
    network: network::in_memory::MpmcBroadcaster,
    wsts_coordinator: fire::Coordinator<wsts::v2::Aggregator>,
    private_key: PrivateKey,
}

impl Coordinator {
    /// Construct a new coordinator
    pub fn new(
        network: network::in_memory::MpmcBroadcaster,
        signer_info: SignerInfo,
        threshold: u32,
    ) -> Self {
        let num_signers = signer_info.signer_public_keys.len().try_into().unwrap();
        let message_private_key = signer_info.signer_private_key;
        let signer_public_keys: hashbrown::HashMap<u32, _> = signer_info
            .signer_public_keys
            .into_iter()
            .enumerate()
            .map(|(idx, key)| (idx.try_into().unwrap(), p256k1::point::Point::from(&key)))
            .collect();
        let num_keys = num_signers;
        let dkg_threshold = num_keys;
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id + 1).collect()))
            .collect();
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold,
            message_private_key: signer_info.signer_private_key.into(),
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            signer_key_ids,
            signer_public_keys,
        };

        let wsts_coordinator = fire::Coordinator::new(config);

        Self {
            network,
            wsts_coordinator,
            private_key: message_private_key,
        }
    }

    /// Run DKG
    pub async fn run_dkg(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        id: WstsMessageId,
    ) -> PublicKey {
        self.wsts_coordinator
            .move_to(coordinator::State::DkgPublicDistribute)
            .expect("failed to move state machine");

        let outbound = self
            .wsts_coordinator
            .start_public_shares()
            .expect("failed to start public shares");

        self.send_packet(bitcoin_chain_tip, id, outbound).await;

        match self.loop_until_result(bitcoin_chain_tip, id).await {
            wsts::state_machine::OperationResult::Dkg(aggregate_key) => {
                PublicKey::try_from(&aggregate_key).expect("Got the point at infinity")
            }
            _ => panic!("unexpected operation result"),
        }
    }

    /// Run a signing round
    pub async fn run_signing_round(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        id: WstsMessageId,
        msg: &[u8],
        signature_type: SignatureType,
    ) -> wsts::taproot::SchnorrProof {
        let outbound = self
            .wsts_coordinator
            .start_signing_round(msg, signature_type)
            .expect("failed to start signing round");

        self.send_packet(bitcoin_chain_tip, id, outbound).await;

        match self.loop_until_result(bitcoin_chain_tip, id).await {
            wsts::state_machine::OperationResult::SignTaproot(signature)
            | wsts::state_machine::OperationResult::SignSchnorr(signature) => signature,
            _ => panic!("unexpected operation result"),
        }
    }

    async fn loop_until_result(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        id: WstsMessageId,
    ) -> wsts::state_machine::OperationResult {
        let future = async move {
            loop {
                let msg = self.network.receive().await.expect("network error");

                let message::Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                    continue;
                };

                let packet = wsts::net::Packet {
                    msg: wsts_msg.inner,
                    sig: Vec::new(),
                };

                let (outbound_packet, operation_result) = self
                    .wsts_coordinator
                    .process_message(&packet)
                    .expect("message processing failed");

                if let Some(packet) = outbound_packet {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    self.send_packet(bitcoin_chain_tip, id, packet).await;
                }

                if let Some(result) = operation_result {
                    return result;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
    }
}

/// Test signer that can operate over an `in_memory` network
pub struct Signer {
    network: network::in_memory::MpmcBroadcaster,
    wsts_signer: wsts_state_machine::SignerStateMachine,
    private_key: PrivateKey,
}

impl Signer {
    /// Construct a new signer
    pub fn new(
        network: network::in_memory::MpmcBroadcaster,
        signer_info: SignerInfo,
        threshold: u32,
    ) -> Self {
        let wsts_signer = wsts_state_machine::SignerStateMachine::new(
            signer_info.signer_public_keys,
            threshold,
            signer_info.signer_private_key,
        )
        .expect("failed to construct state machine");

        Self {
            network,
            wsts_signer,
            private_key: signer_info.signer_private_key,
        }
    }

    /// Participate in a DKG round and return the result
    pub async fn run_until_dkg_end(mut self) -> Self {
        let future = async move {
            let mut rng = OsRng;
            loop {
                let msg = self.network.receive().await.expect("network error");
                let bitcoin_chain_tip = msg.bitcoin_chain_tip;

                let message::Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                    continue;
                };

                let packet = wsts::net::Packet {
                    msg: wsts_msg.inner,
                    sig: Vec::new(),
                };

                let outbound_packets = self
                    .wsts_signer
                    .process_inbound_messages(&[packet], &mut rng)
                    .expect("message processing failed");

                for packet in outbound_packets {
                    self.wsts_signer
                        .process_inbound_messages(&[packet.clone()], &mut rng)
                        .expect("message processing failed");

                    self.send_packet(bitcoin_chain_tip, wsts_msg.id, packet.clone())
                        .await;

                    if let wsts::net::Message::DkgEnd(_) = packet.msg {
                        return self;
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
    }

    /// Participate in a signing round and return the result
    pub async fn run_until_signature_share_response(mut self) -> Self {
        let future = async move {
            let mut rng = OsRng;
            loop {
                let msg = self.network.receive().await.expect("network error");
                let bitcoin_chain_tip = msg.bitcoin_chain_tip;

                let message::Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                    continue;
                };

                let packet = wsts::net::Packet {
                    msg: wsts_msg.inner,
                    sig: Vec::new(),
                };

                let outbound_packets = self
                    .wsts_signer
                    .process_inbound_messages(&[packet], &mut rng)
                    .expect("message processing failed");

                for packet in outbound_packets {
                    self.wsts_signer
                        .process_inbound_messages(&[packet.clone()], &mut rng)
                        .expect("message processing failed");

                    self.send_packet(bitcoin_chain_tip, wsts_msg.id, packet.clone())
                        .await;

                    if let wsts::net::Message::SignatureShareResponse(_) = packet.msg {
                        return self;
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
    }

    /// The public key for this signer.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_key)
    }
}

trait WstsEntity {
    fn network(&mut self) -> &mut network::in_memory::MpmcBroadcaster;
    fn private_key(&self) -> &PrivateKey;

    async fn send_packet(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        id: WstsMessageId,
        packet: wsts::net::Packet,
    ) {
        let payload: message::Payload = message::WstsMessage { id, inner: packet.msg }.into();

        let msg = payload
            .to_message(bitcoin_chain_tip)
            .sign_ecdsa(self.private_key());

        self.network()
            .broadcast(msg)
            .await
            .expect("failed to broadcast dkg begin msg");
    }
}

impl WstsEntity for Coordinator {
    fn network(&mut self) -> &mut network::in_memory::MpmcBroadcaster {
        &mut self.network
    }

    fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

impl WstsEntity for Signer {
    fn network(&mut self) -> &mut network::in_memory::MpmcBroadcaster {
        &mut self.network
    }

    fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

/// A set of signers and a coordinator
pub struct SignerSet {
    signers: Vec<Signer>,
    coordinator: Coordinator,
}

impl SignerSet {
    /// Construct a new signer set
    pub fn new<F>(signer_info: &[SignerInfo], threshold: u32, connect: F) -> Self
    where
        F: Fn() -> network::in_memory::MpmcBroadcaster,
    {
        let coordinator_info = signer_info.first().unwrap().clone();
        let coordinator = Coordinator::new(connect(), coordinator_info, threshold);
        let signers = signer_info
            .iter()
            .cloned()
            .map(|signer_info| Signer::new(connect(), signer_info, threshold))
            .collect();

        Self { signers, coordinator }
    }

    /// Run DKG and return the private and public shares
    /// for all signers
    pub async fn run_dkg<Rng: rand::RngCore + rand::CryptoRng>(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        id: WstsMessageId,
        rng: &mut Rng,
        dkg_shares_status: model::DkgSharesStatus,
    ) -> (PublicKey, Vec<model::EncryptedDkgShares>) {
        let mut signer_handles = Vec::new();
        for signer in self.signers.drain(..) {
            let handle = tokio::spawn(async { signer.run_until_dkg_end().await });
            signer_handles.push(handle);
        }

        let aggregate_key = self.coordinator.run_dkg(bitcoin_chain_tip, id).await;

        for handle in signer_handles {
            let signer = handle.await.expect("signer crashed");
            self.signers.push(signer)
        }

        let started_at = model::BitcoinBlockRef {
            block_hash: bitcoin_chain_tip,
            block_height: 0,
        };

        (
            aggregate_key,
            self.signers
                .iter()
                .map(|signer| {
                    let mut shares = signer
                        .wsts_signer
                        .get_encrypted_dkg_shares(rng, &started_at)
                        .expect("failed to get encrypted shares");
                    shares.dkg_shares_status = dkg_shares_status;
                    shares
                })
                .collect(),
        )
    }

    /// Participate in signing rounds coordinated by an external coordinator.
    /// Will never terminate unless the signer panics.
    pub async fn participate_in_signing_rounds_forever(&mut self) {
        loop {
            self.participate_in_signing_round().await
        }
    }

    /// Participate in a signing round coordinated by an external coordinator.
    pub async fn participate_in_signing_round(&mut self) {
        let mut signer_handles = Vec::new();
        for signer in self.signers.drain(..) {
            let handle = tokio::spawn(async { signer.run_until_signature_share_response().await });
            signer_handles.push(handle);
        }

        for handle in signer_handles {
            let signer = handle.await.expect("signer crashed");
            self.signers.push(signer)
        }
    }

    /// Dump the current signer set as a dummy rotate-keys transaction to the given storage
    pub async fn write_as_rotate_keys_tx<S, Rng>(
        &self,
        storage: &S,
        chain_tip: &model::BitcoinBlockHash,
        shares: &EncryptedDkgShares,
        rng: &mut Rng,
    ) where
        S: storage::DbWrite + storage::DbRead,
        Rng: rand::RngCore + rand::CryptoRng,
    {
        let stacks_chain_tip = storage
            .get_stacks_chain_tip(chain_tip)
            .await
            .expect("storage error")
            .expect("no stacks chain tip");

        let txid: model::StacksTxId = fake::Faker.fake_with_rng(rng);
        let stacks_transaction = model::StacksTransaction {
            txid,
            block_hash: stacks_chain_tip.block_hash,
        };

        let transaction = model::Transaction {
            txid: txid.to_bytes(),
            tx_type: model::TransactionType::RotateKeys,
            block_hash: stacks_chain_tip.block_hash.to_bytes(),
        };
        let address = StacksPrincipal::from(PrincipalData::from(
            StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                &AddressHashMode::SerializeP2SH,
                self.signers.len(),
                &self
                    .signer_keys()
                    .iter()
                    .map(Secp256k1PublicKey::from)
                    .collect::<Vec<_>>(),
            )
            .expect("failed to create StacksAddress"),
        ));
        let rotate_keys_tx = model::RotateKeysTransaction {
            aggregate_key: shares.aggregate_key,
            address,
            txid,
            signer_set: self.signer_keys(),
            signatures_required: self.signers.len() as u16,
        };

        storage
            .write_transaction(&transaction)
            .await
            .expect("failed to write transaction");

        storage
            .write_stacks_transaction(&stacks_transaction)
            .await
            .expect("failed to write stacks transaction");

        storage
            .write_rotate_keys_transaction(&rotate_keys_tx)
            .await
            .expect("failed to write key rotation");
    }

    /// The public keys in the signer set
    pub fn signer_keys(&self) -> Vec<PublicKey> {
        self.signers
            .iter()
            .map(|signer| signer.public_key())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use model::BitcoinBlockHash;

    use crate::testing::dummy;
    use crate::testing::get_rng;

    use super::*;

    #[tokio::test]
    async fn should_be_able_to_run_dkg() {
        let mut rng = get_rng();
        let network = network::InMemoryNetwork::new();
        let num_signers = 7;
        let threshold = 5;

        let bitcoin_chain_tip: BitcoinBlockHash = fake::Faker.fake_with_rng(&mut rng);
        let txid = dummy::txid(&fake::Faker, &mut rng);

        let signer_info = generate_signer_info(&mut rng, num_signers);
        let mut signer_set = SignerSet::new(&signer_info, threshold, || network.connect());

        let (_, dkg_shares) = signer_set
            .run_dkg(
                bitcoin_chain_tip,
                txid.into(),
                &mut rng,
                model::DkgSharesStatus::Unverified,
            )
            .await;

        assert_eq!(dkg_shares.len(), num_signers as usize);
    }
}
