//! Test utilities for signer message

use bitvec::array::BitArray;
use fake::Fake;
use rand::seq::SliceRandom;
use stacks_common::types::chainstate::StacksAddress;

use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::RejectWithdrawalV1;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::StacksTxId;
use crate::testing::dummy;

impl message::SignerMessage {
    /// Construct a random message
    pub fn random<R: rand::RngCore + ?Sized>(rng: &mut R) -> Self {
        fake::Faker.fake_with_rng(rng)
    }

    /// Construct a random message with the given payload type
    pub fn random_with_payload_type<
        P: Into<message::Payload> + fake::Dummy<fake::Faker>,
        R: rand::RngCore + ?Sized,
    >(
        rng: &mut R,
    ) -> Self {
        let payload = dummy_payload::<P, _>(&fake::Faker, rng);
        Self::random_with_payload(rng, payload)
    }

    /// Construct a random message with the given payload
    fn random_with_payload<R: rand::RngCore + ?Sized>(
        rng: &mut R,
        payload: message::Payload,
    ) -> Self {
        let mut block_hash_data = [0; 32];
        rng.fill_bytes(&mut block_hash_data);
        let block_hash = BitcoinBlockHash::from(block_hash_data);

        payload.to_message(block_hash)
    }
}

impl fake::Dummy<fake::Faker> for message::Payload {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let variants = [
            dummy_payload::<message::SignerDepositDecision, _>,
            dummy_payload::<message::SignerWithdrawalDecision, _>,
            dummy_payload::<message::StacksTransactionSignRequest, _>,
            dummy_payload::<message::StacksTransactionSignature, _>,
            dummy_payload::<message::WstsMessage, _>,
            dummy_payload::<message::BitcoinPreSignRequest, _>,
        ];
        variants.choose(rng).unwrap()(config, rng)
    }
}

impl fake::Dummy<fake::Faker> for message::SignerMessage {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let payload: message::Payload = config.fake_with_rng(rng);

        Self::random_with_payload(rng, payload)
    }
}

impl fake::Dummy<fake::Faker> for message::SignerDepositDecision {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        Self {
            output_index: config.fake_with_rng(rng),
            txid: dummy::txid(config, rng),
            can_accept: config.fake_with_rng(rng),
            can_sign: config.fake_with_rng(rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for message::StacksTransactionSignRequest {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let private_key = PrivateKey::new(rng);
        Self {
            contract_tx: ContractCall::RejectWithdrawalV1(RejectWithdrawalV1 {
                request_id: 1,
                signer_bitmap: BitArray::ZERO,
                deployer: StacksAddress::burn_address(false),
            })
            .into(),
            tx_fee: 123,
            nonce: 1,
            aggregate_key: PublicKey::from_private_key(&private_key),
            txid: config.fake_with_rng::<StacksTxId, _>(rng).into(),
        }
    }
}

impl fake::Dummy<fake::Faker> for message::StacksTransactionSignature {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        Self {
            txid: dummy::stacks_txid(config, rng),
            signature: dummy::recoverable_signature(config, rng),
        }
    }
}

impl fake::Dummy<fake::Faker> for message::WstsMessage {
    fn dummy_with_rng<R: rand::RngCore + ?Sized>(config: &fake::Faker, rng: &mut R) -> Self {
        let dkg_end_begin = wsts::net::DkgEndBegin {
            dkg_id: config.fake_with_rng(rng),
            signer_ids: config.fake_with_rng(rng),
            key_ids: config.fake_with_rng(rng),
        };

        Self {
            id: dummy::txid(config, rng).into(),
            inner: wsts::net::Message::DkgEndBegin(dkg_end_begin),
        }
    }
}

fn dummy_payload<P, R>(config: &fake::Faker, rng: &mut R) -> message::Payload
where
    P: Into<message::Payload> + fake::Dummy<fake::Faker>,
    R: rand::RngCore + ?Sized,
{
    config.fake_with_rng::<P, _>(rng).into()
}
