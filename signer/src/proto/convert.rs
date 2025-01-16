//! Conversion functions from a protobuf type to regular type and vice
//! versa.
//!
//! Converting to a protobuf type must be infallible, while converting from
//! a protobuf type can be fallible.
//!

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use bitcoin::OutPoint;
use bitvec::array::BitArray;
use clarity::codec::StacksMessageCodec as _;
use clarity::vm::types::PrincipalData;
use p256k1::point::Point;
use p256k1::scalar::Scalar;
use polynomial::Polynomial;
use secp256k1::ecdsa::RecoverableSignature;
use stacks_common::types::chainstate::StacksAddress;
use wsts::common::Nonce;
use wsts::common::PolyCommitment;
use wsts::common::PublicNonce;
use wsts::common::SignatureShare;
use wsts::common::TupleProof;
use wsts::net::BadPrivateShare;
use wsts::net::DkgBegin;
use wsts::net::DkgEnd;
use wsts::net::DkgEndBegin;
use wsts::net::DkgFailure;
use wsts::net::DkgPrivateBegin;
use wsts::net::DkgPrivateShares;
use wsts::net::DkgPublicShares;
use wsts::net::DkgStatus;
use wsts::net::NonceRequest;
use wsts::net::NonceResponse;
use wsts::net::SignatureShareRequest;
use wsts::net::SignatureShareResponse;
use wsts::net::SignatureType;
use wsts::traits::PartyState;
use wsts::traits::SignerState;

use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::TxRequestIds;
use crate::codec;
use crate::ecdsa::Signed;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::message::BitcoinPreSignAck;
use crate::message::BitcoinPreSignRequest;
use crate::message::Payload;
use crate::message::SignerDepositDecision;
use crate::message::SignerMessage;
use crate::message::SignerWithdrawalDecision;
use crate::message::StacksTransactionSignRequest;
use crate::message::StacksTransactionSignature;
use crate::message::WstsMessage;
use crate::proto;
use crate::stacks::contracts::AcceptWithdrawalV1;
use crate::stacks::contracts::CompleteDepositV1;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::RejectWithdrawalV1;
use crate::stacks::contracts::RotateKeysV1;
use crate::stacks::contracts::SmartContract;
use crate::stacks::contracts::StacksTx;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;

/// This trait is to make it easy to handle fields of protobuf structs that
/// are `None`, when they should be `Some(_)`.
trait RequiredField: Sized {
    type Inner;
    fn required(self) -> Result<Self::Inner, Error>;
}

impl<T> RequiredField for Option<T> {
    type Inner = T;
    fn required(self) -> Result<Self::Inner, Error> {
        self.ok_or(Error::RequiredProtobufFieldMissing)
    }
}

impl From<[u8; 32]> for proto::Uint256 {
    fn from(value: [u8; 32]) -> Self {
        let mut part0 = [0u8; 8];
        let mut part1 = [0u8; 8];
        let mut part2 = [0u8; 8];
        let mut part3 = [0u8; 8];

        part0.copy_from_slice(&value[..8]);
        part1.copy_from_slice(&value[8..16]);
        part2.copy_from_slice(&value[16..24]);
        part3.copy_from_slice(&value[24..32]);

        proto::Uint256 {
            bits_part0: u64::from_le_bytes(part0),
            bits_part1: u64::from_le_bytes(part1),
            bits_part2: u64::from_le_bytes(part2),
            bits_part3: u64::from_le_bytes(part3),
        }
    }
}

impl From<proto::Uint256> for [u8; 32] {
    fn from(value: proto::Uint256) -> Self {
        let mut bytes = [0u8; 32];

        bytes[..8].copy_from_slice(&value.bits_part0.to_le_bytes());
        bytes[8..16].copy_from_slice(&value.bits_part1.to_le_bytes());
        bytes[16..24].copy_from_slice(&value.bits_part2.to_le_bytes());
        bytes[24..32].copy_from_slice(&value.bits_part3.to_le_bytes());
        bytes
    }
}

impl From<PublicKey> for proto::PublicKey {
    fn from(value: PublicKey) -> Self {
        let (x_only, parity) = value.x_only_public_key();
        proto::PublicKey {
            x_only_public_key: Some(proto::Uint256::from(x_only.serialize())),
            parity_is_odd: parity == secp256k1::Parity::Odd,
        }
    }
}

impl TryFrom<proto::PublicKey> for PublicKey {
    type Error = Error;
    fn try_from(value: proto::PublicKey) -> Result<Self, Self::Error> {
        let x_only: [u8; 32] = value.x_only_public_key.required()?.into();
        let pk = secp256k1::XOnlyPublicKey::from_slice(&x_only).map_err(Error::InvalidPublicKey)?;
        let parity = if value.parity_is_odd {
            secp256k1::Parity::Odd
        } else {
            secp256k1::Parity::Even
        };
        let public_key = secp256k1::PublicKey::from_x_only_public_key(pk, parity);
        Ok(Self::from(public_key))
    }
}

impl From<RecoverableSignature> for proto::RecoverableSignature {
    fn from(value: RecoverableSignature) -> Self {
        let mut lower_bits = [0; 32];
        let mut upper_bits = [0; 32];

        let (recovery_id, bytes) = value.serialize_compact();

        lower_bits.copy_from_slice(&bytes[..32]);
        upper_bits.copy_from_slice(&bytes[32..]);

        Self {
            lower_bits: Some(proto::Uint256::from(lower_bits)),
            upper_bits: Some(proto::Uint256::from(upper_bits)),
            recovery_id: recovery_id.to_i32(),
        }
    }
}

impl TryFrom<proto::RecoverableSignature> for RecoverableSignature {
    type Error = Error;
    fn try_from(value: proto::RecoverableSignature) -> Result<Self, Self::Error> {
        let mut data = [0; 64];

        let lower_bits: [u8; 32] = value.lower_bits.required()?.into();
        let upper_bits: [u8; 32] = value.upper_bits.required()?.into();

        data[..32].copy_from_slice(&lower_bits);
        data[32..].copy_from_slice(&upper_bits);

        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(value.recovery_id)
            .map_err(Error::InvalidPublicKey)?;

        RecoverableSignature::from_compact(&data, recovery_id)
            .map_err(Error::InvalidRecoverableSignatureBytes)
    }
}

impl From<secp256k1::ecdsa::Signature> for proto::EcdsaSignature {
    fn from(value: secp256k1::ecdsa::Signature) -> Self {
        let mut lower_bits = [0; 32];
        let mut upper_bits = [0; 32];

        let bytes = value.serialize_compact();

        lower_bits.copy_from_slice(&bytes[..32]);
        upper_bits.copy_from_slice(&bytes[32..]);

        Self {
            lower_bits: Some(proto::Uint256::from(lower_bits)),
            upper_bits: Some(proto::Uint256::from(upper_bits)),
        }
    }
}

impl TryFrom<proto::EcdsaSignature> for secp256k1::ecdsa::Signature {
    type Error = Error;
    fn try_from(value: proto::EcdsaSignature) -> Result<Self, Self::Error> {
        let mut data = [0; 64];

        let lower_bits: [u8; 32] = value.lower_bits.required()?.into();
        let upper_bits: [u8; 32] = value.upper_bits.required()?.into();

        data[..32].copy_from_slice(&lower_bits);
        data[32..].copy_from_slice(&upper_bits);

        secp256k1::ecdsa::Signature::from_compact(&data).map_err(Error::InvalidEcdsaSignatureBytes)
    }
}

impl From<BitcoinTxId> for proto::BitcoinTxid {
    fn from(value: BitcoinTxId) -> Self {
        proto::BitcoinTxid {
            txid: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::BitcoinTxid> for BitcoinTxId {
    type Error = Error;
    fn try_from(value: proto::BitcoinTxid) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.txid.required()?.into();
        Ok(BitcoinTxId::from(bytes))
    }
}

impl From<BitcoinBlockHash> for proto::BitcoinBlockHash {
    fn from(value: BitcoinBlockHash) -> Self {
        proto::BitcoinBlockHash {
            block_hash: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::BitcoinBlockHash> for BitcoinBlockHash {
    type Error = Error;
    fn try_from(value: proto::BitcoinBlockHash) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.block_hash.required()?.into();
        Ok(BitcoinBlockHash::from(bytes))
    }
}

impl From<bitcoin::OutPoint> for proto::OutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        proto::OutPoint {
            txid: Some(proto::BitcoinTxid::from(BitcoinTxId::from(value.txid))),
            vout: value.vout,
        }
    }
}

impl TryFrom<proto::OutPoint> for bitcoin::OutPoint {
    type Error = Error;
    fn try_from(value: proto::OutPoint) -> Result<Self, Self::Error> {
        let txid: BitcoinTxId = value.txid.required()?.try_into()?;

        Ok(bitcoin::OutPoint {
            txid: txid.into(),
            vout: value.vout,
        })
    }
}

impl From<StacksTxId> for proto::StacksTxid {
    fn from(value: StacksTxId) -> Self {
        proto::StacksTxid {
            txid: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::StacksTxid> for StacksTxId {
    type Error = Error;
    fn try_from(value: proto::StacksTxid) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.txid.required()?.into();
        Ok(StacksTxId::from(bytes))
    }
}

impl From<StacksBlockHash> for proto::StacksBlockId {
    fn from(value: StacksBlockHash) -> Self {
        proto::StacksBlockId {
            block_id: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::StacksBlockId> for StacksBlockHash {
    type Error = Error;
    fn try_from(value: proto::StacksBlockId) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.block_id.required()?.into();
        Ok(StacksBlockHash::from(bytes))
    }
}

impl From<StacksAddress> for proto::StacksAddress {
    fn from(value: StacksAddress) -> Self {
        proto::StacksAddress {
            address: value.serialize_to_vec(),
        }
    }
}

impl TryFrom<proto::StacksAddress> for StacksAddress {
    type Error = Error;
    fn try_from(value: proto::StacksAddress) -> Result<Self, Self::Error> {
        let fd = &mut value.address.as_slice();
        StacksAddress::consensus_deserialize(fd).map_err(Error::StacksCodec)
    }
}

impl From<StacksPrincipal> for proto::StacksPrincipal {
    fn from(value: StacksPrincipal) -> Self {
        proto::StacksPrincipal { data: value.serialize_to_vec() }
    }
}

impl TryFrom<proto::StacksPrincipal> for StacksPrincipal {
    type Error = Error;
    fn try_from(value: proto::StacksPrincipal) -> Result<Self, Self::Error> {
        let fd = &mut value.data.as_slice();

        PrincipalData::consensus_deserialize(fd)
            .map(StacksPrincipal::from)
            .map_err(Error::StacksCodec)
    }
}

impl From<SignerDepositDecision> for proto::SignerDepositDecision {
    fn from(value: SignerDepositDecision) -> Self {
        proto::SignerDepositDecision {
            outpoint: Some(proto::OutPoint {
                txid: Some(BitcoinTxId::from(value.txid).into()),
                vout: value.output_index,
            }),
            can_accept: value.can_accept,
            can_sign: value.can_sign,
        }
    }
}

impl TryFrom<proto::SignerDepositDecision> for SignerDepositDecision {
    type Error = Error;
    fn try_from(value: proto::SignerDepositDecision) -> Result<Self, Self::Error> {
        let outpoint: bitcoin::OutPoint = value.outpoint.required()?.try_into()?;
        Ok(SignerDepositDecision {
            txid: outpoint.txid,
            output_index: outpoint.vout,
            can_accept: value.can_accept,
            can_sign: value.can_sign,
        })
    }
}

impl From<SignerWithdrawalDecision> for proto::SignerWithdrawalDecision {
    fn from(value: SignerWithdrawalDecision) -> Self {
        proto::SignerWithdrawalDecision {
            request_id: value.request_id,
            block_id: Some(StacksBlockHash::from(value.block_hash).into()),
            accepted: value.accepted,
            txid: Some(value.txid.into()),
        }
    }
}

impl TryFrom<proto::SignerWithdrawalDecision> for SignerWithdrawalDecision {
    type Error = Error;
    fn try_from(value: proto::SignerWithdrawalDecision) -> Result<Self, Self::Error> {
        Ok(SignerWithdrawalDecision {
            request_id: value.request_id,
            block_hash: StacksBlockHash::try_from(value.block_id.required()?)?.into_bytes(),
            accepted: value.accepted,
            txid: value.txid.required()?.try_into()?,
        })
    }
}

impl From<CompleteDepositV1> for proto::CompleteDeposit {
    fn from(value: CompleteDepositV1) -> Self {
        proto::CompleteDeposit {
            outpoint: Some(value.outpoint.into()),
            amount: value.amount,
            recipient: Some(StacksPrincipal::from(value.recipient).into()),
            deployer: Some(value.deployer.into()),
            sweep_txid: Some(value.sweep_txid.into()),
            sweep_block_hash: Some(value.sweep_block_hash.into()),
            sweep_block_height: value.sweep_block_height,
        }
    }
}

impl TryFrom<proto::CompleteDeposit> for CompleteDepositV1 {
    type Error = Error;
    fn try_from(value: proto::CompleteDeposit) -> Result<Self, Self::Error> {
        Ok(CompleteDepositV1 {
            outpoint: value.outpoint.required()?.try_into()?,
            amount: value.amount,
            recipient: StacksPrincipal::try_from(value.recipient.required()?)?.into(),
            deployer: value.deployer.required()?.try_into()?,
            sweep_txid: value.sweep_txid.required()?.try_into()?,
            sweep_block_hash: value.sweep_block_hash.required()?.try_into()?,
            sweep_block_height: value.sweep_block_height,
        })
    }
}

impl From<AcceptWithdrawalV1> for proto::AcceptWithdrawal {
    fn from(value: AcceptWithdrawalV1) -> Self {
        proto::AcceptWithdrawal {
            request_id: value.request_id,
            outpoint: Some(value.outpoint.into()),
            tx_fee: value.tx_fee,
            signer_bitmap: value.signer_bitmap.iter().map(|e| *e).collect(),
            deployer: Some(value.deployer.into()),
            sweep_block_hash: Some(value.sweep_block_hash.into()),
            sweep_block_height: value.sweep_block_height,
        }
    }
}

impl TryFrom<proto::AcceptWithdrawal> for AcceptWithdrawalV1 {
    type Error = Error;
    fn try_from(value: proto::AcceptWithdrawal) -> Result<Self, Self::Error> {
        let mut signer_bitmap = BitArray::ZERO;
        value
            .signer_bitmap
            .iter()
            .enumerate()
            .take(signer_bitmap.len().min(crate::MAX_KEYS as usize))
            .for_each(|(index, vote)| {
                // The BitArray::<[u8; 16]>::set function panics if the
                // index is out of bounds but that cannot be the case here
                // because we only take 128 values.
                signer_bitmap.set(index, *vote);
            });

        Ok(AcceptWithdrawalV1 {
            request_id: value.request_id,
            outpoint: value.outpoint.required()?.try_into()?,
            tx_fee: value.tx_fee,
            signer_bitmap,
            deployer: value.deployer.required()?.try_into()?,
            sweep_block_hash: value.sweep_block_hash.required()?.try_into()?,
            sweep_block_height: value.sweep_block_height,
        })
    }
}

impl From<RejectWithdrawalV1> for proto::RejectWithdrawal {
    fn from(value: RejectWithdrawalV1) -> Self {
        proto::RejectWithdrawal {
            request_id: value.request_id,
            signer_bitmap: value.signer_bitmap.iter().map(|e| *e).collect(),
            deployer: Some(value.deployer.into()),
        }
    }
}

impl TryFrom<proto::RejectWithdrawal> for RejectWithdrawalV1 {
    type Error = Error;
    fn try_from(value: proto::RejectWithdrawal) -> Result<Self, Self::Error> {
        let mut signer_bitmap = BitArray::ZERO;
        value
            .signer_bitmap
            .iter()
            .enumerate()
            .take(signer_bitmap.len().min(crate::MAX_KEYS as usize))
            .for_each(|(index, vote)| {
                // The BitArray::<[u8; 16]>::set function panics if the
                // index is out of bounds but that cannot be the case here
                // because we only take 128 values.
                signer_bitmap.set(index, *vote);
            });

        Ok(RejectWithdrawalV1 {
            request_id: value.request_id,
            signer_bitmap,
            deployer: value.deployer.required()?.try_into()?,
        })
    }
}

impl From<RotateKeysV1> for proto::RotateKeys {
    fn from(value: RotateKeysV1) -> Self {
        proto::RotateKeys {
            new_keys: value.new_keys.into_iter().map(|v| v.into()).collect(),
            aggregate_key: Some(value.aggregate_key.into()),
            deployer: Some(value.deployer.into()),
            signatures_required: value.signatures_required.into(),
        }
    }
}

impl TryFrom<proto::RotateKeys> for RotateKeysV1 {
    type Error = Error;
    fn try_from(value: proto::RotateKeys) -> Result<Self, Self::Error> {
        Ok(RotateKeysV1 {
            new_keys: value
                .new_keys
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<BTreeSet<_>, Error>>()?,
            aggregate_key: value.aggregate_key.required()?.try_into()?,
            deployer: value.deployer.required()?.try_into()?,
            signatures_required: value
                .signatures_required
                .try_into()
                .map_err(|_| Error::TypeConversion)?,
        })
    }
}

impl From<SmartContract> for proto::SmartContract {
    fn from(value: SmartContract) -> Self {
        match value {
            SmartContract::SbtcRegistry => proto::SmartContract::SbtcRegistry,
            SmartContract::SbtcToken => proto::SmartContract::SbtcToken,
            SmartContract::SbtcDeposit => proto::SmartContract::SbtcDeposit,
            SmartContract::SbtcWithdrawal => proto::SmartContract::SbtcWithdrawal,
            SmartContract::SbtcBootstrap => proto::SmartContract::SbtcBootstrap,
        }
    }
}

impl TryFrom<proto::SmartContract> for SmartContract {
    type Error = Error;
    fn try_from(value: proto::SmartContract) -> Result<Self, Self::Error> {
        Ok(match value {
            proto::SmartContract::SbtcRegistry => SmartContract::SbtcRegistry,
            proto::SmartContract::SbtcToken => SmartContract::SbtcToken,
            proto::SmartContract::SbtcDeposit => SmartContract::SbtcDeposit,
            proto::SmartContract::SbtcWithdrawal => SmartContract::SbtcWithdrawal,
            proto::SmartContract::SbtcBootstrap => SmartContract::SbtcBootstrap,
            proto::SmartContract::Unspecified => return Err(Error::TypeConversion),
        })
    }
}

impl From<StacksTransactionSignRequest> for proto::StacksTransactionSignRequest {
    fn from(value: StacksTransactionSignRequest) -> Self {
        let contract_tx = match value.contract_tx {
            StacksTx::ContractCall(contract_call) => match contract_call {
                ContractCall::CompleteDepositV1(inner) => {
                    proto::stacks_transaction_sign_request::ContractTx::CompleteDeposit(
                        inner.into(),
                    )
                }
                ContractCall::AcceptWithdrawalV1(inner) => {
                    proto::stacks_transaction_sign_request::ContractTx::AcceptWithdrawal(
                        inner.into(),
                    )
                }
                ContractCall::RejectWithdrawalV1(inner) => {
                    proto::stacks_transaction_sign_request::ContractTx::RejectWithdrawal(
                        inner.into(),
                    )
                }
                ContractCall::RotateKeysV1(inner) => {
                    proto::stacks_transaction_sign_request::ContractTx::RotateKeys(inner.into())
                }
            },
            StacksTx::SmartContract(inner) => {
                proto::stacks_transaction_sign_request::ContractTx::SmartContract(
                    proto::SmartContract::from(inner).into(),
                )
            }
        };
        proto::StacksTransactionSignRequest {
            aggregate_key: Some(value.aggregate_key.into()),
            nonce: value.nonce,
            tx_fee: value.tx_fee,
            txid: Some(StacksTxId::from(value.txid).into()),
            contract_tx: Some(contract_tx),
        }
    }
}

impl TryFrom<proto::StacksTransactionSignRequest> for StacksTransactionSignRequest {
    type Error = Error;
    fn try_from(value: proto::StacksTransactionSignRequest) -> Result<Self, Self::Error> {
        let contract_tx = match value.contract_tx.required()? {
            proto::ContractTx::CompleteDeposit(inner) => {
                StacksTx::ContractCall(ContractCall::CompleteDepositV1(inner.try_into()?))
            }
            proto::ContractTx::AcceptWithdrawal(inner) => {
                StacksTx::ContractCall(ContractCall::AcceptWithdrawalV1(inner.try_into()?))
            }
            proto::ContractTx::RejectWithdrawal(inner) => {
                StacksTx::ContractCall(ContractCall::RejectWithdrawalV1(inner.try_into()?))
            }
            proto::ContractTx::RotateKeys(inner) => {
                StacksTx::ContractCall(ContractCall::RotateKeysV1(inner.try_into()?))
            }
            proto::ContractTx::SmartContract(inner) => StacksTx::SmartContract(
                proto::SmartContract::try_from(inner)
                    .map_err(|_| Error::TypeConversion)?
                    .try_into()?,
            ),
        };
        Ok(StacksTransactionSignRequest {
            aggregate_key: value.aggregate_key.required()?.try_into()?,
            nonce: value.nonce,
            tx_fee: value.tx_fee,
            txid: StacksTxId::try_from(value.txid.required()?)?.into(),
            contract_tx,
        })
    }
}

impl From<DkgBegin> for proto::DkgBegin {
    fn from(value: DkgBegin) -> Self {
        proto::DkgBegin { dkg_id: value.dkg_id }
    }
}

impl From<proto::DkgBegin> for DkgBegin {
    fn from(value: proto::DkgBegin) -> Self {
        DkgBegin { dkg_id: value.dkg_id }
    }
}

impl From<DkgPrivateBegin> for proto::DkgPrivateBegin {
    fn from(value: DkgPrivateBegin) -> Self {
        proto::DkgPrivateBegin {
            dkg_id: value.dkg_id,
            signer_ids: value.signer_ids,
            key_ids: value.key_ids,
        }
    }
}

impl From<proto::DkgPrivateBegin> for DkgPrivateBegin {
    fn from(value: proto::DkgPrivateBegin) -> Self {
        DkgPrivateBegin {
            dkg_id: value.dkg_id,
            signer_ids: value.signer_ids,
            key_ids: value.key_ids,
        }
    }
}

impl From<DkgPrivateShares> for proto::DkgPrivateShares {
    fn from(value: DkgPrivateShares) -> Self {
        let shares = value
            .shares
            .into_iter()
            .map(|(source_signer_id, shares)| proto::PrivateShare {
                source_signer_id,
                encrypted_shares: shares
                    .into_iter()
                    .map(|(signer_id, encrypted_secret_share)| proto::SecretShare {
                        signer_id,
                        encrypted_secret_share,
                    })
                    .collect(),
            })
            .collect();
        proto::DkgPrivateShares {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            shares,
        }
    }
}

impl TryFrom<proto::DkgPrivateShares> for DkgPrivateShares {
    type Error = Error;
    fn try_from(value: proto::DkgPrivateShares) -> Result<Self, Self::Error> {
        let shares = value
            .shares
            .into_iter()
            .map(|share| {
                let encrypted_shares = share
                    .encrypted_shares
                    .into_iter()
                    .map(|v| (v.signer_id, v.encrypted_secret_share))
                    .collect();
                (share.source_signer_id, encrypted_shares)
            })
            .collect();
        Ok(DkgPrivateShares {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            shares,
        })
    }
}

impl From<DkgEndBegin> for proto::DkgEndBegin {
    fn from(value: DkgEndBegin) -> Self {
        proto::DkgEndBegin {
            dkg_id: value.dkg_id,
            signer_ids: value.signer_ids,
            key_ids: value.key_ids,
        }
    }
}

impl From<proto::DkgEndBegin> for DkgEndBegin {
    fn from(value: proto::DkgEndBegin) -> Self {
        DkgEndBegin {
            dkg_id: value.dkg_id,
            signer_ids: value.signer_ids,
            key_ids: value.key_ids,
        }
    }
}

impl From<TupleProof> for proto::TupleProof {
    fn from(value: TupleProof) -> Self {
        proto::TupleProof {
            combined_commitment: Some(value.rB.into()),
            signature: Some(proto::SchnorrProof {
                random_commitment: Some(value.R.into()),
                response: Some(value.z.into()),
            }),
        }
    }
}

impl TryFrom<proto::TupleProof> for TupleProof {
    type Error = Error;
    fn try_from(value: proto::TupleProof) -> Result<Self, Self::Error> {
        let signature = value.signature.required()?;
        Ok(TupleProof {
            R: signature.random_commitment.required()?.try_into()?,
            rB: value.combined_commitment.required()?.try_into()?,
            z: signature.response.required()?.try_into()?,
        })
    }
}

impl From<BadPrivateShare> for proto::BadPrivateShare {
    fn from(value: BadPrivateShare) -> Self {
        proto::BadPrivateShare {
            shared_key: Some(value.shared_key.into()),
            tuple_proof: Some(value.tuple_proof.into()),
        }
    }
}

impl TryFrom<proto::BadPrivateShare> for BadPrivateShare {
    type Error = Error;
    fn try_from(value: proto::BadPrivateShare) -> Result<Self, Self::Error> {
        Ok(BadPrivateShare {
            shared_key: value.shared_key.required()?.try_into()?,
            tuple_proof: value.tuple_proof.required()?.try_into()?,
        })
    }
}

impl From<hashbrown::HashMap<u32, BadPrivateShare>> for proto::BadPrivateShares {
    fn from(value: hashbrown::HashMap<u32, BadPrivateShare>) -> Self {
        proto::BadPrivateShares {
            shares: value.into_iter().map(|(k, v)| (k, v.into())).collect(),
        }
    }
}

impl TryFrom<proto::BadPrivateShares> for hashbrown::HashMap<u32, BadPrivateShare> {
    type Error = Error;
    fn try_from(value: proto::BadPrivateShares) -> Result<Self, Self::Error> {
        value
            .shares
            .into_iter()
            .map(|(k, v)| Ok((k, v.try_into()?)))
            .collect::<Result<hashbrown::HashMap<_, _>, Error>>()
    }
}

fn hashset_to_zst(set: hashbrown::HashSet<u32>) -> BTreeMap<u32, proto::SetValueZst> {
    set.into_iter()
        .map(|v| (v, proto::SetValueZst {}))
        .collect()
}

fn zst_to_hashset(set: BTreeMap<u32, proto::SetValueZst>) -> hashbrown::HashSet<u32> {
    set.into_keys().collect()
}

impl From<DkgStatus> for proto::DkgStatus {
    fn from(value: DkgStatus) -> Self {
        let mode = match value {
            DkgStatus::Success => proto::dkg_status::Mode::Success(proto::Success {}),
            DkgStatus::Failure(dkg_failure) => match dkg_failure {
                DkgFailure::BadState => proto::dkg_status::Mode::BadState(proto::BadState {}),
                DkgFailure::MissingPublicShares(inner) => {
                    proto::dkg_status::Mode::MissingPublicShares(proto::MissingPublicShares {
                        signer_ids: hashset_to_zst(inner),
                    })
                }
                DkgFailure::BadPublicShares(inner) => {
                    proto::dkg_status::Mode::BadPublicShares(proto::BadPublicShares {
                        signer_ids: hashset_to_zst(inner),
                    })
                }
                DkgFailure::MissingPrivateShares(inner) => {
                    proto::dkg_status::Mode::MissingPrivateShares(proto::MissingPrivateShares {
                        signer_ids: hashset_to_zst(inner),
                    })
                }
                DkgFailure::BadPrivateShares(inner) => {
                    proto::dkg_status::Mode::BadPrivateShares(inner.into())
                }
            },
        };
        proto::DkgStatus { mode: Some(mode) }
    }
}

impl TryFrom<proto::DkgStatus> for DkgStatus {
    type Error = Error;
    fn try_from(value: proto::DkgStatus) -> Result<Self, Self::Error> {
        Ok(match value.mode.required()? {
            proto::dkg_status::Mode::Success(_) => DkgStatus::Success,
            proto::dkg_status::Mode::BadState(_) => DkgStatus::Failure(DkgFailure::BadState),
            proto::dkg_status::Mode::MissingPublicShares(inner) => DkgStatus::Failure(
                DkgFailure::MissingPublicShares(zst_to_hashset(inner.signer_ids)),
            ),
            proto::dkg_status::Mode::BadPublicShares(inner) => DkgStatus::Failure(
                DkgFailure::BadPublicShares(zst_to_hashset(inner.signer_ids)),
            ),
            proto::dkg_status::Mode::MissingPrivateShares(inner) => DkgStatus::Failure(
                DkgFailure::MissingPrivateShares(zst_to_hashset(inner.signer_ids)),
            ),
            proto::dkg_status::Mode::BadPrivateShares(inner) => {
                DkgStatus::Failure(DkgFailure::BadPrivateShares(inner.try_into()?))
            }
        })
    }
}

impl From<DkgEnd> for proto::DkgEnd {
    fn from(value: DkgEnd) -> Self {
        proto::DkgEnd {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            status: Some(value.status.into()),
        }
    }
}

impl TryFrom<proto::DkgEnd> for DkgEnd {
    type Error = Error;
    fn try_from(value: proto::DkgEnd) -> Result<Self, Self::Error> {
        Ok(DkgEnd {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            status: value.status.required()?.try_into()?,
        })
    }
}

impl From<SignatureType> for proto::SignatureType {
    fn from(value: SignatureType) -> Self {
        let signature = match value {
            SignatureType::Frost => {
                proto::signature_type::SignatureType::Frost(proto::FrostSignatureType {})
            }
            SignatureType::Schnorr => {
                proto::signature_type::SignatureType::Schnorr(proto::SchnorrSignatureType {})
            }
            SignatureType::Taproot(root) => {
                proto::signature_type::SignatureType::Taproot(proto::TaprootSignatureType {
                    merkle_root: root.map(|v| proto::MerkleRoot { root: Some(v.into()) }),
                })
            }
        };
        proto::SignatureType {
            signature_type: Some(signature),
        }
    }
}

impl TryFrom<proto::SignatureType> for SignatureType {
    type Error = Error;
    fn try_from(value: proto::SignatureType) -> Result<Self, Self::Error> {
        Ok(match value.signature_type.required()? {
            proto::signature_type::SignatureType::Frost(_) => SignatureType::Frost,
            proto::signature_type::SignatureType::Schnorr(_) => SignatureType::Schnorr,
            proto::signature_type::SignatureType::Taproot(taproot) => SignatureType::Taproot(
                taproot
                    .merkle_root
                    .map(|v| Ok::<_, Error>(v.root.required()?.into()))
                    .transpose()?,
            ),
        })
    }
}

impl From<NonceRequest> for proto::NonceRequest {
    fn from(value: NonceRequest) -> Self {
        proto::NonceRequest {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            message: value.message,
            signature_type: Some(value.signature_type.into()),
        }
    }
}

impl TryFrom<proto::NonceRequest> for NonceRequest {
    type Error = Error;
    fn try_from(value: proto::NonceRequest) -> Result<Self, Self::Error> {
        Ok(NonceRequest {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            message: value.message,
            signature_type: value.signature_type.required()?.try_into()?,
        })
    }
}

impl From<PublicNonce> for proto::PublicNonce {
    fn from(value: PublicNonce) -> Self {
        proto::PublicNonce {
            nonce_d: Some(value.D.into()),
            nonce_e: Some(value.E.into()),
        }
    }
}

impl TryFrom<proto::PublicNonce> for PublicNonce {
    type Error = Error;
    fn try_from(value: proto::PublicNonce) -> Result<Self, Self::Error> {
        Ok(PublicNonce {
            D: value.nonce_d.required()?.try_into()?,
            E: value.nonce_e.required()?.try_into()?,
        })
    }
}

impl From<NonceResponse> for proto::NonceResponse {
    fn from(value: NonceResponse) -> Self {
        proto::NonceResponse {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            signer_id: value.signer_id,
            key_ids: value.key_ids,
            nonces: value.nonces.into_iter().map(|v| v.into()).collect(),
            message: value.message,
        }
    }
}

impl TryFrom<proto::NonceResponse> for NonceResponse {
    type Error = Error;
    fn try_from(value: proto::NonceResponse) -> Result<Self, Self::Error> {
        Ok(NonceResponse {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            signer_id: value.signer_id,
            key_ids: value.key_ids,
            nonces: value
                .nonces
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, Error>>()?,
            message: value.message,
        })
    }
}

impl From<SignatureShareRequest> for proto::SignatureShareRequest {
    fn from(value: SignatureShareRequest) -> Self {
        proto::SignatureShareRequest {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            message: value.message,
            nonce_responses: value
                .nonce_responses
                .into_iter()
                .map(|v| v.into())
                .collect(),
            signature_type: Some(value.signature_type.into()),
        }
    }
}

impl TryFrom<proto::SignatureShareRequest> for SignatureShareRequest {
    type Error = Error;
    fn try_from(value: proto::SignatureShareRequest) -> Result<Self, Self::Error> {
        Ok(SignatureShareRequest {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            nonce_responses: value
                .nonce_responses
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            message: value.message,
            signature_type: value.signature_type.required()?.try_into()?,
        })
    }
}

impl From<SignatureShare> for proto::SignatureShare {
    fn from(value: SignatureShare) -> Self {
        proto::SignatureShare {
            id: value.id,
            signature_share: Some(value.z_i.into()),
            key_ids: value.key_ids,
        }
    }
}

impl TryFrom<proto::SignatureShare> for SignatureShare {
    type Error = Error;
    fn try_from(value: proto::SignatureShare) -> Result<Self, Self::Error> {
        Ok(SignatureShare {
            id: value.id,
            z_i: value.signature_share.required()?.try_into()?,
            key_ids: value.key_ids,
        })
    }
}

impl From<SignatureShareResponse> for proto::SignatureShareResponse {
    fn from(value: SignatureShareResponse) -> Self {
        proto::SignatureShareResponse {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            signer_id: value.signer_id,
            signature_shares: value
                .signature_shares
                .into_iter()
                .map(|v| v.into())
                .collect(),
        }
    }
}

impl TryFrom<proto::SignatureShareResponse> for SignatureShareResponse {
    type Error = Error;
    fn try_from(value: proto::SignatureShareResponse) -> Result<Self, Self::Error> {
        Ok(SignatureShareResponse {
            dkg_id: value.dkg_id,
            sign_id: value.sign_id,
            sign_iter_id: value.sign_iter_id,
            signer_id: value.signer_id,
            signature_shares: value
                .signature_shares
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}
impl From<WstsMessage> for proto::WstsMessage {
    fn from(value: WstsMessage) -> Self {
        let inner = match value.inner {
            wsts::net::Message::DkgBegin(inner) => {
                proto::wsts_message::Inner::DkgBegin(inner.into())
            }
            wsts::net::Message::DkgPublicShares(inner) => {
                proto::wsts_message::Inner::SignerDkgPublicShares(inner.into())
            }
            wsts::net::Message::DkgPrivateBegin(inner) => {
                proto::wsts_message::Inner::DkgPrivateBegin(inner.into())
            }
            wsts::net::Message::DkgPrivateShares(inner) => {
                proto::wsts_message::Inner::DkgPrivateShares(inner.into())
            }
            wsts::net::Message::DkgEndBegin(inner) => {
                proto::wsts_message::Inner::DkgEndBegin(inner.into())
            }
            wsts::net::Message::DkgEnd(inner) => proto::wsts_message::Inner::DkgEnd(inner.into()),
            wsts::net::Message::NonceRequest(inner) => {
                proto::wsts_message::Inner::NonceRequest(inner.into())
            }
            wsts::net::Message::NonceResponse(inner) => {
                proto::wsts_message::Inner::NonceResponse(inner.into())
            }
            wsts::net::Message::SignatureShareRequest(inner) => {
                proto::wsts_message::Inner::SignatureShareRequest(inner.into())
            }
            wsts::net::Message::SignatureShareResponse(inner) => {
                proto::wsts_message::Inner::SignatureShareResponse(inner.into())
            }
        };
        proto::WstsMessage {
            txid: Some(BitcoinTxId::from(value.txid).into()),
            inner: Some(inner),
        }
    }
}

impl TryFrom<proto::WstsMessage> for WstsMessage {
    type Error = Error;
    fn try_from(value: proto::WstsMessage) -> Result<Self, Self::Error> {
        let inner = match value.inner.required()? {
            proto::wsts_message::Inner::DkgBegin(inner) => {
                wsts::net::Message::DkgBegin(inner.into())
            }
            proto::wsts_message::Inner::SignerDkgPublicShares(inner) => {
                wsts::net::Message::DkgPublicShares(inner.try_into()?)
            }
            proto::wsts_message::Inner::DkgPrivateBegin(inner) => {
                wsts::net::Message::DkgPrivateBegin(inner.into())
            }
            proto::wsts_message::Inner::DkgPrivateShares(inner) => {
                wsts::net::Message::DkgPrivateShares(inner.try_into()?)
            }
            proto::wsts_message::Inner::DkgEndBegin(inner) => {
                wsts::net::Message::DkgEndBegin(inner.into())
            }
            proto::wsts_message::Inner::DkgEnd(inner) => {
                wsts::net::Message::DkgEnd(inner.try_into()?)
            }
            proto::wsts_message::Inner::NonceRequest(inner) => {
                wsts::net::Message::NonceRequest(inner.try_into()?)
            }
            proto::wsts_message::Inner::NonceResponse(inner) => {
                wsts::net::Message::NonceResponse(inner.try_into()?)
            }
            proto::wsts_message::Inner::SignatureShareRequest(inner) => {
                wsts::net::Message::SignatureShareRequest(inner.try_into()?)
            }
            proto::wsts_message::Inner::SignatureShareResponse(inner) => {
                wsts::net::Message::SignatureShareResponse(inner.try_into()?)
            }
        };
        Ok(WstsMessage {
            txid: BitcoinTxId::try_from(value.txid.required()?)?.into(),
            inner,
        })
    }
}

impl From<StacksTransactionSignature> for proto::StacksTransactionSignature {
    fn from(value: StacksTransactionSignature) -> Self {
        proto::StacksTransactionSignature {
            txid: Some(StacksTxId::from(value.txid).into()),
            signature: Some(value.signature.into()),
        }
    }
}

impl TryFrom<proto::StacksTransactionSignature> for StacksTransactionSignature {
    type Error = Error;
    fn try_from(value: proto::StacksTransactionSignature) -> Result<Self, Self::Error> {
        Ok(StacksTransactionSignature {
            txid: StacksTxId::try_from(value.txid.required()?)?.into(),
            signature: value.signature.required()?.try_into()?,
        })
    }
}

impl From<QualifiedRequestId> for proto::QualifiedRequestId {
    fn from(value: QualifiedRequestId) -> Self {
        proto::QualifiedRequestId {
            request_id: value.request_id,
            txid: Some(value.txid.into()),
            block_hash: Some(value.block_hash.into()),
        }
    }
}

impl TryFrom<proto::QualifiedRequestId> for QualifiedRequestId {
    type Error = Error;
    fn try_from(value: proto::QualifiedRequestId) -> Result<Self, Self::Error> {
        Ok(QualifiedRequestId {
            request_id: value.request_id,
            txid: StacksTxId::try_from(value.txid.required()?)?,
            block_hash: value.block_hash.required()?.try_into()?,
        })
    }
}

impl From<TxRequestIds> for proto::TxRequestIds {
    fn from(value: TxRequestIds) -> Self {
        proto::TxRequestIds {
            deposits: value
                .deposits
                .into_iter()
                .map(proto::OutPoint::from)
                .collect(),
            withdrawals: value.withdrawals.into_iter().map(|v| v.into()).collect(),
        }
    }
}

impl TryFrom<proto::TxRequestIds> for TxRequestIds {
    type Error = Error;
    fn try_from(value: proto::TxRequestIds) -> Result<Self, Self::Error> {
        Ok(TxRequestIds {
            deposits: value
                .deposits
                .into_iter()
                .map(OutPoint::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            withdrawals: value
                .withdrawals
                .into_iter()
                .map(QualifiedRequestId::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<Fees> for proto::Fees {
    fn from(value: Fees) -> Self {
        proto::Fees {
            total: value.total,
            rate: value.rate,
        }
    }
}

impl From<proto::Fees> for Fees {
    fn from(value: proto::Fees) -> Self {
        Fees {
            total: value.total,
            rate: value.rate,
        }
    }
}

impl From<BitcoinPreSignRequest> for proto::BitcoinPreSignRequest {
    fn from(value: BitcoinPreSignRequest) -> Self {
        proto::BitcoinPreSignRequest {
            request_package: value
                .request_package
                .into_iter()
                .map(|v| v.into())
                .collect(),
            fee_rate: value.fee_rate,
            last_fees: value.last_fees.map(|v| v.into()),
        }
    }
}

impl TryFrom<proto::BitcoinPreSignRequest> for BitcoinPreSignRequest {
    type Error = Error;
    fn try_from(value: proto::BitcoinPreSignRequest) -> Result<Self, Self::Error> {
        Ok(BitcoinPreSignRequest {
            request_package: value
                .request_package
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            fee_rate: value.fee_rate,
            last_fees: value.last_fees.map(|v| v.into()),
        })
    }
}

impl From<BitcoinPreSignAck> for proto::BitcoinPreSignAck {
    fn from(_: BitcoinPreSignAck) -> Self {
        proto::BitcoinPreSignAck {}
    }
}

impl From<proto::BitcoinPreSignAck> for BitcoinPreSignAck {
    fn from(_: proto::BitcoinPreSignAck) -> Self {
        BitcoinPreSignAck {}
    }
}

impl From<SignerMessage> for proto::SignerMessage {
    fn from(value: SignerMessage) -> Self {
        proto::SignerMessage {
            bitcoin_chain_tip: Some(value.bitcoin_chain_tip.into()),
            payload: Some(value.payload.into()),
        }
    }
}

impl TryFrom<proto::SignerMessage> for SignerMessage {
    type Error = Error;
    fn try_from(value: proto::SignerMessage) -> Result<Self, Self::Error> {
        Ok(SignerMessage {
            bitcoin_chain_tip: value.bitcoin_chain_tip.required()?.try_into()?,
            payload: value.payload.required()?.try_into()?,
        })
    }
}

impl From<Payload> for proto::Payload {
    fn from(value: Payload) -> Self {
        match value {
            Payload::SignerDepositDecision(inner) => {
                proto::signer_message::Payload::SignerDepositDecision(inner.into())
            }
            Payload::SignerWithdrawalDecision(inner) => {
                proto::signer_message::Payload::SignerWithdrawalDecision(inner.into())
            }
            Payload::StacksTransactionSignRequest(inner) => {
                proto::signer_message::Payload::StacksTransactionSignRequest(inner.into())
            }
            Payload::StacksTransactionSignature(inner) => {
                proto::signer_message::Payload::StacksTransactionSignature(inner.into())
            }
            Payload::WstsMessage(inner) => {
                proto::signer_message::Payload::WstsMessage(inner.into())
            }
            Payload::BitcoinPreSignRequest(inner) => {
                proto::signer_message::Payload::BitcoinPreSignRequest(inner.into())
            }
            Payload::BitcoinPreSignAck(inner) => {
                proto::signer_message::Payload::BitcoinPreSignAck(inner.into())
            }
        }
    }
}

impl TryFrom<proto::Payload> for Payload {
    type Error = Error;
    fn try_from(value: proto::Payload) -> Result<Self, Self::Error> {
        let payload = match value {
            proto::signer_message::Payload::SignerDepositDecision(inner) => {
                Payload::SignerDepositDecision(inner.try_into()?)
            }
            proto::signer_message::Payload::SignerWithdrawalDecision(inner) => {
                Payload::SignerWithdrawalDecision(inner.try_into()?)
            }
            proto::signer_message::Payload::StacksTransactionSignRequest(inner) => {
                Payload::StacksTransactionSignRequest(inner.try_into()?)
            }
            proto::signer_message::Payload::StacksTransactionSignature(inner) => {
                Payload::StacksTransactionSignature(inner.try_into()?)
            }
            proto::signer_message::Payload::WstsMessage(inner) => {
                Payload::WstsMessage(inner.try_into()?)
            }
            proto::signer_message::Payload::BitcoinPreSignRequest(inner) => {
                Payload::BitcoinPreSignRequest(inner.try_into()?)
            }
            proto::signer_message::Payload::BitcoinPreSignAck(inner) => {
                Payload::BitcoinPreSignAck(inner.into())
            }
        };
        Ok(payload)
    }
}

impl From<Signed<SignerMessage>> for proto::Signed {
    fn from(value: Signed<SignerMessage>) -> Self {
        proto::Signed {
            signature: Some(value.signature.into()),
            signer_public_key: Some(value.signer_public_key.into()),
            signer_message: Some(value.inner.into()),
        }
    }
}

impl TryFrom<proto::Signed> for Signed<SignerMessage> {
    type Error = Error;
    fn try_from(value: proto::Signed) -> Result<Self, Self::Error> {
        let inner: SignerMessage = value.signer_message.required()?.try_into()?;
        Ok(Signed {
            inner,
            signature: value.signature.required()?.try_into()?,
            signer_public_key: value.signer_public_key.required()?.try_into()?,
        })
    }
}

impl From<Point> for proto::Point {
    fn from(value: Point) -> Self {
        let [parity, x_coordinate @ ..] = value.compress().data;
        proto::Point {
            x_coordinate: Some(proto::Uint256::from(x_coordinate)),
            parity_is_odd: parity == 3, // SECP256K1_TAG_PUBKEY_ODD
        }
    }
}

impl TryFrom<proto::Point> for Point {
    type Error = Error;
    fn try_from(value: proto::Point) -> Result<Self, Self::Error> {
        let x_coordinate: [u8; 32] = value.x_coordinate.required()?.into();
        let field_element = p256k1::field::Element::from(x_coordinate);
        // This gives you a point with even parity. We may need to negate the
        // point so that it has the correct parity.
        let point = Point::lift_x(&field_element).map_err(|_| Error::TypeConversion)?;

        if value.parity_is_odd {
            Ok(-point)
        } else {
            Ok(point)
        }
    }
}

impl From<Scalar> for proto::Scalar {
    fn from(value: Scalar) -> Self {
        proto::Scalar {
            value: Some(value.to_bytes().into()),
        }
    }
}

impl TryFrom<proto::Scalar> for Scalar {
    type Error = Error;
    fn try_from(value: proto::Scalar) -> Result<Self, Self::Error> {
        let scalar: [u8; 32] = value.value.required()?.into();
        Ok(Scalar::from(scalar))
    }
}

impl From<Polynomial<Scalar>> for proto::Polynomial {
    fn from(value: Polynomial<Scalar>) -> Self {
        proto::Polynomial {
            data: value
                .data()
                .iter()
                .map(|v| proto::Scalar::from(*v))
                .collect(),
        }
    }
}

impl TryFrom<proto::Polynomial> for Polynomial<Scalar> {
    type Error = Error;
    fn try_from(value: proto::Polynomial) -> Result<Self, Self::Error> {
        Ok(Polynomial::new(
            value
                .data
                .into_iter()
                .map(Scalar::try_from)
                .collect::<Result<Vec<_>, Error>>()?,
        ))
    }
}

impl From<(u32, Scalar)> for proto::PrivateKeyShare {
    fn from((key_id, value): (u32, Scalar)) -> Self {
        proto::PrivateKeyShare {
            key_id,
            private_key: Some(value.into()),
        }
    }
}

impl TryFrom<proto::PrivateKeyShare> for (u32, Scalar) {
    type Error = Error;
    fn try_from(value: proto::PrivateKeyShare) -> Result<Self, Self::Error> {
        Ok((value.key_id, value.private_key.required()?.try_into()?))
    }
}

impl From<Nonce> for proto::PrivateNonce {
    fn from(value: Nonce) -> Self {
        proto::PrivateNonce {
            nonce_d: Some(value.d.into()),
            nonce_e: Some(value.e.into()),
        }
    }
}

impl TryFrom<proto::PrivateNonce> for Nonce {
    type Error = Error;
    fn try_from(value: proto::PrivateNonce) -> Result<Self, Self::Error> {
        Ok(Nonce {
            d: value.nonce_d.required()?.try_into()?,
            e: value.nonce_e.required()?.try_into()?,
        })
    }
}

impl From<(u32, PartyState)> for proto::PartyState {
    fn from((key_id, value): (u32, PartyState)) -> Self {
        proto::PartyState {
            key_id,
            polynomial: value.polynomial.map(|v| v.into()),
            private_keys: value.private_keys.into_iter().map(|v| v.into()).collect(),
            nonce: Some(value.nonce.into()),
        }
    }
}

impl TryFrom<proto::PartyState> for (u32, PartyState) {
    type Error = Error;
    fn try_from(value: proto::PartyState) -> Result<Self, Self::Error> {
        Ok((
            value.key_id,
            PartyState {
                polynomial: value.polynomial.map(|v| v.try_into()).transpose()?,
                private_keys: value
                    .private_keys
                    .into_iter()
                    .map(|v| v.try_into())
                    .collect::<Result<Vec<_>, Error>>()?,
                nonce: value.nonce.required()?.try_into()?,
            },
        ))
    }
}

impl From<SignerState> for proto::SignerState {
    fn from(value: SignerState) -> Self {
        proto::SignerState {
            id: value.id,
            key_ids: value.key_ids,
            num_keys: value.num_keys,
            num_parties: value.num_parties,
            threshold: value.threshold,
            group_key: Some(value.group_key.into()),
            parties: value.parties.into_iter().map(|v| v.into()).collect(),
        }
    }
}

impl TryFrom<proto::SignerState> for SignerState {
    type Error = Error;
    fn try_from(value: proto::SignerState) -> Result<Self, Self::Error> {
        Ok(SignerState {
            id: value.id,
            key_ids: value.key_ids,
            num_keys: value.num_keys,
            num_parties: value.num_parties,
            threshold: value.threshold,
            group_key: value.group_key.required()?.try_into()?,
            parties: value
                .parties
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, Error>>()?,
        })
    }
}

impl From<wsts::schnorr::ID> for proto::ProofIdentifier {
    fn from(value: wsts::schnorr::ID) -> Self {
        proto::ProofIdentifier {
            id: Some(value.id.into()),
            schnorr_response: Some(value.kG.into()),
            aggregate_commitment: Some(value.kca.into()),
        }
    }
}

impl TryFrom<proto::ProofIdentifier> for wsts::schnorr::ID {
    type Error = Error;
    fn try_from(value: proto::ProofIdentifier) -> Result<Self, Self::Error> {
        Ok(wsts::schnorr::ID {
            id: value.id.required()?.try_into()?,
            kG: value.schnorr_response.required()?.try_into()?,
            kca: value.aggregate_commitment.required()?.try_into()?,
        })
    }
}

impl From<PolyCommitment> for proto::PolyCommitment {
    fn from(value: PolyCommitment) -> Self {
        proto::PolyCommitment {
            id: Some(value.id.into()),
            poly: value.poly.into_iter().map(|v| v.into()).collect(),
        }
    }
}

impl TryFrom<proto::PolyCommitment> for PolyCommitment {
    type Error = Error;
    fn try_from(value: proto::PolyCommitment) -> Result<Self, Self::Error> {
        Ok(PolyCommitment {
            id: value.id.required()?.try_into()?,
            poly: value
                .poly
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, Error>>()?,
        })
    }
}

impl From<(u32, PolyCommitment)> for proto::PartyCommitment {
    fn from((signer_id, value): (u32, PolyCommitment)) -> Self {
        proto::PartyCommitment {
            signer_id,
            commitment: Some(value.into()),
        }
    }
}

impl TryFrom<proto::PartyCommitment> for (u32, PolyCommitment) {
    type Error = Error;
    fn try_from(value: proto::PartyCommitment) -> Result<Self, Self::Error> {
        Ok((value.signer_id, value.commitment.required()?.try_into()?))
    }
}

impl From<DkgPublicShares> for proto::SignerDkgPublicShares {
    fn from(value: DkgPublicShares) -> Self {
        proto::SignerDkgPublicShares {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            commitments: value.comms.into_iter().map(|v| v.into()).collect(),
        }
    }
}

impl TryFrom<proto::SignerDkgPublicShares> for DkgPublicShares {
    type Error = Error;
    fn try_from(value: proto::SignerDkgPublicShares) -> Result<Self, Self::Error> {
        Ok(DkgPublicShares {
            dkg_id: value.dkg_id,
            signer_id: value.signer_id,
            comms: value
                .commitments
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<_>, Error>>()?,
        })
    }
}

impl From<BTreeMap<u32, DkgPublicShares>> for proto::DkgPublicShares {
    fn from(value: BTreeMap<u32, DkgPublicShares>) -> Self {
        proto::DkgPublicShares {
            shares: value.into_iter().map(|(k, v)| (k, v.into())).collect(),
        }
    }
}

impl TryFrom<proto::DkgPublicShares> for BTreeMap<u32, DkgPublicShares> {
    type Error = Error;
    fn try_from(value: proto::DkgPublicShares) -> Result<Self, Self::Error> {
        value
            .shares
            .into_iter()
            .map(|(v, k)| Ok((v, k.try_into()?)))
            .collect::<Result<BTreeMap<u32, DkgPublicShares>, Error>>()
    }
}

impl codec::ProtoSerializable for SignerMessage {
    type Message = proto::SignerMessage;

    fn type_tag(&self) -> &'static str {
        match &self.payload {
            Payload::SignerDepositDecision(_) => "SBTC_SIGNER_DEPOSIT_DECISION",
            Payload::SignerWithdrawalDecision(_) => "SBTC_SIGNER_WITHDRAWAL_DECISION",
            Payload::StacksTransactionSignRequest(_) => "SBTC_STACKS_TRANSACTION_SIGN_REQUEST",
            Payload::StacksTransactionSignature(_) => "SBTC_STACKS_TRANSACTION_SIGNATURE",
            Payload::WstsMessage(_) => "SBTC_WSTS_MESSAGE",
            Payload::BitcoinPreSignRequest(_) => "SBTC_BITCOIN_PRE_SIGN_REQUEST",
            Payload::BitcoinPreSignAck(_) => "SBTC_BITCOIN_PRE_SIGN_ACK",
        }
    }
}

impl codec::ProtoSerializable for Signed<SignerMessage> {
    type Message = proto::Signed;

    fn type_tag(&self) -> &'static str {
        self.inner.type_tag()
    }
}

impl codec::ProtoSerializable for SignerState {
    type Message = proto::SignerState;

    fn type_tag(&self) -> &'static str {
        "SBTC_SIGNER_STATE"
    }
}

impl codec::ProtoSerializable for BTreeMap<u32, DkgPublicShares> {
    type Message = proto::DkgPublicShares;

    fn type_tag(&self) -> &'static str {
        "SBTC_DKG_PUBLIC_SHARES"
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::dummy::Unit;

    use super::*;

    use std::marker::PhantomData;

    use fake::Dummy;
    use fake::Fake as _;
    use fake::Faker;
    use rand::rngs::OsRng;
    use test_case::test_case;

    #[test]
    fn conversion_between_bytes_and_uint256() {
        let number = proto::Uint256 {
            bits_part0: Faker.fake_with_rng(&mut OsRng),
            bits_part1: Faker.fake_with_rng(&mut OsRng),
            bits_part2: Faker.fake_with_rng(&mut OsRng),
            bits_part3: Faker.fake_with_rng(&mut OsRng),
        };

        let bytes = <[u8; 32]>::from(number);
        let round_trip_number = proto::Uint256::from(bytes);
        assert_eq!(round_trip_number, number);
    }

    #[test_case(PhantomData::<([u8; 32], proto::Uint256)>; "Uint256")]
    #[test_case(PhantomData::<(PublicKey, proto::PublicKey)>; "PublicKey")]
    #[test_case(PhantomData::<(BitcoinTxId, proto::BitcoinTxid)>; "BitcoinTxId")]
    #[test_case(PhantomData::<(BitcoinBlockHash, proto::BitcoinBlockHash)>; "BitcoinBlockHash")]
    #[test_case(PhantomData::<(StacksTxId, proto::StacksTxid)>; "StacksTxId")]
    #[test_case(PhantomData::<(StacksBlockHash, proto::StacksBlockId)>; "StacksBlockHash")]
    #[test_case(PhantomData::<(StacksPrincipal, proto::StacksPrincipal)>; "StacksPrincipal")]
    #[test_case(PhantomData::<(SignerDepositDecision, proto::SignerDepositDecision)>; "SignerDepositDecision")]
    #[test_case(PhantomData::<(SignerWithdrawalDecision, proto::SignerWithdrawalDecision)>; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<(StacksTransactionSignature, proto::StacksTransactionSignature)>; "StacksTransactionSignature")]
    #[test_case(PhantomData::<(CompleteDepositV1, proto::CompleteDeposit)>; "CompleteDeposit")]
    #[test_case(PhantomData::<(AcceptWithdrawalV1, proto::AcceptWithdrawal)>; "AcceptWithdrawal")]
    #[test_case(PhantomData::<(RejectWithdrawalV1, proto::RejectWithdrawal)>; "RejectWithdrawal")]
    #[test_case(PhantomData::<(RotateKeysV1, proto::RotateKeys)>; "RotateKeys")]
    #[test_case(PhantomData::<(SmartContract, proto::SmartContract)>; "SmartContract")]
    #[test_case(PhantomData::<(Payload, proto::Payload)>; "Payload")]
    #[test_case(PhantomData::<(StacksTransactionSignRequest, proto::StacksTransactionSignRequest)>; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<(WstsMessage, proto::WstsMessage)>; "WstsMessage")]
    #[test_case(PhantomData::<(SignerMessage, proto::SignerMessage)>; "SignerMessage")]
    #[test_case(PhantomData::<(Signed<SignerMessage>, proto::Signed)>; "Signed")]
    #[test_case(PhantomData::<(QualifiedRequestId, proto::QualifiedRequestId)>; "QualifiedRequestId")]
    #[test_case(PhantomData::<(TxRequestIds, proto::TxRequestIds)>; "TxRequestIds")]
    #[test_case(PhantomData::<(Fees, proto::Fees)>; "Fees")]
    #[test_case(PhantomData::<(BitcoinPreSignRequest, proto::BitcoinPreSignRequest)>; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<(BitcoinPreSignAck, proto::BitcoinPreSignAck)>; "BitcoinPreSignAck")]
    fn convert_protobuf_type<T, U, E>(_: PhantomData<(T, U)>)
    where
        // `.unwrap()` requires that `E` implement `std::fmt::Debug` and
        // `assert_eq!` requires `PartialEq + std::fmt::Debug`.
        T: Dummy<Faker> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T>,
        E: std::fmt::Debug,
    {
        // The type T originates from a signer. Let's create a random
        // instance of one.
        let original: T = Faker.fake_with_rng(&mut OsRng);
        // The type U is a protobuf type. Before sending it to other
        // signers, we convert our internal type into it's protobuf
        // counterpart. We can always infallibly create U from T.
        let proto_original = U::from(original.clone());

        // Some other signer receives an instance of U. This could be a
        // malicious actor or a modified version of the signer binary
        // where they made some mistake, so converting back to T can fail.
        let original_from_proto = T::try_from(proto_original).unwrap();
        // In this case, we know U was created from T correctly, so we
        // should be able to convert back without issues.
        assert_eq!(original, original_from_proto);
    }

    /// This test is identical to [`convert_protobuf_types`] tests above,
    /// except we cannot implement Dummy<Faker> on these types.
    #[test_case(PhantomData::<(bitcoin::OutPoint, proto::OutPoint)>; "OutPoint")]
    #[test_case(PhantomData::<(RecoverableSignature, proto::RecoverableSignature)>; "RecoverableSignature")]
    #[test_case(PhantomData::<(secp256k1::ecdsa::Signature, proto::EcdsaSignature)>; "EcdsaSignature")]
    #[test_case(PhantomData::<(StacksAddress, proto::StacksAddress)>; "StacksAddress")]
    #[test_case(PhantomData::<(Point, proto::Point)>; "Point")]
    #[test_case(PhantomData::<(Scalar, proto::Scalar)>; "Scalar")]
    #[test_case(PhantomData::<(Polynomial<Scalar>, proto::Polynomial)>; "Polynomial")]
    #[test_case(PhantomData::<((u32, Scalar), proto::PrivateKeyShare)>; "PrivateKeyShare")]
    #[test_case(PhantomData::<(DkgBegin, proto::DkgBegin)>; "DkgBegin")]
    #[test_case(PhantomData::<(DkgPrivateBegin, proto::DkgPrivateBegin)>; "DkgPrivateBegin")]
    #[test_case(PhantomData::<(DkgPrivateShares, proto::DkgPrivateShares)>; "DkgPrivateShares")]
    #[test_case(PhantomData::<(DkgEndBegin, proto::DkgEndBegin)>; "DkgEndBegin")]
    #[test_case(PhantomData::<(TupleProof, proto::TupleProof)>; "TupleProof")]
    #[test_case(PhantomData::<(BadPrivateShare, proto::BadPrivateShare)>; "BadPrivateShare")]
    #[test_case(PhantomData::<(hashbrown::HashMap<u32, BadPrivateShare>, proto::BadPrivateShares)>; "BadPrivateShares")]
    #[test_case(PhantomData::<(DkgStatus, proto::DkgStatus)>; "DkgStatus")]
    #[test_case(PhantomData::<(DkgEnd, proto::DkgEnd)>; "DkgEnd")]
    #[test_case(PhantomData::<(SignatureType, proto::SignatureType)>; "SignatureType")]
    #[test_case(PhantomData::<(NonceRequest, proto::NonceRequest)>; "NonceRequest")]
    #[test_case(PhantomData::<(PublicNonce, proto::PublicNonce)>; "PublicNonce")]
    #[test_case(PhantomData::<(NonceResponse, proto::NonceResponse)>; "NonceResponse")]
    #[test_case(PhantomData::<(SignatureShareRequest, proto::SignatureShareRequest)>; "SignatureShareRequest")]
    #[test_case(PhantomData::<(SignatureShare, proto::SignatureShare)>; "SignatureShare")]
    #[test_case(PhantomData::<(SignatureShareResponse, proto::SignatureShareResponse)>; "SignatureShareResponse")]
    #[test_case(PhantomData::<(Nonce, proto::PrivateNonce)>; "PrivateNonce")]
    #[test_case(PhantomData::<(wsts::schnorr::ID, proto::ProofIdentifier)>; "ProofIdentifier")]
    #[test_case(PhantomData::<(PolyCommitment, proto::PolyCommitment)>; "PolyCommitment")]
    #[test_case(PhantomData::<((u32, PolyCommitment), proto::PartyCommitment)>; "PartyCommitment")]
    #[test_case(PhantomData::<(DkgPublicShares, proto::SignerDkgPublicShares)>; "SignerDkgPublicShares")]
    #[test_case(PhantomData::<(BTreeMap<u32, DkgPublicShares>, proto::DkgPublicShares)>; "DkgPublicShares")]
    fn convert_protobuf_type2<T, U, E>(_: PhantomData<(T, U)>)
    where
        T: Dummy<Unit> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T>,
        E: std::fmt::Debug,
    {
        let original: T = Unit.fake_with_rng(&mut OsRng);
        let proto_original = U::from(original.clone());

        let original_from_proto = T::try_from(proto_original).unwrap();
        assert_eq!(original, original_from_proto);
    }

    // The following are tests for structs that do not derive eq
    #[derive(Debug)]
    struct PartyStateWrapper((u32, PartyState));

    impl PartialEq for PartyStateWrapper {
        fn eq(&self, other: &Self) -> bool {
            self.0 .0 == other.0 .0
                && self.0 .1.nonce == other.0 .1.nonce
                && self.0 .1.polynomial == other.0 .1.polynomial
                && self.0 .1.private_keys == other.0 .1.private_keys
        }
    }

    #[derive(Debug)]
    struct SignerStateWrapper(SignerState);

    impl PartialEq for SignerStateWrapper {
        fn eq(&self, other: &Self) -> bool {
            self.0.group_key == other.0.group_key
                && self.0.id == other.0.id
                && self.0.key_ids == other.0.key_ids
                && self.0.num_keys == other.0.num_keys
                && self.0.num_parties == other.0.num_parties
                && self.0.threshold == other.0.threshold
                && self.0.parties.len() == other.0.parties.len()
                && self
                    .0
                    .parties
                    .iter()
                    .zip(other.0.parties.iter())
                    .all(|(a, b)| PartyStateWrapper(a.clone()) == PartyStateWrapper(b.clone()))
        }
    }

    #[test_case(PhantomData::<((u32, PartyState), proto::PartyState)>, PartyStateWrapper; "PartyState")]
    #[test_case(PhantomData::<(SignerState, proto::SignerState)>, SignerStateWrapper; "SignerState")]
    fn convert_protobuf_type3<T, U, V, E>(_: PhantomData<(T, U)>, wrapper: fn(T) -> V)
    where
        T: Dummy<Unit> + TryFrom<U, Error = E> + Clone,
        V: PartialEq + std::fmt::Debug,
        U: From<T>,
        E: std::fmt::Debug,
    {
        let original: T = Unit.fake_with_rng(&mut OsRng);
        let proto_original = U::from(original.clone());

        let original_from_proto = T::try_from(proto_original).unwrap();
        assert_eq!(wrapper(original), wrapper(original_from_proto));
    }

    #[test]
    fn convert_protobuf_point() {
        let number = [
            143, 155, 8, 85, 229, 228, 1, 179, 39, 101, 245, 99, 113, 81, 250, 4, 15, 22, 126, 74,
            137, 110, 198, 25, 250, 142, 202, 51, 0, 241, 238, 168,
        ];
        let scalar = p256k1::scalar::Scalar::from(number);

        let original = Point::from(scalar);
        let proto_original = proto::Point::from(original.clone());
        let original_from_proto = Point::try_from(proto_original).unwrap();

        assert_eq!(original, original_from_proto);
    }
}
