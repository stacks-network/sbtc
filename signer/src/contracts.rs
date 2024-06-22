//! This module contains functionality for creating stacks transactions.
//!
//! # Note
//!
//! This assumes that all relevant contracts were deployed by the same address.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use blockstack_lib::address::C32_ADDRESS_VERSION_MAINNET_MULTISIG;
use blockstack_lib::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use blockstack_lib::chainstate::stacks::AssetInfo;
use blockstack_lib::chainstate::stacks::FungibleConditionCode;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigHashMode;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigSpendingCondition;
use blockstack_lib::chainstate::stacks::PostConditionPrincipal;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionAuthFlags;
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostCondition;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionPublicKeyEncoding;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::clarity::vm::types::BuffData;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::SequenceData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::clarity::vm::ClarityName;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::clarity::vm::Value;
use blockstack_lib::core::CHAIN_ID_MAINNET;
use blockstack_lib::core::CHAIN_ID_TESTNET;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::util::secp256k1::MessageSignature;
use blockstack_lib::util::secp256k1::Secp256k1PublicKey;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Message;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use secp256k1::SECP256K1;

use crate::config::NetworkKind;
use crate::error::Error;

/// Requisite info for the signers' multi-sig wallet on Stacks.
#[derive(Debug, Clone)]
pub struct SignerWallet {
    /// The current set of public keys for all known signers during this
    /// PoX cycle. These values must be sorted.
    public_keys: Vec<PublicKey>,
    /// The number of signers necessary for successfully signing a
    /// multi-sig transaction.
    signatures_required: u16,
    /// The kind of network we are operating under.
    network_kind: NetworkKind,
}

impl SignerWallet {
    /// Create the wallet for the signer.
    ///
    /// # Note
    ///
    /// An error is returned if the
    /// number of required signatures is greater than the list of public
    /// keys or if the list of public keys is empty.
    pub fn new(
        mut public_keys: Vec<PublicKey>,
        signatures_required: u16,
        network_kind: NetworkKind,
    ) -> Result<Self, Error> {
        public_keys.sort();

        if public_keys.len() < signatures_required as usize || public_keys.is_empty() {
            return Err(Error::MissingBlock);
        }

        if signatures_required == 0 || public_keys.is_empty() {
            return Err(Error::MissingBlock);
        }

        Ok(Self {
            public_keys,
            signatures_required,
            network_kind,
        })
    }

    fn hash_mode() -> OrderIndependentMultisigHashMode {
        OrderIndependentMultisigHashMode::P2WSH
    }

    /// Return the stacks address for the signers
    pub fn address(&self) -> StacksAddress {
        let public_keys: Vec<Secp256k1PublicKey> = self
            .public_keys
            .iter()
            .map(|pk| Secp256k1PublicKey::from_slice(&pk.serialize()))
            .collect::<Result<_, _>>()
            .expect("we know these are all valid public keys");

        let threshold = self.signatures_required as usize;
        let hash_mode = Self::hash_mode().to_address_hash_mode();
        let version = match self.network_kind {
            NetworkKind::Mainnet => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            NetworkKind::Testnet => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        };
        // For a hash mode of AddressHashMode::SerializeP2SH, which
        // corresponds to OrderIndependentMultisigHashMode::P2WSH, the
        // StacksAddress::from_public_keys function will return None if the
        // threshold is greater than the number of public keys. We enforce
        // that invariant when creating the struct. If we used a different
        // hash mode then we would also have to ensure that all public keys
        // are compressed, which is the case since our public keys are 33
        // bytes.
        StacksAddress::from_public_keys(version, &hash_mode, threshold, &public_keys)
            .expect("signatures required invariant not upheld")
    }
}

/// Contains the current state of the signers keys.
#[derive(Debug)]
pub struct SignerStxState {
    /// The current set of public keys for all known signers during this
    /// PoX cycle. These values must be sorted.
    wallet: SignerWallet,
    /// The next nonce for the StacksAddress associated with the above public
    /// keys.
    nonce: AtomicU64,
    /// This is the stacks address that deployed the sbtc-contracts.
    contract_deployer: StacksAddress,
}

impl SignerStxState {
    /// Create a new SignerStxState
    pub fn new(wallet: SignerWallet, nonce: u64, deployer: StacksAddress) -> Self {
        Self {
            wallet,
            nonce: AtomicU64::new(nonce),
            contract_deployer: deployer,
        }
    }

    /// Convert the signers wallet to an unsigned stacks spending conditions.
    ///
    /// # Note
    ///
    /// * The auth will have a transaction fee and a nonce set.
    /// * This auth does not contain any signatures.
    pub fn as_unsigned_tx_auth(&self, tx_fee: u64) -> TransactionAuth {
        let signer_addr = self.wallet.address();
        let cond = OrderIndependentMultisigSpendingCondition {
            signer: signer_addr.bytes,
            nonce: self.nonce.fetch_add(1, Ordering::Relaxed),
            tx_fee,
            hash_mode: SignerWallet::hash_mode(),
            fields: Vec::new(),
            signatures_required: self.wallet.signatures_required,
        };
        TransactionAuth::Standard(TransactionSpendingCondition::OrderIndependentMultisig(cond))
    }
}

/// A struct describing any transaction post-execution conditions that we'd
/// like to enforce.
///
/// # Note
///
/// * It's unlikely that this will be necessary since the signers control
///   the contract to begin with, we implicitly trust it.
/// * We cannot enforce any conditions on the destination of any sBTC, just
///   the source and the amount.
/// * SIP-005 describes the post conditions, including its limitations, and
///   can be found here
///   https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md#transaction-post-conditions
#[derive(Debug)]
pub struct StacksTxPostConditions {
    /// Specifies whether other asset transfers not covered by the
    /// post-conditions are permitted.
    pub post_condition_mode: TransactionPostConditionMode,
    /// Any post-execution conditions that we'd like to enforce.
    pub post_conditions: Vec<TransactionPostCondition>,
}

/// A trait to ease construction of a StacksTransaction making sBTC related contract calls.
pub trait AsContractCall {
    /// Converts this struct to a Stacks contract call. The deployer is the
    /// stacks address that deployed the contract.
    fn as_contract_call(&self, deployer: StacksAddress) -> TransactionContractCall;
    /// Any post-execution conditions that we'd like to enforce. The
    /// deployer corresponds to the principal in the Transaction
    /// post-conditions, which is the address that sent the asset.
    fn post_conditions(&self, deployer: StacksAddress) -> StacksTxPostConditions;
    /// Make a Stacks transaction for the contract call
    fn as_unsigned_tx(&self, state: &SignerStxState, tx_fee: u64) -> MultisigTransactionSigner {
        // The chain id is used so transactions can't be replayed on other
        // chains. The "common" chain id values are mentioned in
        // stacks-core, in stacks.js at
        // https://github.com/hirosystems/stacks.js/blob/2c57ea4e5abed76da903f5138c79c1d2eceb008b/packages/transactions/src/constants.ts#L1-L8,
        // and in the clarity docs at
        // https://docs.stacks.co/clarity/keywords#chain-id-clarity2:
        let (version, chain_id) = match state.wallet.network_kind {
            NetworkKind::Mainnet => (TransactionVersion::Mainnet, CHAIN_ID_MAINNET),
            NetworkKind::Testnet => (TransactionVersion::Testnet, CHAIN_ID_TESTNET),
        };

        let deployer = state.contract_deployer;
        let cond = self.post_conditions(deployer);

        let tx = StacksTransaction {
            version,
            chain_id,
            auth: state.as_unsigned_tx_auth(tx_fee),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: cond.post_condition_mode,
            post_conditions: cond.post_conditions,
            payload: TransactionPayload::ContractCall(self.as_contract_call(deployer)),
        };
        MultisigTransactionSigner::new(tx, &state.wallet.public_keys)
    }
}

/// A transactionSigner
pub struct MultisigTransactionSigner {
    /// The unsigned transaction
    tx: StacksTransaction,
    /// The message digest that the signers must sign to create a valid
    /// trasnaction.
    digest: Message,
    /// The accumulated transactions
    signatures: BTreeMap<PublicKey, Option<RecoverableSignature>>,
}

impl MultisigTransactionSigner {
    /// Create a new one
    pub fn new(tx: StacksTransaction, public_keys: &[PublicKey]) -> Self {
        Self {
            digest: construct_digest(&tx),
            signatures: public_keys.iter().map(|key| (key.clone(), None)).collect(),
            tx,
        }
    }

    /// Return a reference to the underlying transaction
    pub fn tx(&self) -> &StacksTransaction {
        &self.tx
    }

    /// Add the given signature to the signature list
    ///
    /// # Notes
    ///
    /// An error is returned if we could not recover the public key from
    /// the signature, which can happen if the wrong digest. An error also
    /// happens if the signature is for the correct digest but for a public
    /// key that we werem't expecting.
    pub fn add_signature(&mut self, signature: RecoverableSignature) -> Result<(), Error> {
        let public_key = signature
            .recover(&self.digest)
            .map_err(|err| Error::InvalidRecoverableSignature(err, self.digest))?;

        // Get the entry for the given public key and replace the value
        // with the given signature. If the public key doesn't exist here,
        // then someone sent a signature with an unexpected public key.
        self.signatures
            .get_mut(&public_key)
            .map(|sig| {
                sig.replace(signature);
            })
            .ok_or_else(|| Error::UnknownPublicKey(public_key, self.digest))
    }

    /// Creates a signed transaction with the available signatures
    pub fn finalize_transaction(mut self) -> StacksTransaction {
        use TransactionSpendingCondition::OrderIndependentMultisig;
        let cond = match &mut self.tx.auth {
            TransactionAuth::Standard(OrderIndependentMultisig(cond)) => cond,
            _ => panic!(),
        };
        let key_encoding = TransactionPublicKeyEncoding::Compressed;

        self.signatures
            .into_iter()
            .for_each(|(public_key, maybe_sig)| match maybe_sig {
                Some(sig) => {
                    let signature = from_secp256k1_recoverable(&sig);
                    cond.push_signature(key_encoding, signature);
                }
                None => {
                    let compressed_data = public_key.serialize();
                    let public_key = Secp256k1PublicKey::from_slice(&compressed_data)
                        .expect("we know this is a valid public key");

                    debug_assert!(public_key.compressed());
                    cond.push_public_key(public_key);
                }
            });

        self.tx
    }
}

/// Construct a digest to sign from a given transaction
pub fn construct_digest(tx: &StacksTransaction) -> Message {
    let mut cleared_tx = tx.clone();
    cleared_tx.auth = cleared_tx.auth.into_initial_sighash_auth();

    let sighash = cleared_tx.txid();
    let flags = TransactionAuthFlags::AuthStandard;
    let tx_fee = tx.get_tx_fee();
    let nonce = tx.get_origin_nonce();

    let digest =
        TransactionSpendingCondition::make_sighash_presign(&sighash, &flags, tx_fee, nonce);
    Message::from_digest(digest.into_bytes())
}

/// Generate a signature for the transaction using a private key.
///
/// # Note
///
/// This function constructs a signature for the underlying transaction
/// using the same process that is done in the
/// TransactionSpendingCondition::next_signature function, but we skip a
/// step of generating the next sighash, since we do not need it.
pub fn sign_ecdsa(tx: &StacksTransaction, secret_key: &SecretKey) -> RecoverableSignature {
    let msg = construct_digest(&tx);
    SECP256K1.sign_ecdsa_recoverable(&msg, &secret_key)
}

/// Convert a recoverable signature into a Message Signature.
///
/// The RecoverableSignature type is a wrapper of a wrapper for [u8; 65].
/// Unfortunately, the last wrapper type does not provide a way to get at
/// the underlying bytes except through the
/// RecoverableSignature::serialize_compact function, so we need to just
/// extract them with
///
/// This function is basically lifted from stacks-core at:
/// https://github.com/stacks-network/stacks-core/blob/35d0840c626d258f1e2d72becdcf207a0572ddcd/stacks-common/src/util/secp256k1.rs#L88-L95
fn from_secp256k1_recoverable(sig: &RecoverableSignature) -> MessageSignature {
    let (recovery_id, bytes) = sig.serialize_compact();
    let mut ret_bytes = [0u8; 65];
    // The recovery ID will be 0, 1, 2, or 3
    ret_bytes[0] = recovery_id.to_i32() as u8;
    debug_assert!(recovery_id.to_i32() < 4);

    ret_bytes[1..].copy_from_slice(&bytes[..]);
    MessageSignature(ret_bytes)
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for the complete-deposit-wrapper contract call.
#[derive(Copy, Clone, Debug)]
pub struct CompleteDeposit {
    /// The outpoint of the bitcoin UTXO that was spent as a deposit for
    /// sBTC.
    pub outpoint: OutPoint,
    /// The amount associated with the above UTXO.
    pub amount: u64,
    /// The address where the newly minted sBTC will be deposited.
    pub recipient: StacksAddress,
}

impl CompleteDeposit {
    /// TODO: Make the contract and function names configurable.
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
    const FUNCTION_NAME: &'static str = "complete-deposit-wrapper";

    fn as_contract_args(&self) -> Vec<Value> {
        let txid_data = self.outpoint.txid.to_byte_array().to_vec();
        let txid = BuffData { data: txid_data };
        let principle = StandardPrincipalData::from(self.recipient);

        vec![
            Value::Sequence(SequenceData::Buffer(txid)),
            Value::UInt(self.outpoint.vout as u128),
            Value::UInt(self.amount as u128),
            Value::Principal(PrincipalData::Standard(principle)),
        ]
    }

    /// Converts this struct to a Stacks Contract call
    pub fn as_contract_call(&self, deployer: StacksAddress) -> TransactionContractCall {
        TransactionContractCall {
            address: deployer,
            function_name: ClarityName::from(CompleteDeposit::FUNCTION_NAME),
            contract_name: ContractName::from(CompleteDeposit::CONTRACT_NAME),
            function_args: self.as_contract_args(),
        }
    }

    /// The post conditions for the transaction
    pub fn post_conditions(&self, deployer: StacksAddress) -> StacksTxPostConditions {
        let asset_info = AssetInfo {
            contract_address: deployer,
            contract_name: ContractName::from("sbtc-token"),
            asset_name: ClarityName::from("sBTC"),
        };
        let post_condition = TransactionPostCondition::Fungible(
            PostConditionPrincipal::Contract(deployer, ContractName::from("sbtc-token")),
            asset_info,
            FungibleConditionCode::SentEq,
            self.amount,
        );
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![post_condition],
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::Keypair;
    use secp256k1::Secp256k1;

    use super::*;

    impl Default for StacksTxPostConditions {
        fn default() -> Self {
            Self {
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: Vec::new(),
            }
        }
    }

    struct TestContractCall;

    impl AsContractCall for TestContractCall {
        fn as_contract_call(&self, deployer: StacksAddress) -> TransactionContractCall {
            TransactionContractCall {
                address: deployer,
                contract_name: ContractName::from("all-the-sbtc"),
                function_name: ClarityName::from("mint-it-all"),
                function_args: Vec::new(),
            }
        }
        fn post_conditions(&self, _: StacksAddress) -> StacksTxPostConditions {
            StacksTxPostConditions::default()
        }
    }

    #[test]
    fn one_of_2_multi_sig_works() {
        let ctx = Secp256k1::new();
        let mut key_pairs = vec![
            Keypair::new(&ctx, &mut OsRng),
            Keypair::new(&ctx, &mut OsRng),
        ];
        key_pairs.sort_by_key(|x| x.public_key());

        let public_keys: Vec<_> = key_pairs.iter().map(|kp| kp.public_key()).collect();
        let signatures_required = 1;
        let wallet =
            SignerWallet::new(public_keys, signatures_required, NetworkKind::Testnet).unwrap();

        let state = SignerStxState::new(wallet, 1, StacksAddress::burn_address(false));

        let mut unsigned_tx = TestContractCall.as_unsigned_tx(&state, 0);
        let secret_key = key_pairs[0].secret_key();
        let signature = sign_ecdsa(unsigned_tx.tx(), &secret_key);
        unsigned_tx.add_signature(signature).unwrap();

        let tx = unsigned_tx.finalize_transaction();

        tx.verify().unwrap();
    }

    #[test]
    fn public_key_order_independence_signer_wallet() {}
}
