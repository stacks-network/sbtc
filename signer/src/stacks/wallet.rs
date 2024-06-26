//! This module contains functionality for signing stacks transactions
//! using the signers' multi-sig wallet.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use blockstack_lib::address::C32_ADDRESS_VERSION_MAINNET_MULTISIG;
use blockstack_lib::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigHashMode;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigSpendingCondition;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionAuthFlags;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPublicKeyEncoding;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
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
use crate::stacks::contracts::AsContractCall;

/// Requisite info for the signers' multi-sig wallet on Stacks.
#[derive(Debug, Clone)]
pub struct SignerWallet {
    /// The current set of public keys for all known signers during this
    /// PoX cycle. These values must be sorted.
    public_keys: BTreeSet<PublicKey>,
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
    /// An error is returned if:
    /// 1. There are no public keys.
    /// 2. There are no required signatures.
    /// 3. The number of required signatures exceeding the number of public
    ///    keys.
    pub fn new(
        public_keys: &[PublicKey],
        signatures_required: u16,
        network_kind: NetworkKind,
    ) -> Result<Self, Error> {
        let invalid_threshold = public_keys.len() < signatures_required as usize;

        if invalid_threshold || public_keys.is_empty() || signatures_required == 0 {
            return Err(Error::InvalidWalletDefinition(
                signatures_required,
                public_keys.len(),
            ));
        }

        Ok(Self {
            public_keys: public_keys.iter().copied().collect(),
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

        #[cfg(debug_assertions)]
        for key in public_keys.iter() {
            debug_assert!(key.compressed());
        }
        // For a hash mode of AddressHashMode::SerializeP2WSH, which
        // corresponds to OrderIndependentMultisigHashMode::P2WSH, the
        // StacksAddress::from_public_keys function will return None if the
        // threshold is greater than the number of public keys or if any of
        // the public keys are uncompressed. We enforce the threshold
        // invariant when creating the struct, and PublicKey::serialize
        // returns the bytes for a compressed public key.
        StacksAddress::from_public_keys(version, &hash_mode, threshold, &public_keys)
            .expect("public key invariants not upheld")
    }
}

/// Contains the current state of the signers keys.
#[derive(Debug)]
pub struct SignerStxState {
    /// The multi-sig wallet for all known signers during this PoX cycle.
    wallet: SignerWallet,
    /// The next nonce for the StacksAddress associated with the address of
    /// the wallet.
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

    /// The network that we are operating on
    pub fn network_kind(&self) -> NetworkKind {
        self.wallet.network_kind
    }

    /// Return the public keys associated with the signer's stacks
    /// multi-sig wallet.
    pub fn public_keys(&self) -> &BTreeSet<PublicKey> {
        &self.wallet.public_keys
    }

    /// The stacks address that deployed sbtc smart contracts.
    pub fn contract_deployer(&self) -> StacksAddress {
        self.contract_deployer
    }

    /// Convert the signers wallet to an unsigned stacks spending
    /// conditions.
    ///
    /// # Note
    ///
    /// * The returned spending condition auth will have a transaction fee
    ///   and a nonce set.
    /// * The returned spending condition auth does not contain any
    ///   signatures.
    pub fn as_unsigned_tx_auth(&self, tx_fee: u64) -> OrderIndependentMultisigSpendingCondition {
        let signer_addr = self.wallet.address();
        OrderIndependentMultisigSpendingCondition {
            signer: signer_addr.bytes,
            nonce: self.nonce.fetch_add(1, Ordering::Relaxed),
            tx_fee,
            hash_mode: SignerWallet::hash_mode(),
            fields: Vec::new(),
            signatures_required: self.wallet.signatures_required,
        }
    }
}

/// A helper struct for properly signing a transaction for the signers'
/// multi-sig wallet.
///
/// Only OrderIndependentMultisig auth spending conditions are currently
/// supported, and this invariant is enforced when the struct is created.
#[derive(Debug)]
pub struct MultisigTx {
    /// The unsigned transaction. Only transactions with a
    /// OrderIndependentMultisig auth spending condition are supported.
    tx: StacksTransaction,
    /// The message digest associated with the above transaction that the
    /// signers must sign for authentication.
    digest: Message,
    /// The accumulated signatures for the underlying transaction.
    signatures: BTreeMap<PublicKey, Option<RecoverableSignature>>,
}

impl MultisigTx {
    /// Create a new Stacks transaction for a contract call that can be
    /// signed by the signers' multi-sig wallet.
    pub fn new_contract_call<T>(contract: T, state: &SignerStxState, tx_fee: u64) -> Self
    where
        T: AsContractCall,
    {
        // The chain id is used so transactions can't be replayed on other
        // chains. The "common" chain id values are mentioned in
        // stacks-core, in stacks.js at
        // https://github.com/hirosystems/stacks.js/blob/2c57ea4e5abed76da903f5138c79c1d2eceb008b/packages/transactions/src/constants.ts#L1-L8,
        // and in the clarity docs at
        // https://docs.stacks.co/clarity/keywords#chain-id-clarity2:
        let (version, chain_id) = match state.network_kind() {
            NetworkKind::Mainnet => (TransactionVersion::Mainnet, CHAIN_ID_MAINNET),
            NetworkKind::Testnet => (TransactionVersion::Testnet, CHAIN_ID_TESTNET),
        };

        let deployer = state.contract_deployer();
        let conditions = contract.post_conditions(deployer);
        let auth = state.as_unsigned_tx_auth(tx_fee);
        let spending_condition = TransactionSpendingCondition::OrderIndependentMultisig(auth);

        let tx = StacksTransaction {
            version,
            chain_id,
            auth: TransactionAuth::Standard(spending_condition),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: conditions.post_condition_mode,
            post_conditions: conditions.post_conditions,
            payload: TransactionPayload::ContractCall(contract.as_contract_call(deployer)),
        };

        let digest = construct_digest(&tx);
        let signatures = state.public_keys().iter().map(|&key| (key, None)).collect();

        Self { digest, signatures, tx }
    }
    /// Return a reference to the underlying transaction
    pub fn tx(&self) -> &StacksTransaction {
        &self.tx
    }

    /// Add the given signature to the signature list
    ///
    /// # Notes
    ///
    /// There are two Result::Err paths that can happen here:
    /// 1. We cannot recover the public key from the signature. Perhaps the
    ///    signature was given over the wrong digest.
    /// 2. The signature was given over the correct digest, but we were not
    ///    expecting the associated public key.
    pub fn add_signature(&mut self, signature: RecoverableSignature) -> Result<(), Error> {
        let public_key = signature
            .recover(&self.digest)
            .map_err(|err| Error::InvalidRecoverableSignature(err, self.digest))?;

        // Get the entry for the given public key and replace the value
        // with the given signature. If the public key doesn't exist here,
        // then someone sent a signature using a secret key whose
        // associated public key was unexpected.
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
            _ => unreachable!("Spending condition invariant not upheld"),
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

/// Construct the digest that each signer needs to sign from a given
/// transaction.
///
/// # Note
///
/// This function follows the same procedure as the
/// TransactionSpendingCondition::next_signature function in stacks-core,
/// except that it stops after the digest is created.
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
    let msg = construct_digest(tx);
    SECP256K1.sign_ecdsa_recoverable(&msg, secret_key)
}

/// Convert a recoverable signature into a Message Signature.
///
/// The RecoverableSignature type is a wrapper of a wrapper for [u8; 65].
/// Unfortunately, the last wrapper type does not provide a way to get at
/// the underlying bytes except through the
/// RecoverableSignature::serialize_compact function, so we use that
/// function to just extract them.
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

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::TransactionContractCall;
    use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
    use blockstack_lib::clarity::vm::ClarityName;
    use blockstack_lib::clarity::vm::ContractName;
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;
    use secp256k1::Keypair;

    use test_case::test_case;

    use super::*;
    use crate::stacks::contracts::*;

    // This is the transaction fee. It doesn't matter what value we choose.
    const TX_FEE: u64 = 25;

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
            StacksTxPostConditions {
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    struct WalletSpec {
        signatures_required: u16,
        num_keys: usize,
    }

    /// Test that if we create a multisig wallet and sign with at least the
    /// minimum number of signatures that the transaction will pass
    /// verification.
    #[test_case::test_matrix(
        [WalletSpec {signatures_required: 1, num_keys: 1},
         WalletSpec {signatures_required: 1, num_keys: 2},
         WalletSpec {signatures_required: 1, num_keys: 3},
         WalletSpec {signatures_required: 2, num_keys: 3},
         WalletSpec {signatures_required: 3, num_keys: 3},
         WalletSpec {signatures_required: 4, num_keys: 7},
         WalletSpec {signatures_required: 70, num_keys: 100}],
        [true, false],
        [NetworkKind::Mainnet, NetworkKind::Testnet]
    )]
    fn multi_sig_works(wallet_spec: WalletSpec, max_sigs: bool, network: NetworkKind) {
        // We do the following:
        // 1. Construct the specified multi-sig wallet.
        // 2. Construct any old transaction. In this case it is a contract
        //    call.
        // 3. Provide enough signatures to the transaction. If max_sigs is
        //    true then we proved more than enough signatures, otherwise we
        //    prove the minimum number of required signatures.
        // 4. Check that transaction "verifies".
        let WalletSpec { signatures_required, num_keys } = wallet_spec;
        let key_pairs: Vec<Keypair> = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
            .take(num_keys)
            .collect();

        let public_keys: Vec<_> = key_pairs.iter().map(|kp| kp.public_key()).collect();
        let wallet = SignerWallet::new(&public_keys, signatures_required, network).unwrap();

        // The burn StacksAddress here is the deployer address of the sBTC
        // contract. It may matter for constructing the transaction -- in
        // this case it doesn't -- but it plays no role in the verification
        // of the signature.
        let state = SignerStxState::new(wallet, 1, StacksAddress::burn_address(false));

        let mut tx_signer = MultisigTx::new_contract_call(TestContractCall, &state, TX_FEE);
        let tx = tx_signer.tx();

        // We can give any number of signatures between the required
        // threshold and the number of keys. We give either the minimum or
        // the maximum number of signatures possible depending on the max_sigs flag.
        let submitted_signatures = if max_sigs {
            num_keys
        } else {
            signatures_required as usize
        };
        let signatures: Vec<RecoverableSignature> = key_pairs
            .iter()
            .take(submitted_signatures)
            .map(|kp| sign_ecdsa(tx, &kp.secret_key()))
            .collect();

        // Now add the signatures to the signing object.
        for signature in signatures {
            tx_signer.add_signature(signature).unwrap();
        }

        // Okay, now finalize the transaction. Afterward, it should be
        // able to pass verification.
        let tx = tx_signer.finalize_transaction();
        tx.verify().unwrap();
    }

    /// If one of the signers signs a digest with the wrong key, then we
    /// will reject it. We also reject the case where they sign the wrong
    /// digest with a "correct" key.
    #[test_case(false, false, NetworkKind::Mainnet; "incorrect key, incorrect digest, mainnet")]
    #[test_case(false, true, NetworkKind::Mainnet; "incorrect key, correct digest, mainnet")]
    #[test_case(true, false, NetworkKind::Mainnet; "correct key, incorrect digest, mainnet")]
    #[test_case(false, false, NetworkKind::Testnet; "incorrect key, incorrect digest, testnet")]
    #[test_case(false, true, NetworkKind::Testnet; "incorrect key, correct digest, testnet")]
    #[test_case(true, false, NetworkKind::Testnet; "correct key, incorrect digest, testnet")]
    fn cannot_accept_invalid_sig(correct_key: bool, correct_digest: bool, network: NetworkKind) {
        let signatures_required = 4;
        let num_keys = 7;
        let key_pairs: Vec<Keypair> = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
            .take(num_keys)
            .collect();

        let public_keys: Vec<_> = key_pairs.iter().map(|kp| kp.public_key()).collect();
        let wallet = SignerWallet::new(&public_keys, signatures_required, network).unwrap();

        let state = SignerStxState::new(wallet, 1, StacksAddress::burn_address(false));
        let mut tx_signer = MultisigTx::new_contract_call(TestContractCall, &state, TX_FEE);

        // The accumulated signatures start off empty
        assert!(tx_signer.signatures.values().all(Option::is_none));

        let secret_key = if correct_key {
            key_pairs[0].secret_key()
        } else {
            // This key pair is unlikely to be one of the known key pairs
            Keypair::new_global(&mut OsRng).secret_key()
        };

        let msg = if correct_digest {
            tx_signer.digest
        } else {
            // This message is unlikely to be the digest of the transaction
            Message::from_digest([1; 32])
        };
        let signature = SECP256K1.sign_ecdsa_recoverable(&msg, &secret_key);

        // Now let's try to add a bad signature. We skip the case where we
        // have a correct key and the correct digest so this should always
        // fail.
        let res = tx_signer.add_signature(signature);
        assert!(res.is_err());

        // The inner signatures should still be empty, since we should not
        // add any bad signatures
        assert!(tx_signer.signatures.values().all(Option::is_none));

        // Now for good measure, lets add a valid signature, and make sure
        // things update correctly.
        let secret_key = key_pairs[0].secret_key();
        let msg = tx_signer.digest;
        let signature = SECP256K1.sign_ecdsa_recoverable(&msg, &secret_key);
        tx_signer.add_signature(signature).unwrap();
        assert!(!tx_signer.signatures.values().all(Option::is_none));
    }

    #[test_case(NetworkKind::Mainnet; "Main net")]
    #[test_case(NetworkKind::Testnet; "Test net")]
    fn public_key_order_independence_signer_wallet(network: NetworkKind) {
        // Generally, for a stacks multi-sig wallet, the stacks address
        // changes depending on the ordering of the given list of public
        // keys. We don't want the address to depend on the ordering of
        // keys. Check that the SignerWallet returns the same address
        // regardless of the ordering of the keys given to it on
        // construction.
        let mut public_keys: Vec<PublicKey> =
            std::iter::repeat_with(|| Keypair::new_global(&mut OsRng).public_key())
                .take(50)
                .collect();

        let pks1 = public_keys.clone();
        let wallet1 = SignerWallet::new(&pks1, 5, network).unwrap();

        // Although it's unlikely, it's possible for the shuffle to not
        // shuffle anything, so we need to keep trying.
        while pks1 == public_keys {
            public_keys.shuffle(&mut OsRng);
        }

        let wallet2 = SignerWallet::new(&public_keys, 5, network).unwrap();

        assert_eq!(wallet1.address(), wallet2.address())
    }
}
