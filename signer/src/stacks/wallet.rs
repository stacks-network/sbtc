//! This module contains functionality for signing stacks transactions
//! using the signers' multi-sig wallet.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::LazyLock;

use blockstack_lib::address::C32_ADDRESS_VERSION_MAINNET_MULTISIG;
use blockstack_lib::address::C32_ADDRESS_VERSION_TESTNET_MULTISIG;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigHashMode;
use blockstack_lib::chainstate::stacks::OrderIndependentMultisigSpendingCondition;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPublicKeyEncoding;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::core::CHAIN_ID_MAINNET;
use blockstack_lib::core::CHAIN_ID_TESTNET;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::util::secp256k1::Secp256k1PublicKey;
use rand::SeedableRng as _;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Message;

use crate::config::NetworkKind;
use crate::config::SignerConfig;
use crate::context::Context;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::signature::RecoverableEcdsaSignature as _;
use crate::signature::SighashDigest as _;
use crate::stacks::contracts::AsTxPayload;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::DbRead;
use crate::MAX_KEYS;

/// Stacks multisig addresses are Hash160 hashes of bitcoin Scripts (more
/// or less). The enum value below defines which Script will be used to
/// construct the address, and so implicitly describes how the multisig
/// Stacks address is created. The specific hash mode chosen here needs to
/// match the hash mode used in our smart contracts. This is defined in the
/// `sbtc-bootstrap-signers.clar` contract in the `pubkeys-to-spend-script`
/// read-only function. This mode matches the code there.
const MULTISIG_ADDRESS_HASH_MODE: OrderIndependentMultisigHashMode =
    OrderIndependentMultisigHashMode::P2SH;

/// A set of dummy private keys which are used for creating "dummy" transactions
/// for Stacks transaction size estimation.
static DUMMY_PRIVATE_KEYS: LazyLock<[PrivateKey; 128]> = LazyLock::new(|| {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    std::array::from_fn(|_| PrivateKey::new(&mut rng))
});

/// Requisite info for the signers' multi-sig wallet on Stacks.
#[derive(Debug)]
pub struct SignerWallet {
    /// The current set of public keys for all known signers during this
    /// PoX cycle.
    public_keys: BTreeSet<PublicKey>,
    /// The aggregate key created by combining the above public keys.
    aggregate_key: PublicKey,
    /// The number of signers necessary for successfully signing a
    /// multi-sig transaction.
    signatures_required: u16,
    /// The kind of network we are operating under.
    network_kind: NetworkKind,
    /// The multi-sig address associated with the public keys.
    address: StacksAddress,
    /// The next nonce for the StacksAddress associated with the address of
    /// the wallet.
    nonce: AtomicU64,
}

impl SignerWallet {
    /// Create the wallet for the signer.
    ///
    /// # Errors
    ///
    /// An error is returned here if:
    /// 1. There are no public keys in the provided slice.
    /// 2. The number of required signatures is zero.
    /// 3. The number of required signatures exceeds the number of public
    ///    keys.
    /// 4. The number of public keys exceeds the MAX_KEYS constant.
    /// 5. The combined public key would be the point at infinity.
    ///
    /// Error condition (5) occurs when [`PublicKey::combine_keys`] errors.
    /// There are two other conditions where that function errors, which
    /// are:
    ///
    /// * The provided slice of public keys is empty.
    /// * The number of elements in the provided slice is greater than
    ///   [`i32::MAX`].
    ///
    /// But we enforce that the number of public keys is less than
    /// [`MAX_KEYS`] and [`MAX_KEYS`] <= [`u16::MAX`] < [`i32::MAX`] and we
    /// explicitly check for an empty slice already so these cases are
    /// covered.
    ///
    /// # Notes
    ///
    /// Now there is always a small risk that [`PublicKey::combine_keys`]
    /// will return a `Result::Err`, even with perfectly fine inputs. This
    /// is highly unlikely by chance, but a Byzantine actor could trigger
    /// it purposefully if we don't require a signer to prove that they
    /// control the public key that they submit.
    pub fn new<'a, I>(
        public_keys: I,
        signatures_required: u16,
        network_kind: NetworkKind,
        nonce: u64,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        let public_keys: BTreeSet<PublicKey> = public_keys.into_iter().copied().collect();

        // Check most error conditions
        let num_keys = public_keys.len();
        let invalid_threshold = num_keys < signatures_required as usize;
        let invalid_num_keys = num_keys == 0 || num_keys > MAX_KEYS as usize;

        if invalid_threshold || invalid_num_keys || signatures_required == 0 {
            return Err(Error::InvalidWalletDefinition(
                signatures_required,
                num_keys,
            ));
        }

        // Used for creating the combined stacks address
        let pubkeys: Vec<Secp256k1PublicKey> =
            public_keys.iter().map(Secp256k1PublicKey::from).collect();

        let num_sigs = signatures_required as usize;
        let hash_mode = Self::hash_mode().to_address_hash_mode();
        let version = match network_kind {
            NetworkKind::Mainnet => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            _ => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        };

        // The [`StacksAddress::from_public_keys`] call below should never
        // fail. For the [`AddressHashMode::SerializeP2SH`] hash mode --
        // which we use since it corresponds to the
        // [`OrderIndependentMultisigHashMode::P2SH`] hash mode -- the
        // [`StacksAddress::from_public_keys`] function will return None if
        // the threshold is greater than the number of public keys. We
        // enforce the threshold invariant above in this function.
        Ok(Self {
            aggregate_key: PublicKey::combine_keys(public_keys.iter())?,
            public_keys,
            signatures_required,
            network_kind,
            address: StacksAddress::from_public_keys(version, &hash_mode, num_sigs, &pubkeys)
                .ok_or(Error::StacksMultiSig(signatures_required, num_keys))?,
            nonce: AtomicU64::new(nonce),
        })
    }

    /// Load the multi-sig wallet from the last rotate-keys transaction
    /// stored in the database. If it's not there, fall back to the
    /// bootstrap multi-sig wallet in the signer's config.
    ///
    /// The wallet that is loaded is the one that cooresponds to the signer
    /// set defined in the last confirmed key rotation contract call.
    pub async fn load<C>(ctx: &C, chain_tip: &BitcoinBlockHash) -> Result<SignerWallet, Error>
    where
        C: Context,
    {
        // Get the key rotation transaction from the database. This maps to
        // what the stacks network thinks the signers' address is.
        let last_key_rotation = ctx.get_storage().get_last_key_rotation(chain_tip).await?;

        let config = &ctx.config().signer;
        let network_kind = config.network;

        match last_key_rotation {
            Some(keys) => {
                let public_keys = keys.signer_set;
                let signatures_required = keys.signatures_required;
                SignerWallet::new(&public_keys, signatures_required, network_kind, 0)
            }
            None => Self::load_boostrap_wallet(config),
        }
    }

    /// Load the bootstrap wallet implicitly defined in the signer config.
    pub fn load_boostrap_wallet(config: &SignerConfig) -> Result<SignerWallet, Error> {
        let network_kind = config.network;
        let public_keys = config.bootstrap_signing_set();
        let signatures_required = config.bootstrap_signatures_required;

        SignerWallet::new(&public_keys, signatures_required, network_kind, 0)
    }

    fn hash_mode() -> OrderIndependentMultisigHashMode {
        MULTISIG_ADDRESS_HASH_MODE
    }

    /// Return the stacks address for the signers
    pub fn address(&self) -> &StacksAddress {
        &self.address
    }

    /// The aggregate public key of the given public keys.
    ///
    /// # Notes
    ///
    /// This aggregate is almost certainly different from the aggregate key
    /// that is output after DKG.
    ///
    /// Once <https://github.com/stacks-network/sbtc/issues/614> gets done
    /// then we will always have a unification of the Stacks and bitcoin
    /// aggregate keys.
    pub fn stacks_aggregate_key(&self) -> &PublicKey {
        &self.aggregate_key
    }

    /// Returns the number of public keys in the multi-sig wallet.
    pub fn num_signers(&self) -> u16 {
        // We check that the number of keys is less than or equal to the
        // MAX_KEYS variable when we created this struct, and MAX_KEYS is a
        // u16. So this cast should always succeed.
        self.public_keys
            .len()
            .try_into()
            .expect("BUG! the number of keys is supposed to be less than u16::MAX")
    }

    /// Return the public keys for the signers' multi-sig wallet
    pub fn public_keys(&self) -> &BTreeSet<PublicKey> {
        &self.public_keys
    }

    /// Return the nonce that should be used with the next transaction
    pub fn get_nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Set the next nonce to the provided value
    pub fn set_nonce(&self, value: u64) {
        self.nonce.store(value, Ordering::Relaxed)
    }

    /// The number of participants required to construct a valid signature
    /// for Stacks transactions.
    pub fn signatures_required(&self) -> u16 {
        self.signatures_required
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
        OrderIndependentMultisigSpendingCondition {
            signer: self.address.bytes,
            nonce: self.nonce.fetch_add(1, Ordering::Relaxed),
            tx_fee,
            hash_mode: SignerWallet::hash_mode(),
            fields: Vec::new(),
            signatures_required: self.signatures_required,
        }
    }
}

/// A helper struct for properly signing a transaction for the signers'
/// multi-sig wallet.
///
/// Only [`TransactionSpendingCondition::OrderIndependentMultisig`] auth
/// spending conditions are currently supported, and this invariant is
/// enforced when the struct is created.
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
    /// Create a new Stacks transaction for a given payload that can be
    /// signed by the signers' multi-sig wallet.
    pub fn new_tx<T>(payload: &T, wallet: &SignerWallet, tx_fee: u64) -> Self
    where
        T: AsTxPayload,
    {
        // The chain id is used so transactions can't be replayed on other
        // chains. The "common" chain id values are mentioned in
        // stacks-core, in stacks.js at
        // https://github.com/hirosystems/stacks.js/blob/2c57ea4e5abed76da903f5138c79c1d2eceb008b/packages/transactions/src/constants.ts#L1-L8,
        // and in the clarity docs at
        // https://docs.stacks.co/clarity/keywords#chain-id-clarity2:
        let (version, chain_id) = match wallet.network_kind {
            NetworkKind::Mainnet => (TransactionVersion::Mainnet, CHAIN_ID_MAINNET),
            _ => (TransactionVersion::Testnet, CHAIN_ID_TESTNET),
        };

        let conditions = payload.post_conditions();
        let auth = wallet.as_unsigned_tx_auth(tx_fee);
        let spending_condition = TransactionSpendingCondition::OrderIndependentMultisig(auth);

        let tx = StacksTransaction {
            version,
            chain_id,
            auth: TransactionAuth::Standard(spending_condition),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: conditions.post_condition_mode,
            post_conditions: conditions.post_conditions,
            payload: payload.tx_payload(),
        };

        let digest = Message::from_digest(tx.digest());
        let signatures = wallet.public_keys.iter().map(|&key| (key, None)).collect();

        Self { digest, signatures, tx }
    }

    /// Return a reference to the underlying transaction
    pub fn tx(&self) -> &StacksTransaction {
        &self.tx
    }

    /// Return the total number of signatures that have been received so
    /// far for this transaction.
    pub fn num_signatures(&self) -> u16 {
        self.signatures
            .values()
            .map(|maybe_sig| maybe_sig.is_some() as u16)
            .sum()
    }

    /// Add the given signature to the signature list
    ///
    /// # Notes
    ///
    /// There are two [`Err`] paths that can happen here:
    /// 1. We cannot recover the public key from the signature. Perhaps the
    ///    signature was given over the wrong digest.
    /// 2. The signature was given over the correct digest, but we were not
    ///    expecting the associated public key.
    pub fn add_signature(&mut self, signature: RecoverableSignature) -> Result<(), Error> {
        let public_key: PublicKey = signature.recover_ecdsa(&self.digest)?;

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
            _ => unreachable!("spending condition invariant not upheld"),
        };
        let key_encoding = TransactionPublicKeyEncoding::Compressed;

        self.signatures
            .into_iter()
            .for_each(|(public_key, maybe_sig)| match maybe_sig {
                Some(sig) => cond.push_signature(key_encoding, sig.as_stacks_sig()),
                None => cond.push_public_key(Secp256k1PublicKey::from(&public_key)),
            });

        self.tx
    }
}

/// Get the number of bytes for a fully signed stacks transaction with the
/// given payload.
///
/// This function is very unlikely to fail in practice.
pub fn get_full_tx_size<T>(payload: &T, wallet: &SignerWallet) -> Result<u64, Error>
where
    T: AsTxPayload,
{
    use stacks_common::codec::StacksMessageCodec as _;
    let num_signers = wallet.public_keys().len();

    // We only need the first `num_signers` keys.
    let private_keys = DUMMY_PRIVATE_KEYS
        .iter()
        .take(num_signers)
        .copied()
        .collect::<Vec<_>>();

    let public_keys: Vec<_> = private_keys
        .iter()
        .map(PublicKey::from_private_key)
        .collect();

    // This will only fail if we get very unlucky with private keys that we
    // generate. We create a new wallet so that we don't alter the state of the
    // wallet that was passed in, which will increment nonces for new
    // transactions.
    let wallet = SignerWallet::new(
        &public_keys,
        wallet.signatures_required,
        wallet.network_kind,
        0,
    )?;

    let mut multisig_tx = MultisigTx::new_tx(payload, &wallet, 0);
    for private_key in private_keys
        .iter()
        .take(wallet.signatures_required as usize)
    {
        let signature = crate::signature::sign_stacks_tx(multisig_tx.tx(), private_key);
        // This won't fail, since this is a proper signature
        multisig_tx.add_signature(signature)?;
    }

    Ok(multisig_tx.finalize_transaction().serialize_to_vec().len() as u64)
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::TransactionPayload;
    use blockstack_lib::clarity::vm::Value as ClarityValue;
    use fake::Fake;
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;
    use rand::SeedableRng as _;
    use secp256k1::Keypair;
    use secp256k1::SECP256K1;

    use clarity::codec::StacksMessageCodec as _;
    use test_case::test_case;

    use crate::context::Context;
    use crate::signature::sign_stacks_tx;
    use crate::stacks::contracts::AsContractCall;
    use crate::stacks::contracts::ReqContext;
    use crate::storage::model;
    use crate::storage::model::RotateKeysTransaction;
    use crate::storage::model::StacksPrincipal;
    use crate::storage::DbWrite;
    use crate::testing::context::ConfigureMockedClients;
    use crate::testing::context::TestContext;
    use crate::testing::context::*;
    use crate::testing::storage::model::TestData;

    use super::*;

    // This is the transaction fee. It doesn't matter what value we choose.
    const TX_FEE: u64 = 25;

    impl MultisigTx {
        /// Create a new Stacks transaction for a contract call that can be
        /// signed by the signers' multi-sig wallet.
        pub fn new_contract_call<T>(contract: T, wallet: &SignerWallet, tx_fee: u64) -> Self
        where
            T: AsContractCall,
        {
            use crate::testing::wallet::ContractCallWrapper;
            Self::new_tx(&ContractCallWrapper(contract), wallet, tx_fee)
        }
    }

    struct TestContractCall;

    impl AsContractCall for TestContractCall {
        const CONTRACT_NAME: &'static str = "all-the-sbtc";
        const FUNCTION_NAME: &'static str = "mint-it-all";
        fn deployer_address(&self) -> StacksAddress {
            StacksAddress::burn_address(false)
        }
        fn as_contract_args(&self) -> Vec<ClarityValue> {
            Vec::new()
        }
        async fn validate<C>(&self, _db: &C, _ctx: &ReqContext) -> Result<(), Error>
        where
            C: Context + Send + Sync,
        {
            Ok(())
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

        let public_keys: Vec<_> = key_pairs.iter().map(|kp| kp.public_key().into()).collect();
        let wallet = SignerWallet::new(&public_keys, signatures_required, network, 1).unwrap();

        let mut tx_signer = MultisigTx::new_contract_call(TestContractCall, &wallet, TX_FEE);
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
            .map(|kp| sign_stacks_tx(tx, &kp.secret_key().into()))
            .collect();

        // Now add the signatures to the signing object.
        let mut count = 0;
        assert_eq!(count, tx_signer.num_signatures());
        for signature in signatures {
            tx_signer.add_signature(signature).unwrap();
            count += 1;
            assert_eq!(count, tx_signer.num_signatures());
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

        let public_keys: Vec<_> = key_pairs.iter().map(|kp| kp.public_key().into()).collect();
        let wallet = SignerWallet::new(&public_keys, signatures_required, network, 1).unwrap();

        let mut tx_signer = MultisigTx::new_contract_call(TestContractCall, &wallet, TX_FEE);

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
        let signature = SECP256K1.sign_ecdsa_recoverable(&msg, &secret_key).into();

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
        let signature = SECP256K1.sign_ecdsa_recoverable(&msg, &secret_key).into();
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
            std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
                .map(|kp| kp.public_key().into())
                .take(50)
                .collect();

        let pks1 = public_keys.clone();
        let wallet1 = SignerWallet::new(&pks1, 5, network, 0).unwrap();

        // Although it's unlikely, it's possible for the shuffle to not
        // shuffle anything, so we need to keep trying.
        while pks1 == public_keys {
            public_keys.shuffle(&mut OsRng);
        }

        let wallet2 = SignerWallet::new(&public_keys, 5, network, 0).unwrap();

        assert_eq!(wallet1.address(), wallet2.address())
    }

    /// Here we test that we can load a SignerWallet from storage. To do
    /// that we:
    /// 1. Generate and store random bitcoin and stacks blockchains.
    /// 2. Create a random wallet.
    /// 3. Generate a rotate-keys transaction object using the details of
    ///    the random wallet from (2).
    /// 4. Attempt to load the wallet from storage. This should return
    ///    essentially the same wallet from (2). The only difference is
    ///    that the nonce in the loaded wallet is fetched from the
    ///    "stacks-node" (in this test it just returns a nonce of zero).
    #[tokio::test]
    async fn loading_signer_wallet_from_context() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(51);

        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();
        let db = ctx.get_storage_mut();

        // Create a blockchain. We do not generate any withdrawal or
        // deposit requests, so we do not need to specify the signer set.
        let test_params = crate::testing::storage::model::Params {
            num_bitcoin_blocks: 10,
            num_stacks_blocks_per_bitcoin_block: 0,
            num_deposit_requests_per_block: 0,
            num_withdraw_requests_per_block: 0,
            num_signers_per_request: 0,
            consecutive_blocks: false,
        };
        let test_data = TestData::generate(&mut rng, &[], &test_params);
        test_data.write_to(&db).await;

        // Let's generate a the signers' wallet.
        let signer_keys: Vec<PublicKey> =
            std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
                .map(|kp| kp.public_key().into())
                .take(50)
                .collect();
        let signatures_required = 5;
        let network = NetworkKind::Regtest;
        let wallet1 = SignerWallet::new(&signer_keys, signatures_required, network, 0).unwrap();

        // Let's store the key information about this wallet into the database
        let rotate_keys = RotateKeysTransaction {
            txid: fake::Faker.fake_with_rng(&mut rng),
            address: StacksPrincipal::from(clarity::vm::types::PrincipalData::from(
                wallet1.address().clone(),
            )),
            aggregate_key: *wallet1.stacks_aggregate_key(),
            signer_set: signer_keys.clone(),
            signatures_required: wallet1.signatures_required,
        };

        let bitcoin_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
        let stacks_chain_tip = db
            .get_stacks_chain_tip(&bitcoin_chain_tip)
            .await
            .unwrap()
            .unwrap();

        // We haven't stored any RotateKeysTransactions into the database
        // yet, so it will try to load the wallet from the context.
        let wallet0 = SignerWallet::load(&ctx, &bitcoin_chain_tip).await.unwrap();
        let config = &ctx.config().signer;
        let bootstrap_aggregate_key =
            PublicKey::combine_keys(&config.bootstrap_signing_set()).unwrap();
        assert_eq!(wallet0.aggregate_key, bootstrap_aggregate_key);

        let tx = model::StacksTransaction {
            txid: rotate_keys.txid,
            block_hash: stacks_chain_tip.block_hash,
        };

        db.write_stacks_transaction(&tx).await.unwrap();
        db.write_rotate_keys_transaction(&rotate_keys)
            .await
            .unwrap();

        // Okay, now let's load it up and make sure things match.
        let wallet2 = SignerWallet::load(&ctx, &bitcoin_chain_tip).await.unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(wallet1.public_keys(), wallet2.public_keys());
        assert_eq!(
            wallet1.stacks_aggregate_key(),
            wallet2.stacks_aggregate_key()
        );
    }

    #[test]
    fn loading_signer_wallet_from_config() {
        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        // Let's try to load the wallet from our test config.
        SignerWallet::load_boostrap_wallet(&ctx.config().signer).unwrap();
    }

    #[test_case(1, 1)]
    #[test_case(2, 3)]
    #[test_case(11, 15)]
    fn can_get_full_tx_size(signatures_required: u16, num_keys: u16) {
        const BASE_TX_SIZE: u64 = 55;
        const SIGNATURE_SIZE: u64 = 66;
        const PUBKEY_SIZE: u64 = 34;

        let network_kind = NetworkKind::Regtest;

        let public_keys = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
            .map(|kp| kp.public_key().into())
            .take(num_keys as usize)
            .collect::<Vec<_>>();

        let wallet = SignerWallet::new(&public_keys, signatures_required, network_kind, 0).unwrap();

        let payload = TransactionPayload::ContractCall(TestContractCall.as_contract_call());

        let payload_size = payload.tx_payload().serialize_to_vec().len() as u64;

        let expected_size = BASE_TX_SIZE
            + payload_size
            + (signatures_required as u64 * SIGNATURE_SIZE)
            + ((num_keys - signatures_required) as u64 * PUBKEY_SIZE);

        let size = get_full_tx_size(&payload, &wallet).unwrap();

        assert_eq!(size, expected_size);
    }
}
