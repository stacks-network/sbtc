use bitcoin::absolute::LockTime;
use bitcoin::key::TapTweak;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::CompressedPublicKey;
use bitcoin::EcdsaSighashType;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::PublicKey;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoincore_rpc::json::ImportDescriptors;
use bitcoincore_rpc::json::ListUnspentQueryOptions;
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::json::Timestamp;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;
use secp256k1::SECP256K1;
use signer::utxo::UnsignedTransaction;
use std::sync::OnceLock;

/// These must match the username and password in bitcoin.conf
const BITCOIN_CORE_RPC_USERNAME: &str = "alice";
const BITCOIN_CORE_RPC_PASSWORD: &str = "pw";

pub const BITCOIN_CORE_FALLBACK_FEE: Amount = Amount::from_sat(1000);

/// The name of our wallet on bitcoin-core
const BITCOIN_CORE_WALLET_NAME: &str = "integration-tests-wallet";

/// The faucet has a fixed secret key so that any mined amounts are
/// preseved between test runs.
const FAUCET_SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

const FAUCET_LABEL: Option<&str> = Some("faucet");

/// Initializes a blockchain and wallet on bitcoin-core. It can be called
/// multiple times (even concurrently) but only generates the client and
/// recipient once.
///
/// This function does the following:
/// * Creates an RPC client to bitcoin-core
/// * Creates or loads a watch-only wallet on bitcoin-core
/// * Loads a "faucet" private-public key pair with a P2WPKH address.
/// * Has the bitcoin-core wallet watch the generated address.
/// * Ensures that the faucet has at least 1 bitcoin spent to its address.
pub fn initialize_blockchain() -> &'static (Client, Recipient) {
    static BTC_CLIENT: OnceLock<(Client, Recipient)> = OnceLock::new();
    BTC_CLIENT.get_or_init(|| {
        let username = BITCOIN_CORE_RPC_USERNAME.to_string();
        let password = BITCOIN_CORE_RPC_PASSWORD.to_string();
        let auth = Auth::UserPass(username, password);
        let rpc = Client::new("http://localhost:18443", auth).unwrap();

        get_or_create_wallet(&rpc, BITCOIN_CORE_WALLET_NAME);
        let faucet = Recipient::from_key(FAUCET_SECRET_KEY, AddressType::P2wpkh);
        faucet.track_address(&rpc, FAUCET_LABEL);

        let amount = rpc
            .get_received_by_address(&faucet.address, Some(1))
            .unwrap();

        if amount < Amount::from_int_btc(1) {
            faucet.generate_blocks(&rpc, 101);
        }

        (rpc, faucet)
    })
}

fn get_or_create_wallet(rpc: &Client, wallet: &str) {
    match rpc.load_wallet(wallet) {
        // Success
        Ok(_) => (),
        // This happens if the wallet has already been loaded.
        Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -35, .. }))) => (),
        // The wallet probably hasn't been created yet, so lets do that
        Err(_) => {
            // We want a wallet that is watch only, since we manage keys
            let disable_private_keys = Some(true);
            rpc.create_wallet(wallet, disable_private_keys, None, None, None)
                .unwrap();
        }
    };
}

/// Helper struct for representing an address we control on bitcoin.
pub struct Recipient {
    pub keypair: secp256k1::Keypair,
    pub address: Address,
}

fn descriptor_base(public_key: &PublicKey, kind: AddressType) -> String {
    match kind {
        AddressType::P2wpkh => format!("wpkh({public_key})"),
        AddressType::P2tr => format!("tr({public_key})"),
        AddressType::P2pkh => format!("pkh({public_key})"),
        // We're missing pay-to-script-hash (P2SH) and
        // pay-to-witness-script-hash (P2WSH)
        _ => unimplemented!(""),
    }
}

impl Recipient {
    /// Generate a new public-private key pair and address of the given
    /// kind.
    pub fn new(kind: AddressType) -> Self {
        let keypair = secp256k1::Keypair::new_global(&mut rand::rngs::OsRng);
        let pk = keypair.public_key();
        let address = match kind {
            AddressType::P2wpkh => Address::p2wpkh(&CompressedPublicKey(pk), Network::Regtest),
            AddressType::P2pkh => Address::p2pkh(PublicKey::new(pk), Network::Regtest),
            AddressType::P2tr => {
                let (internal_key, _) = pk.x_only_public_key();
                Address::p2tr(SECP256K1, internal_key, None, Network::Regtest)
            }
            _ => unimplemented!(),
        };

        Recipient { keypair, address }
    }

    // Use a specific secret key and address kind to generate a recipient.
    pub fn from_key(secret_key: &str, kind: AddressType) -> Self {
        let keypair = secp256k1::Keypair::from_seckey_str_global(secret_key).unwrap();
        let pk = keypair.public_key();
        let address = match kind {
            AddressType::P2wpkh => Address::p2wpkh(&CompressedPublicKey(pk), Network::Regtest),
            AddressType::P2pkh => Address::p2pkh(PublicKey::new(pk), Network::Regtest),
            AddressType::P2tr => {
                let (internal_key, _) = pk.x_only_public_key();
                Address::p2tr(SECP256K1, internal_key, None, Network::Regtest)
            }
            _ => unimplemented!(),
        };

        Recipient { keypair, address }
    }

    /// Tell bitcoin core to track transactions associated with this address,
    ///
    /// Note: this is needed in order for get_utxos and get_balance to work
    /// as expected.
    pub fn track_address(&self, rpc: &Client, label: Option<&str>) {
        let public_key = PublicKey::new(self.keypair.public_key());
        let kind = self.address.address_type().unwrap();

        let desc = descriptor_base(&public_key, kind);
        let descriptor_info = rpc.get_descriptor_info(&desc).unwrap();

        let req = ImportDescriptors {
            descriptor: descriptor_info.descriptor,
            label: label.map(ToString::to_string),
            internal: Some(false),
            timestamp: Timestamp::Time(0),
            active: None,
            next_index: None,
            range: None,
        };
        let response = rpc.import_descriptors(req).unwrap();
        response.into_iter().for_each(|item| assert!(item.success));
    }

    /// Generate num_blocks blocks with coinbase rewards being sent to this
    /// recipient.
    pub fn generate_blocks(&self, rpc: &Client, num_blocks: u64) {
        rpc.generate_to_address(num_blocks, &self.address).unwrap();
    }

    /// Return all UTXOs for this recipient where the amount is greater
    /// than or equal to the given amount. The address must be tracked by
    /// the bitcoin-core wallet.
    pub fn get_utxos(&self, rpc: &Client, amount: Option<u64>) -> Vec<ListUnspentResultEntry> {
        let query_options = amount.map(|sats| ListUnspentQueryOptions {
            minimum_amount: Some(Amount::from_sat(sats)),
            ..Default::default()
        });
        rpc.list_unspent(None, None, Some(&[&self.address]), None, query_options)
            .unwrap()
    }

    /// Get the total amount of UTXOs controlled by the recipient.
    pub fn get_balance(&self, rpc: &Client) -> Amount {
        self.get_utxos(rpc, None)
            .into_iter()
            .map(|x| x.amount)
            .sum()
    }

    /// Send the specified amount to the specific address.
    ///
    /// Note: only P2TR and P2WPKH addresses are supported.
    pub fn send_to(&self, rpc: &Client, amount: u64, address: &Address) {
        let fee = BITCOIN_CORE_FALLBACK_FEE.to_sat();
        let utxo = self.get_utxos(&rpc, Some(amount + fee)).pop().unwrap();

        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(utxo.txid, utxo.vout),
                sequence: Sequence::ZERO,
                script_sig: ScriptBuf::new(),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: address.script_pubkey(),
                },
                TxOut {
                    value: utxo.amount.unchecked_sub(Amount::from_sat(amount + fee)),
                    script_pubkey: self.address.script_pubkey(),
                },
            ],
        };

        let input_index = 0;
        let keypair = &self.keypair;
        match self.address.address_type().unwrap() {
            AddressType::P2wpkh => p2wpkh_sign_transaction(&mut tx, input_index, &utxo, keypair),
            AddressType::P2tr => p2tr_sign_transaction(&mut tx, input_index, &[utxo], keypair),
            _ => unimplemented!(),
        };
        rpc.send_raw_transaction(&tx).unwrap();
    }
}

pub trait Utxo {
    fn amount(&self) -> Amount;
    fn script_pubkey(&self) -> &ScriptBuf;
    fn to_tx_out(&self) -> TxOut {
        TxOut {
            value: self.amount(),
            script_pubkey: self.script_pubkey().clone(),
        }
    }
}

impl Utxo for ListUnspentResultEntry {
    fn amount(&self) -> Amount {
        self.amount
    }

    fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pub_key
    }
}

impl Utxo for TxOut {
    fn amount(&self) -> Amount {
        self.value
    }

    fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }
}

pub fn p2wpkh_sign_transaction<U>(
    tx: &mut Transaction,
    input_index: usize,
    utxo: &U,
    keys: &secp256k1::Keypair,
) where
    U: Utxo,
{
    let sighash_type = EcdsaSighashType::All;
    let sighash = SighashCache::new(&*tx)
        .p2wpkh_signature_hash(
            input_index,
            utxo.script_pubkey().as_script(),
            utxo.amount(),
            sighash_type,
        )
        .expect("failed to create sighash");

    let msg = secp256k1::Message::from(sighash);
    let signature = SECP256K1.sign_ecdsa(&msg, &keys.secret_key());

    let signature = bitcoin::ecdsa::Signature { signature, sighash_type };
    tx.input[input_index].witness = Witness::p2wpkh(&signature, &keys.public_key());
}

pub fn p2tr_sign_transaction<U>(
    tx: &mut Transaction,
    input_index: usize,
    utxos: &[U],
    keypair: &secp256k1::Keypair,
) where
    U: Utxo,
{
    let tx_outs: Vec<TxOut> = utxos.iter().map(Utxo::to_tx_out).collect();
    let prevouts = Prevouts::All(tx_outs.as_slice());
    let sighash_type = TapSighashType::Default;

    let sighash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to create taproot key-spend sighash");
    let tweaked = keypair.tap_tweak(SECP256K1, None);

    let msg = secp256k1::Message::from(sighash);
    let signature = SECP256K1.sign_schnorr(&msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };

    tx.input[input_index].witness = Witness::p2tr_key_spend(&signature);
}

pub fn set_witness_data(unsigned: &mut UnsignedTransaction, keypair: secp256k1::Keypair) {
    let sighash_type = TapSighashType::Default;
    let sighashes = unsigned.construct_digests().unwrap();

    let signer_msg = secp256k1::Message::from(sighashes.signers);
    let tweaked = keypair.tap_tweak(SECP256K1, None);
    let signature = SECP256K1.sign_schnorr(&signer_msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    let signer_witness = Witness::p2tr_key_spend(&signature);

    let deposit_witness = sighashes.deposits.into_iter().map(|(deposit, sighash)| {
        let deposit_msg = secp256k1::Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&deposit_msg, &keypair);
        let signature = bitcoin::taproot::Signature { signature, sighash_type };
        deposit.construct_witness_data(signature)
    });

    let witness_data: Vec<Witness> = std::iter::once(signer_witness)
        .chain(deposit_witness)
        .collect();

    unsigned
        .tx
        .input
        .iter_mut()
        .zip(witness_data)
        .for_each(|(tx_in, witness)| {
            tx_in.witness = witness;
        });
}
