//! Integration testing helper functions
//!

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::BlockHash;
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
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::key::TapTweak;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::json::ImportDescriptors;
use bitcoincore_rpc::json::ListUnspentQueryOptions;
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoincore_rpc::json::ScanTxOutResult;
use bitcoincore_rpc::json::Timestamp;
use bitcoincore_rpc::json::Utxo;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use secp256k1::SECP256K1;
use std::sync::OnceLock;

/// These must match the username and password in bitcoin.conf
/// The username for RPC calls in bitcoin-core
pub const BITCOIN_CORE_RPC_USERNAME: &str = "devnet";
/// The password for RPC calls in bitcoin-core
pub const BITCOIN_CORE_RPC_PASSWORD: &str = "devnet";

/// The fallback fee in bitcoin core
pub const BITCOIN_CORE_FALLBACK_FEE: Amount = Amount::from_sat(1000);

/// The minimum height of the bitcoin blockchains. You need 100 blocks
/// mined on top of a bitcoin block before you can spend the coinbase
/// rewards.
pub const MIN_BLOCKCHAIN_HEIGHT: u64 = 101;

/// The name of our wallet on bitcoin-core
const BITCOIN_CORE_WALLET_NAME: &str = "integration-tests-wallet";

/// The faucet has a fixed secret key so that any mined amounts are
/// preserved between test runs.
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
pub fn initialize_blockchain() -> (&'static Client, &'static Faucet) {
    static BTC_CLIENT: OnceLock<Client> = OnceLock::new();
    static FAUCET: OnceLock<Faucet> = OnceLock::new();
    let rpc = BTC_CLIENT.get_or_init(|| {
        let username = BITCOIN_CORE_RPC_USERNAME.to_string();
        let password = BITCOIN_CORE_RPC_PASSWORD.to_string();
        let auth = Auth::UserPass(username, password);
        Client::new("http://localhost:18443", auth).unwrap()
    });

    let faucet = FAUCET.get_or_init(|| {
        get_or_create_wallet(rpc, BITCOIN_CORE_WALLET_NAME);
        let faucet = Faucet::new(FAUCET_SECRET_KEY, AddressType::P2wpkh, rpc);
        faucet.track_address(FAUCET_LABEL);

        let amount = rpc.get_received_by_address(&faucet.address, None).unwrap();

        if amount < Amount::from_int_btc(1) {
            faucet.generate_blocks(MIN_BLOCKCHAIN_HEIGHT);
        }

        faucet
    });

    (rpc, faucet)
}

fn get_or_create_wallet(rpc: &Client, wallet: &str) {
    match rpc.load_wallet(wallet) {
        // Success
        Ok(_) => (),
        // This happens if the wallet has already been loaded.
        Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -35, .. }))) => (),
        // The wallet probably hasn't been created yet, so let's do that
        Err(_) => {
            // We want a wallet that is watch only, since we manage keys
            let disable_private_keys = Some(true);
            rpc.create_wallet(wallet, disable_private_keys, None, None, None)
                .unwrap();
        }
    };
}

/// Struct representing the bitcoin miner, all coins are usually generated
/// to this recipient.
pub struct Faucet {
    /// The public/private key pair.
    pub keypair: secp256k1::Keypair,
    /// The address associated with the above keypair.
    pub address: Address,
    /// The rpc client for interacting with bitcoin core.
    pub rpc: &'static Client,
}

/// Helper struct for representing an address we control on bitcoin.
#[derive(Debug, Clone)]
pub struct Recipient {
    /// The public/private key pair
    pub keypair: secp256k1::Keypair,
    /// The address associated with the above keypair.
    pub address: Address,
    /// The script pubkey associated with the above keypair.
    pub script_pubkey: ScriptBuf,
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
        let script_pubkey = match kind {
            AddressType::P2wpkh => ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash()),
            AddressType::P2pkh => ScriptBuf::new_p2pkh(&PublicKey::new(pk).pubkey_hash()),
            AddressType::P2tr => {
                let (internal_key, _) = pk.x_only_public_key();
                ScriptBuf::new_p2tr(SECP256K1, internal_key, None)
            }
            _ => unimplemented!(),
        };

        let params = Network::Regtest.params();
        let address = Address::from_script(&script_pubkey, params).unwrap();

        Recipient {
            keypair,
            address,
            script_pubkey,
        }
    }

    /// Return all UTXOs for this recipient where the amount is greater
    /// than or equal to the given amount. The address must be tracked by
    /// the bitcoin-core wallet.
    pub fn get_utxos(&self, rpc: &Client, amount: Option<u64>) -> Vec<Utxo> {
        let mut utxos = self.scan(rpc).unspents;

        if let Some(amount) = amount {
            utxos.retain(|utxo| utxo.amount.to_sat() >= amount);
        }
        utxos
    }

    /// Get the total amount of UTXOs controlled by the recipient.
    pub fn get_balance(&self, rpc: &Client) -> Amount {
        self.scan(rpc).total_amount
    }

    /// Scan Bitcoin-core for transactions associated with this recipient's
    /// address.
    fn scan(&self, rpc: &Client) -> ScanTxOutResult {
        let public_key = PublicKey::new(self.keypair.public_key());
        let kind = self.address.address_type().unwrap();

        let desc = descriptor_base(&public_key, kind);
        let descriptor = ScanTxOutRequest::Single(desc);
        rpc.scan_tx_out_set_blocking(&[descriptor]).unwrap()
    }
}

impl Faucet {
    fn new(secret_key: &str, kind: AddressType, rpc: &'static Client) -> Self {
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

        Faucet { keypair, address, rpc }
    }

    /// Tell bitcoin core to track transactions associated with this address,
    ///
    /// Note: this is needed in order for get_utxos and get_balance to work
    /// as expected.
    fn track_address(&self, label: Option<&str>) {
        let public_key = PublicKey::new(self.keypair.public_key());
        let kind = self.address.address_type().unwrap();

        let desc = descriptor_base(&public_key, kind);
        let descriptor_info = self.rpc.get_descriptor_info(&desc).unwrap();

        let req = ImportDescriptors {
            descriptor: descriptor_info.descriptor,
            label: label.map(ToString::to_string),
            internal: Some(false),
            timestamp: Timestamp::Time(0),
            active: None,
            next_index: None,
            range: None,
        };
        let response = self.rpc.import_descriptors(req).unwrap();
        response.into_iter().for_each(|item| assert!(item.success));
    }

    /// Generate num_blocks blocks with coinbase rewards being sent to this
    /// recipient.
    pub fn generate_blocks(&self, num_blocks: u64) -> Vec<BlockHash> {
        self.rpc
            .generate_to_address(num_blocks, &self.address)
            .unwrap()
    }

    /// Generates one block with coinbase rewards being sent to this recipient.
    pub fn generate_block(&self) -> BlockHash {
        self.generate_blocks(1)
            .pop()
            .expect("failed to generate bitcoin block")
    }

    /// Return all UTXOs for this recipient where the amount is greater
    /// than or equal to the given amount. The address must be tracked by
    /// the bitcoin-core wallet.
    fn get_utxos(&self, amount: Option<u64>) -> Vec<ListUnspentResultEntry> {
        let query_options = amount.map(|sats| ListUnspentQueryOptions {
            minimum_amount: Some(Amount::from_sat(sats)),
            ..Default::default()
        });
        self.rpc
            .list_unspent(None, None, Some(&[&self.address]), None, query_options)
            .unwrap()
    }

    /// Send the specified amount to the specific address.
    ///
    /// Note: only P2TR and P2WPKH addresses are supported.
    pub fn send_to(&self, amount: u64, address: &Address) -> OutPoint {
        let fee = BITCOIN_CORE_FALLBACK_FEE.to_sat();
        let utxo = self.get_utxos(Some(amount + fee)).pop().unwrap();

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
        self.rpc.send_raw_transaction(&tx).unwrap();
        OutPoint::new(tx.compute_txid(), 0)
    }
}

/// Extract the relevant aspects of a UTXO
pub trait AsUtxo {
    /// The transaction ID
    fn txid(&self) -> Txid;
    /// The output index of the UTXO
    fn vout(&self) -> u32;
    /// The amount locked in the UTXO
    fn amount(&self) -> Amount;
    /// The scriptPubKey for the UTXO
    fn script_pubkey(&self) -> &ScriptBuf;
    /// Transform this into a "UTXO" object
    fn to_tx_out(&self) -> TxOut {
        TxOut {
            value: self.amount(),
            script_pubkey: self.script_pubkey().clone(),
        }
    }
    /// The outpoint of this UTXO
    fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid(), self.vout())
    }
}

impl AsUtxo for Utxo {
    fn txid(&self) -> Txid {
        self.txid
    }
    fn vout(&self) -> u32 {
        self.vout
    }
    fn amount(&self) -> Amount {
        self.amount
    }
    fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pub_key
    }
}

impl AsUtxo for ListUnspentResultEntry {
    fn txid(&self) -> Txid {
        self.txid
    }
    fn vout(&self) -> u32 {
        self.vout
    }
    fn amount(&self) -> Amount {
        self.amount
    }
    fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pub_key
    }
}

/// Provide a signature to the input P2WPKH UTXO
pub fn p2wpkh_sign_transaction<U>(
    tx: &mut Transaction,
    input_index: usize,
    utxo: &U,
    keys: &secp256k1::Keypair,
) where
    U: AsUtxo,
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

/// Provide a signature to the input P2TR UTXO
pub fn p2tr_sign_transaction<U>(
    tx: &mut Transaction,
    input_index: usize,
    utxos: &[U],
    keypair: &secp256k1::Keypair,
) where
    U: AsUtxo,
{
    let tx_outs: Vec<TxOut> = utxos.iter().map(AsUtxo::to_tx_out).collect();
    let prevouts = Prevouts::All(tx_outs.as_slice());
    let sighash_type = TapSighashType::All;

    let sighash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to create taproot key-spend sighash");
    let tweaked = keypair.tap_tweak(SECP256K1, None);

    let msg = secp256k1::Message::from(sighash);
    let signature = SECP256K1.sign_schnorr(&msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };

    tx.input[input_index].witness = Witness::p2tr_key_spend(&signature);
}
