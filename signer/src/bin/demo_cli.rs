use std::str::FromStr;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use bitcoin::{
    absolute, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use bitcoin::{Address, XOnlyPublicKey};
use bitcoincore_rpc::{json, Client as BitcoinClient, RpcApi as _};
use blockstack_lib::chainstate::stacks::address::{PoxAddressType20, PoxAddressType32};
use blockstack_lib::chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, StacksTransaction, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionPublicKeyEncoding,
    TransactionSpendingCondition, TransactionVersion,
};
use clap::{Args, Parser, Subcommand};
use clarity::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use clarity::util::secp256k1::MessageSignature;
use clarity::{
    types::{chainstate::StacksAddress, Address as _},
    vm::types::{PrincipalData, StandardPrincipalData},
};
use config::ConfigError;
use emily_client::{
    apis::{
        configuration::{ApiKey, Configuration as EmilyConfig},
        deposit_api,
    },
    models::CreateDepositRequestBody,
};
use fake::Fake as _;
use rand::rngs::OsRng;
use sbtc::deposits::{DepositScriptInputs, ReclaimScriptInputs};
use signer::config::Settings;
use signer::keys::{PrivateKey, PublicKey, SignerScriptPubKey};
use signer::signature::{sign_stacks_tx, RecoverableEcdsaSignature as _};
use signer::stacks::api::{StacksClient, StacksInteract};
use signer::stacks::contracts::{AsContractCall as _, AsTxPayload as _};
use signer::storage::model::StacksPrincipal;
use signer::testing::wallet::InitiateWithdrawalRequest;
use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

// Demo defaults
const DEMO_PRIVATE_KEY: &str = "2be0a71cb3a27d7f71a790ebe96cd106dd6d9c811b402178d1666ec3034dd64c";
const DEMO_STACKS_ADDR: &str = "ST3497E9JFQ7KB9VEHAZRWYKF3296WQZEXBPXG193";
const DEMO_BITCOIN_ADDR: &str = "bcrt1qezfmjvnaeu66wm52h7885mccjfh9lmh2v4kf8n";
const DEMO_DEPLOYER: &str = "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS";

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
enum Error {
    #[error("Signer error: {0}")]
    SignerError(#[from] signer::error::Error),
    #[error("Config error: {0}")]
    ConfigError(ConfigError),
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(#[from] bitcoincore_rpc::Error),
    #[error("Invalid Bitcoin address: {0}")]
    InvalidBitcoinAddress(#[from] bitcoin::address::ParseError),
    #[error("No available UTXOs")]
    NoAvailableUtxos,
    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),
    #[error("SBTC error: {0}")]
    SbtcError(#[from] sbtc::error::Error),
    #[error("Emily deposit error: {0}")]
    EmilyDeposit(#[from] emily_client::apis::Error<deposit_api::CreateDepositError>),
    #[error("Invalid stacks address: {0}")]
    InvalidStacksAddress(String),
    #[error("Invalid deployer: {0}")]
    InvalidDeployer(String),
}

#[derive(Debug, Parser)]
struct CliArgs {
    #[clap(subcommand)]
    command: CliCommand,
    /// The address that deployed the contract.
    #[clap(long = "deployer", default_value = DEMO_DEPLOYER)]
    deployer: String,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Simulate a deposit request
    Deposit(DepositArgs),
    Withdraw(WithdrawArgs),
    Donation(DonationArgs),
    Info,
}

#[derive(Debug, Args)]
struct DepositArgs {
    /// Amount to deposit in satoshis (including fees).
    #[clap(long)]
    amount: u64,
    /// Maximum fee to pay for the transaction in satoshis.
    #[clap(long = "max-fee", default_value = "20000")]
    max_fee: u64,
    /// Lock time for the transaction.
    #[clap(long = "lock-time", default_value = "10")]
    lock_time: u32,
    /// The beneficiary Stacks address to receive the deposit in sBTC.
    #[clap(long = "recipient", default_value = DEMO_STACKS_ADDR)]
    recipient: String,
}

#[derive(Debug, Args)]
struct WithdrawArgs {
    /// Amount to withdraw in satoshis (excluding fees).
    #[clap(long)]
    amount: u64,
    /// Maximum fee to pay for the transaction in satoshis.
    #[clap(long = "max-fee", default_value = "20000")]
    max_fee: u64,
    /// The sBTC sender private key.
    #[clap(long = "sender-sk", default_value = DEMO_PRIVATE_KEY)]
    sender_sk: String,
    /// The BTC recipient.
    #[clap(long = "recipient", default_value = DEMO_BITCOIN_ADDR)]
    recipient: String,
}

#[derive(Debug, Args)]
struct DonationArgs {
    /// Amount to donate
    #[clap(long)]
    amount: u64,
}

struct Context {
    bitcoin_client: BitcoinClient,
    stacks_client: StacksClient,
    emily_config: EmilyConfig,
    deployer: StacksAddress,
    network: bitcoin::Network,
}

impl Context {
    fn new(args: &CliArgs) -> Result<Context, Error> {
        let settings =
            Settings::new(Some("signer/src/config/default.toml")).map_err(Error::ConfigError)?;

        let emily_config = get_emily_config(&settings);
        let bitcoin_client = get_bitcoin_client(&settings);
        let stacks_client = get_stacks_client(&settings);
        let deployer = PrincipalData::parse_standard_principal(&args.deployer)
            .map(StacksAddress::from)
            .map_err(|_| Error::InvalidDeployer(args.deployer.clone()))?;

        Ok(Context {
            bitcoin_client,
            stacks_client,
            emily_config,
            deployer,
            network: bitcoin::Network::Regtest,
        })
    }

    async fn get_current_aggregate_key(&self) -> Result<Option<PublicKey>, Error> {
        self.stacks_client
            .get_current_signers_aggregate_key(&self.deployer)
            .await
            .map_err(Error::SignerError)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();
    let ctx = Context::new(&args).expect("failed to create context");

    match args.command {
        CliCommand::Deposit(args) => exec_deposit(&ctx, args).await?,
        CliCommand::Withdraw(args) => exec_withdraw(&ctx, args).await?,
        CliCommand::Donation(args) => exec_donation(&ctx, args).await?,
        CliCommand::Info => exec_info(&ctx).await?,
    }
    Ok(())
}

fn get_emily_config(settings: &Settings) -> EmilyConfig {
    // Setup our Emily client configuration by getting the first configured endpoint
    // and using that to populate the client.
    let mut emily_api_endpoint = settings
        .emily
        .endpoints
        .first()
        .expect("No Emily endpoints configured")
        .clone();

    let emily_api_key = if emily_api_endpoint.username().is_empty() {
        None
    } else {
        Some(ApiKey {
            prefix: None,
            key: emily_api_endpoint.username().to_string(),
        })
    };

    let _ = emily_api_endpoint.set_username("");

    EmilyConfig {
        base_path: emily_api_endpoint
            .to_string()
            .trim_end_matches("/")
            .to_string(),
        api_key: emily_api_key,
        ..Default::default()
    }
}

fn get_bitcoin_client(settings: &Settings) -> BitcoinClient {
    let bitcoin_url = format!(
        "{}wallet/depositor",
        settings
            .bitcoin
            .rpc_endpoints
            .first()
            .expect("No Bitcoin RPC endpoints configured")
    );

    BitcoinClient::new(
        &bitcoin_url,
        bitcoincore_rpc::Auth::UserPass("devnet".into(), "devnet".into()),
    )
    .expect("Failed to create Bitcoin RPC client")
}

fn get_stacks_client(settings: &Settings) -> StacksClient {
    let url = settings
        .stacks
        .endpoints
        .first()
        .expect("No Stacks endpoints configured");

    StacksClient::new(url.clone()).expect("Failed to create Stacks client")
}

async fn exec_deposit(ctx: &Context, args: DepositArgs) -> Result<(), Error> {
    let (unsigned_tx, deposit_script, reclaim_script) =
        create_bitcoin_deposit_transaction(ctx, &args).await?;

    let txid = unsigned_tx.compute_txid();

    let signed_tx =
        ctx.bitcoin_client
            .sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    println!("Signed transaction: {}", hex::encode(&signed_tx.hex));

    let tx_id = ctx.bitcoin_client.send_raw_transaction(&signed_tx.hex)?;
    println!("Transaction sent: {tx_id}");

    let emily_deposit = deposit_api::create_deposit(
        &ctx.emily_config,
        CreateDepositRequestBody {
            bitcoin_tx_output_index: 0,
            bitcoin_txid: txid.to_string(),
            deposit_script: deposit_script.deposit_script().to_hex_string(),
            reclaim_script: reclaim_script.reclaim_script().to_hex_string(),
            transaction_hex: serialize_hex(&unsigned_tx),
        },
    )
    .await?;

    println!("Deposit request created: {:?}", emily_deposit);

    Ok(())
}

async fn exec_donation(ctx: &Context, args: DonationArgs) -> Result<(), Error> {
    let aggregate_key = ctx
        .get_current_aggregate_key()
        .await?
        .expect("missing aggregate key in contract");

    let unsigned_tx = get_transaction(
        &ctx.bitcoin_client,
        TxOut {
            value: Amount::from_sat(args.amount),
            script_pubkey: aggregate_key.signers_script_pubkey(),
        },
        Amount::from_sat(153),
    )?;

    let signed_tx =
        ctx.bitcoin_client
            .sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    println!("Signed transaction: {}", hex::encode(&signed_tx.hex));

    let tx_id = ctx.bitcoin_client.send_raw_transaction(&signed_tx.hex)?;
    println!("Transaction sent: {tx_id}");

    Ok(())
}

async fn exec_info(ctx: &Context) -> Result<(), Error> {
    println!("Deployer: {}", ctx.deployer);

    let Some(aggregate_key) = ctx.get_current_aggregate_key().await? else {
        println!("No aggregate key (missing rotate key?)");
        return Ok(());
    };

    println!("Current aggregate key: {aggregate_key}");

    let x_only: XOnlyPublicKey = aggregate_key.into();
    println!("Signers xonly pubkey: {x_only}");

    let address = Address::from_script(&x_only.signers_script_pubkey(), ctx.network).unwrap();
    println!("Signers regtest bitcoin address (for donation): {address}");

    let random_principal: StacksPrincipal = fake::Faker.fake_with_rng(&mut OsRng);
    println!(
        "Random stacks address (for demo recipient): {}",
        *random_principal
    );

    Ok(())
}

async fn exec_withdraw(ctx: &Context, args: WithdrawArgs) -> Result<(), Error> {
    let recipient_addr = Address::from_str(&args.recipient)?.require_network(ctx.network)?;
    let recipient = address_to_clarity_arg(&recipient_addr);

    let withdrawal_request = InitiateWithdrawalRequest {
        amount: args.amount,
        recipient,
        max_fee: args.max_fee,
        deployer: ctx.deployer,
    };

    let payload = TransactionPayload::ContractCall(withdrawal_request.as_contract_call());
    let tx = create_stacks_tx(ctx, payload, args.sender_sk).await?;

    println!(
        "Submitted stacks tx: {:?}",
        ctx.stacks_client.submit_tx(&tx).await
    );

    Ok(())
}

async fn create_stacks_tx(
    ctx: &Context,
    payload: TransactionPayload,
    sender_sk: String,
) -> Result<StacksTransaction, Error> {
    let private_key = PrivateKey::from_str(&sender_sk).map_err(Error::SignerError)?;
    let public_key = PublicKey::from_private_key(&private_key);

    let (tx_version, chain_id, addr_version) = match ctx.network {
        bitcoin::Network::Bitcoin => (
            TransactionVersion::Mainnet,
            CHAIN_ID_MAINNET,
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        ),
        _ => (
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        ),
    };

    let sender_addr = StacksAddress::from_public_keys(
        addr_version,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key.into()],
    )
    .expect("failed to generate address from public key");
    let nonce = ctx
        .stacks_client
        .get_account(&sender_addr)
        .await
        .map_err(Error::SignerError)?
        .nonce;

    let conditions = payload.post_conditions();

    let auth = SinglesigSpendingCondition {
        signer: sender_addr.bytes,
        nonce,
        tx_fee: 1000,
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Compressed,
        signature: MessageSignature::empty(),
    };

    let mut tx = StacksTransaction {
        version: tx_version,
        chain_id,
        auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: conditions.post_condition_mode,
        post_conditions: conditions.post_conditions,
        payload: payload.tx_payload(),
    };

    let signature = sign_stacks_tx(&tx, &private_key).as_stacks_sig();
    match tx.auth {
        TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref mut auth)) => {
            auth.set_signature(signature)
        }
        _ => panic!("unexpected tx auth"),
    }

    Ok(tx)
}

fn address_to_clarity_arg(addr: &Address) -> (u8, Vec<u8>) {
    // We cannot use `PoxAddress::from_b58` as it doesn't support regtest addresses
    let addr_data = addr.to_address_data();
    let bytes: &[u8] = match addr_data {
        bitcoin::address::AddressData::P2pkh { ref pubkey_hash } => pubkey_hash.as_ref(),
        bitcoin::address::AddressData::P2sh { ref script_hash } => script_hash.as_ref(),
        bitcoin::address::AddressData::Segwit { ref witness_program } => {
            witness_program.program().as_bytes()
        }
        _ => panic!("unexpected addr"),
    };
    let version: u8 = match addr.address_type().expect("unknown addr type") {
        bitcoin::AddressType::P2pkh => AddressHashMode::SerializeP2PKH as u8,
        bitcoin::AddressType::P2sh => AddressHashMode::SerializeP2SH as u8,
        bitcoin::AddressType::P2wpkh => PoxAddressType20::P2WPKH as u8,
        bitcoin::AddressType::P2wsh => PoxAddressType32::P2WSH as u8,
        bitcoin::AddressType::P2tr => PoxAddressType32::P2TR as u8,
        _ => todo!(),
    };
    (version, bytes.to_vec())
}

async fn create_bitcoin_deposit_transaction(
    ctx: &Context,
    args: &DepositArgs,
) -> Result<(Transaction, DepositScriptInputs, ReclaimScriptInputs), Error> {
    let aggregate_key = ctx
        .get_current_aggregate_key()
        .await?
        .expect("missing aggregate key in contract");

    let deposit_script = DepositScriptInputs {
        signers_public_key: aggregate_key.into(),
        max_fee: args.max_fee,
        recipient: PrincipalData::Standard(StandardPrincipalData::from(
            StacksAddress::from_string(&args.recipient)
                .ok_or(Error::InvalidStacksAddress(args.recipient.clone()))?,
        )),
    };

    let reclaim_script = ReclaimScriptInputs::try_new(args.lock_time, ScriptBuf::new())?;

    let unsigned_tx = get_transaction(
        &ctx.bitcoin_client,
        TxOut {
            value: Amount::from_sat(args.amount),
            script_pubkey: sbtc::deposits::to_script_pubkey(
                deposit_script.deposit_script(),
                reclaim_script.reclaim_script(),
            ),
        },
        Amount::from_sat(153),
    )?;

    println!(
        "deposit script: {}",
        deposit_script
            .deposit_script()
            .as_bytes()
            .to_lower_hex_string()
    );
    println!(
        "reclaim script: {}",
        reclaim_script
            .reclaim_script()
            .as_bytes()
            .to_lower_hex_string()
    );

    Ok((unsigned_tx, deposit_script, reclaim_script))
}

fn get_transaction(
    bitcoin_client: &BitcoinClient,
    tx_out: TxOut,
    fee: Amount,
) -> Result<Transaction, Error> {
    let amount = tx_out.value;

    // Look for UTXOs that can cover the amount + transaction fee
    let opts = json::ListUnspentQueryOptions {
        minimum_amount: Some(amount + fee),
        ..Default::default()
    };

    let unspent = bitcoin_client
        .list_unspent(Some(1), None, None, None, Some(opts))?
        .into_iter()
        .next()
        .ok_or(Error::NoAvailableUtxos)?;

    // Create the unsigned transaction
    Ok(Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: unspent.txid,
                vout: unspent.vout,
            },
            script_sig: Default::default(),
            sequence: Sequence::ZERO,
            witness: Default::default(),
        }],
        output: vec![
            tx_out,
            TxOut {
                value: unspent.amount - amount - fee,
                script_pubkey: unspent.script_pub_key,
            },
        ],
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
    })
}
