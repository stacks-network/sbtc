use std::str::FromStr;

use bitcoin::hex::DisplayHex;
use bitcoin::{
    absolute, transaction::Version, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut,
};
use bitcoin::{Address, XOnlyPublicKey};
use bitcoincore_rpc::json;
use bitcoincore_rpc::{Client, RpcApi};
use clap::{Args, Parser, Subcommand};
use clarity::{
    types::{chainstate::StacksAddress, Address as _},
    vm::types::{PrincipalData, StandardPrincipalData},
};
use emily_client::{
    apis::{
        configuration::{ApiKey, Configuration},
        deposit_api,
    },
    models::CreateDepositRequestBody,
};
use fake::Fake as _;
use rand::rngs::OsRng;
use sbtc::deposits::{DepositScriptInputs, ReclaimScriptInputs};
use secp256k1::PublicKey;
use signer::config::Settings;
use signer::keys::SignerScriptPubKey;
use signer::storage::model::StacksPrincipal;

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
enum Error {
    #[error("Signer error: {0}")]
    SignerError(#[from] signer::error::Error),
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
    #[error("Invalid signer key: {0}")]
    InvalidSignerKey(String),
}

#[derive(Debug, Parser)]
struct CliArgs {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Simulate a deposit request
    Deposit(DepositArgs),
    Donation(DonationArgs),
    Info(InfoArgs),
}

#[derive(Debug, Args)]
struct DepositArgs {
    /// Amount to deposit in satoshis, excluding the fee.
    #[clap(long)]
    amount: u64,
    /// Maximum fee to pay for the transaction in satoshis, in addition to
    /// the amount.
    #[clap(long)]
    max_fee: u64,
    /// Lock time for the transaction.
    #[clap(long)]
    lock_time: u32,
    /// The beneficiary Stacks address to receive the deposit in sBTC.
    #[clap(long = "stacks-addr")]
    stacks_recipient: String,
    /// The public key of the aggregate signer.
    #[clap(long = "signer-key")]
    signer_aggregate_key: String,
}

#[derive(Debug, Args)]
struct DonationArgs {
    /// Amount to deposit in satoshis, excluding the fee.
    #[clap(long)]
    amount: u64,
    /// The public key of the aggregate signer.
    #[clap(long = "signer-key")]
    signer_aggregate_key: String,
}

#[derive(Debug, Args)]
struct InfoArgs {
    /// The public key of the aggregate signer.
    #[clap(long = "signer-key")]
    signer_aggregate_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    let settings = Settings::new(Some("signer/src/config/default.toml"))?;

    // Setup our Emily client configuration by getting the first configured endpoint
    // and using that to populate the client.
    let emily_api_endpoint_config = settings
        .emily
        .endpoints
        .first()
        .expect("No Emily endpoints configured");
    let emily_client_config = Configuration {
        base_path: emily_api_endpoint_config
            .endpoint
            .to_string()
            .trim_end_matches("/")
            .to_string(),
        api_key: emily_api_endpoint_config
            .api_key
            .clone()
            .map(|key_string| ApiKey { prefix: None, key: key_string }),
        ..Default::default()
    };

    let bitcoin_url = format!(
        "{}wallet/depositor",
        settings
            .bitcoin
            .rpc_endpoints
            .first()
            .expect("No Bitcoin RPC endpoints configured")
    );

    let bitcoin_client = Client::new(
        &bitcoin_url,
        bitcoincore_rpc::Auth::UserPass("devnet".into(), "devnet".into()),
    )
    .expect("Failed to create Bitcoin RPC client");

    match args.command {
        CliCommand::Deposit(args) => {
            exec_deposit(args, &bitcoin_client, &emily_client_config).await?
        }
        CliCommand::Donation(args) => exec_donation(args, &bitcoin_client).await?,
        CliCommand::Info(args) => exec_info(args).await?,
    }

    Ok(())
}

async fn exec_deposit(
    args: DepositArgs,
    bitcoin_client: &Client,
    emily_config: &Configuration,
) -> Result<(), Error> {
    let (unsigned_tx, deposit_script, reclaim_script) =
        create_bitcoin_deposit_transaction(bitcoin_client, &args)?;

    let txid = unsigned_tx.compute_txid();

    let signed_tx = bitcoin_client.sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    println!("Signed transaction: {:?}", hex::encode(&signed_tx.hex));
    let tx = bitcoin_client.send_raw_transaction(&signed_tx.hex)?;
    println!("Transaction sent: calculated txid {txid:?}, actual txid {tx:?}");

    let emily_deposit = deposit_api::create_deposit(
        emily_config,
        CreateDepositRequestBody {
            bitcoin_tx_output_index: 0,
            bitcoin_txid: txid.to_string(),
            deposit_script: deposit_script.deposit_script().to_hex_string(),
            reclaim_script: reclaim_script.reclaim_script().to_hex_string(),
        },
    )
    .await?;

    println!("Deposit request created: {:?}", emily_deposit);

    Ok(())
}

async fn exec_donation(args: DonationArgs, bitcoin_client: &Client) -> Result<(), Error> {
    let pubkey = XOnlyPublicKey::from_str(&args.signer_aggregate_key)
        .or_else(|_| PublicKey::from_str(&args.signer_aggregate_key).map(XOnlyPublicKey::from))
        .map_err(|_| Error::InvalidSignerKey(args.signer_aggregate_key.clone()))?;

    // Look for UTXOs that can cover the amount + max fee
    let opts = json::ListUnspentQueryOptions {
        minimum_amount: Some(Amount::from_sat(args.amount)),
        ..Default::default()
    };

    let unspent = bitcoin_client
        .list_unspent(Some(6), None, None, None, Some(opts))?
        .into_iter()
        .next()
        .ok_or(Error::NoAvailableUtxos)?;

    // Get a new address for change (SegWit)
    let change_address = bitcoin_client
        .get_new_address(None, Some(json::AddressType::Bech32))?
        .require_network(Network::Regtest)?;

    // Create the unsigned transaction
    let unsigned_tx = Transaction {
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
            TxOut {
                value: Amount::from_sat(args.amount),
                script_pubkey: pubkey.signers_script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(unspent.amount.to_sat() - args.amount - 153),
                script_pubkey: change_address.into(),
            },
        ],
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
    };

    let signed_tx = bitcoin_client.sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    println!("Signed transaction: {:?}", hex::encode(&signed_tx.hex));
    let tx = bitcoin_client.send_raw_transaction(&signed_tx.hex)?;

    println!("Transaction sent: {tx:?}");

    Ok(())
}

async fn exec_info(args: InfoArgs) -> Result<(), Error> {
    let pubkey = XOnlyPublicKey::from_str(&args.signer_aggregate_key)
        .or_else(|_| PublicKey::from_str(&args.signer_aggregate_key).map(XOnlyPublicKey::from))
        .map_err(|_| Error::InvalidSignerKey(args.signer_aggregate_key.clone()))?;
    println!("Signers pubkey (for bridge): {pubkey}");

    let address =
        Address::from_script(&pubkey.signers_script_pubkey(), bitcoin::Network::Regtest).unwrap();
    println!("Signers bitcoin address (for donation): {address}");

    let random_principal: StacksPrincipal = fake::Faker.fake_with_rng(&mut OsRng);
    println!(
        "Random stacks address (for demo recipient): {}",
        *random_principal
    );

    Ok(())
}

fn create_bitcoin_deposit_transaction(
    client: &Client,
    args: &DepositArgs,
) -> Result<(Transaction, DepositScriptInputs, ReclaimScriptInputs), Error> {
    let pubkey = XOnlyPublicKey::from_str(&args.signer_aggregate_key)
        .or_else(|_| PublicKey::from_str(&args.signer_aggregate_key).map(XOnlyPublicKey::from))
        .map_err(|_| Error::InvalidSignerKey(args.signer_aggregate_key.clone()))?;

    let deposit_script = DepositScriptInputs {
        signers_public_key: pubkey,
        max_fee: args.max_fee,
        recipient: PrincipalData::Standard(StandardPrincipalData::from(
            StacksAddress::from_string(&args.stacks_recipient)
                .ok_or(Error::InvalidStacksAddress(args.stacks_recipient.clone()))?,
        )),
    };

    let reclaim_script = ReclaimScriptInputs::try_new(args.lock_time, ScriptBuf::new())?;

    // Look for UTXOs that can cover the amount + max fee
    let opts = json::ListUnspentQueryOptions {
        minimum_amount: Some(Amount::from_sat(args.amount + args.max_fee)),
        ..Default::default()
    };
    let unspent = client
        .list_unspent(Some(6), None, None, None, Some(opts))?
        .into_iter()
        .next()
        .ok_or(Error::NoAvailableUtxos)?;

    // Get a new address for change (SegWit)
    let change_address = client
        .get_new_address(None, Some(json::AddressType::Bech32))?
        .require_network(Network::Regtest)?;

    // Create the unsigned transaction
    let unsigned_tx = Transaction {
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
            TxOut {
                value: Amount::from_sat(args.amount + args.max_fee),
                script_pubkey: sbtc::deposits::to_script_pubkey(
                    deposit_script.deposit_script(),
                    reclaim_script.reclaim_script(),
                ),
            },
            TxOut {
                value: Amount::from_sat(unspent.amount.to_sat() - args.amount - args.max_fee - 153),
                script_pubkey: change_address.into(),
            },
        ],
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
    };

    println!(
        "deposit script: {:?}",
        deposit_script
            .deposit_script()
            .as_bytes()
            .to_lower_hex_string()
    );
    println!(
        "reclaim script: {:?}",
        reclaim_script
            .reclaim_script()
            .as_bytes()
            .to_lower_hex_string()
    );

    Ok((unsigned_tx, deposit_script, reclaim_script))
}
