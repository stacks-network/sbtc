//! Command-line utility for constructing sBTC deposit addresses.

use std::str::FromStr as _;
use std::time::Duration;

use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::opcodes::all as opcodes;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use clarity::vm::Value as ClarityValue;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::SequenceData;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use secp256k1::PublicKey;
use serde::Deserialize;

const DEFAULT_MAX_FEE: u64 = 80_000;
const DEFAULT_LOCK_TIME: u32 = 950;
const DEFAULT_STACKS_API_URL: &str = "https://api.hiro.so";
const DEFAULT_DEPLOYER: &str = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("invalid Stacks recipient: {0}")]
    InvalidRecipient(String),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid reclaim script hex: {0}")]
    InvalidReclaimScript(String),
    #[error("invalid response from the Stacks API: {0}")]
    InvalidStacksResponse(String),
    #[error("the sBTC registry has no aggregate key")]
    MissingAggregateKey,
    #[error("Stacks API request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("could not construct the reclaim script: {0}")]
    ReclaimScript(#[from] sbtc::error::Error),
}

/// Utilities for working with sBTC.
#[derive(Debug, Parser)]
#[command(name = "sbtc")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compute the Bitcoin address for an sBTC deposit.
    ComputeDepositAddress(ComputeDepositAddress),
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("reclaim")
        .required(true)
        .multiple(false)
        .args(["reclaim_pubkey", "reclaim_script"])
))]
struct ComputeDepositAddress {
    /// The Stacks principal that will receive the minted sBTC.
    recipient: String,

    /// Hex-encoded public key that controls the reclaim path. Accepts a
    /// 32-byte x-only or 33-byte compressed key.
    #[arg(long, value_name = "PUBLIC_KEY")]
    reclaim_pubkey: Option<String>,

    /// Complete hex-encoded reclaim script, including its lock-time prefix.
    #[arg(long, value_name = "HEX")]
    reclaim_script: Option<String>,

    /// Maximum Bitcoin L1 fee, in satoshis, chargeable during the signers'
    /// sweep.
    #[arg(long, default_value_t = DEFAULT_MAX_FEE)]
    max_fee: u64,

    /// The relative lock time, in Bitcoin blocks. Only used with `--reclaim-pubkey`.
    #[arg(long, default_value_t = DEFAULT_LOCK_TIME, conflicts_with = "reclaim_script")]
    lock_time: u32,

    /// The current signer aggregate key. When omitted, it is fetched from
    /// the sBTC registry smart contract.
    #[arg(long, value_name = "PUBLIC_KEY")]
    signers_aggregate_pubkey: Option<String>,

    /// Base URL for the Stacks API used to query the sBTC registry smart
    /// contract.
    #[arg(long, default_value = DEFAULT_STACKS_API_URL)]
    stacks_api_url: String,

    /// The Stacks address that deployed the sBTC registry smart contract.
    #[arg(long, default_value = DEFAULT_DEPLOYER)]
    deployer: String,

    /// The Bitcoin network for the resulting address.
    #[arg(long, value_enum, default_value_t = BitcoinNetwork::Mainnet)]
    network: BitcoinNetwork,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl From<BitcoinNetwork> for Network {
    fn from(value: BitcoinNetwork) -> Self {
        match value {
            BitcoinNetwork::Mainnet => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DataVarResponse {
    data: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    match Cli::parse().command {
        Command::ComputeDepositAddress(args) => compute_deposit_address(args).await,
    }
}

async fn compute_deposit_address(args: ComputeDepositAddress) -> Result<(), Error> {
    let recipient = PrincipalData::parse(&args.recipient)
        .map_err(|_| Error::InvalidRecipient(args.recipient.clone()))?;

    let signers_public_key = match args.signers_aggregate_pubkey {
        Some(key) => parse_x_only_public_key(&key)?,
        None => fetch_aggregate_key(&args.stacks_api_url, &args.deployer).await?,
    };

    let reclaim_script = match (args.reclaim_pubkey, args.reclaim_script) {
        (Some(key), None) => {
            let key = parse_x_only_public_key(&key)?;
            let user_script = ScriptBuf::builder()
                .push_opcode(opcodes::OP_DROP)
                .push_slice(key.serialize())
                .push_opcode(opcodes::OP_CHECKSIG)
                .into_script();
            ReclaimScriptInputs::try_new(args.lock_time, user_script)?.reclaim_script()
        }
        (None, Some(script)) => {
            let script = ScriptBuf::from_hex(script.trim_start_matches("0x"))
                .map_err(|error| Error::InvalidReclaimScript(error.to_string()))?;
            ReclaimScriptInputs::parse(&script)?.reclaim_script()
        }
        _ => unreachable!("clap requires exactly one reclaim input"),
    };

    let deposit = DepositScriptInputs {
        signers_public_key,
        recipient,
        max_fee: args.max_fee,
    };

    println!(
        "{}",
        deposit.to_address(reclaim_script, args.network.into())
    );
    Ok(())
}

fn parse_x_only_public_key(value: &str) -> Result<XOnlyPublicKey, Error> {
    let key = value.strip_prefix("0x").unwrap_or(value);
    XOnlyPublicKey::from_str(key)
        .or_else(|_| PublicKey::from_str(key).map(|key| key.x_only_public_key().0))
        .map_err(|_| Error::InvalidPublicKey(value.to_owned()))
}

async fn fetch_aggregate_key(api_url: &str, deployer: &str) -> Result<XOnlyPublicKey, Error> {
    let url = format!(
        "{}/v2/data_var/{deployer}/sbtc-registry/current-aggregate-pubkey?proof=0",
        api_url.trim_end_matches('/')
    );
    let response = reqwest::Client::new()
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?
        .error_for_status()?
        .json::<DataVarResponse>()
        .await?;
    parse_aggregate_key(&response.data)
}

fn parse_aggregate_key(data: &str) -> Result<XOnlyPublicKey, Error> {
    let value = ClarityValue::try_deserialize_hex_untyped(data)
        .map_err(|error| Error::InvalidStacksResponse(error.to_string()))?;

    let bytes = match value {
        ClarityValue::Sequence(SequenceData::Buffer(buffer)) => buffer.data,
        _ => {
            return Err(Error::InvalidStacksResponse(
                "aggregate key data variable was not a buffer".into(),
            ));
        }
    };
    if bytes.as_slice() == [0] {
        return Err(Error::MissingAggregateKey);
    }
    let key = PublicKey::from_slice(&bytes)
        .map_err(|_| Error::InvalidStacksResponse("aggregate key was not a public key".into()))?;
    Ok(key.x_only_public_key().0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    const RECIPIENT: &str = "SP000000000000000000002Q6VF78";
    const KEY: &str = "026c44dfe47941b0271c642c549d9a763afce7c6b0495c72f1a32c2f09898ea3df";

    #[test]
    fn compute_address_defaults() {
        let cli = Cli::try_parse_from([
            "sbtc",
            "compute-deposit-address",
            RECIPIENT,
            "--reclaim-pubkey",
            KEY,
        ])
        .unwrap();
        let Command::ComputeDepositAddress(args) = cli.command;

        assert_eq!(args.max_fee, DEFAULT_MAX_FEE);
        assert_eq!(args.lock_time, DEFAULT_LOCK_TIME);
        assert_eq!(args.stacks_api_url, DEFAULT_STACKS_API_URL);
        assert_eq!(args.deployer, DEFAULT_DEPLOYER);
        assert!(args.signers_aggregate_pubkey.is_none());
        assert!(matches!(args.network, BitcoinNetwork::Mainnet));
    }

    #[test]
    fn signers_aggregate_pubkey_option_is_accepted() {
        let cli = Cli::try_parse_from([
            "sbtc",
            "compute-deposit-address",
            RECIPIENT,
            "--reclaim-pubkey",
            KEY,
            "--signers-aggregate-pubkey",
            KEY,
        ])
        .unwrap();
        let Command::ComputeDepositAddress(args) = cli.command;

        assert_eq!(args.signers_aggregate_pubkey.as_deref(), Some(KEY));
    }

    #[test]
    fn reclaim_input_is_required_and_exclusive() {
        let missing = Cli::try_parse_from(["sbtc", "compute-deposit-address", RECIPIENT]);
        assert_eq!(
            missing.unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );

        let duplicate = Cli::try_parse_from([
            "sbtc",
            "compute-deposit-address",
            RECIPIENT,
            "--reclaim-pubkey",
            KEY,
            "--reclaim-script",
            "51",
        ]);
        assert_eq!(duplicate.unwrap_err().kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn lock_time_cannot_be_used_with_a_reclaim_script() {
        let script = Cli::try_parse_from([
            "sbtc",
            "compute-deposit-address",
            RECIPIENT,
            "--reclaim-script",
            "00b2",
        ]);
        assert!(script.is_ok());

        let explicit_lock_time = Cli::try_parse_from([
            "sbtc",
            "compute-deposit-address",
            RECIPIENT,
            "--reclaim-script",
            "00b2",
            "--lock-time",
            "950",
        ]);
        assert_eq!(
            explicit_lock_time.unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn compressed_and_x_only_keys_are_accepted() {
        let compressed = parse_x_only_public_key(KEY).unwrap();
        let x_only = parse_x_only_public_key(&compressed.to_string()).unwrap();
        assert_eq!(compressed, x_only);
        assert_eq!(
            compressed,
            parse_x_only_public_key(&format!("0x{KEY}")).unwrap()
        );
    }

    #[test]
    fn aggregate_key_is_decoded_from_clarity() {
        let encoded = format!("0x0200000021{KEY}");
        assert_eq!(
            parse_aggregate_key(&encoded).unwrap(),
            parse_x_only_public_key(KEY).unwrap()
        );
        assert!(matches!(
            parse_aggregate_key("0x020000000100"),
            Err(Error::MissingAggregateKey)
        ));
    }
}
