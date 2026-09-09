//! A module for setting up metrics in the APP
//!

use std::net::SocketAddr;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Response;

use crate::block_observer::Deposit;
use crate::error::Error;
use crate::message::StacksTransactionSignRequest;
use crate::stacks::api::ClarityName;
use crate::stacks::contracts::SmartContract;
use crate::transaction_signer::AcceptedSigHash;

/// The buckets used for metric histograms
const METRIC_BUCKETS: [f64; 9] = [1e-4, 1e-3, 1e-2, 0.1, 0.5, 1.0, 5.0, 20.0, f64::INFINITY];

/// The quantiles to use when rendering histograms
const METRIC_QUANTILES: [f64; 8] = [0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0];

/// All metrics captured in this crate
#[derive(strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Metrics {
    /// The metric for the total number of submitted transactions.
    TransactionsSubmittedTotal,
    /// The metric for the total number of deposit requests that have been
    /// swept.
    DepositsSweptTotal,
    /// The metric for the total number of observed bitcoin or stacks
    /// blocks. We use a label to distinguish ¡between the two. Note that
    /// this only includes bitcoin blocks observed over the ZeroMQ
    /// interface and stacks blocks observed from the event observer.
    BlocksObservedTotal,
    /// The number of deposit requests processed from Emily. This includes
    /// duplicates.
    DepositRequestsTotal,
    /// The total number of signing rounds that have completed
    /// successfully. This includes WSTS and "regular" multi-sig signing
    /// rounds on stacks. We use a label to distinguish between the two.
    SigningRoundsCompletedTotal,
    /// The total number of tenures that this signer has served as
    /// coordinator.
    CoordinatorTenuresTotal,
    /// The total number of sign requests received from the signer.
    SignRequestsTotal,
    /// The amount of time it took to complete a signing round in seconds.
    /// This includes WSTS and "regular" multi-sig signing rounds on
    /// stacks. We use a label to distinguish between the two.
    SigningRoundDurationSeconds,
    /// The amount of time, in seconds for running bitcoin or stacks
    /// validation.
    ValidationDurationSeconds,
    /// The number of peers connected in the p2p network.
    PeersConnected,
    /// The amount of time, in seconds, it took for a call-read request to
    /// return from the stacks node.
    CallReadOnlyDurationSeconds,
    /// Records total number of times that a call-read request has been
    /// made to the stacks node.
    CallReadOnlyRequestsTotal,
    /// The amount of time, in seconds, it took for to read a data variable
    /// in a smart contract by making a request to the stacks node.
    ReadDataVarDurationSeconds,
    /// Records the total number of times that request to read a data
    /// variable has been made to the stacks node.
    ReadDataVarRequestsTotal,
    /// The amount of time, in seconds, it took read a map entry in a smart
    /// contract by making a request to the stacks node.
    ReadMapEntryDurationSeconds,
    /// The total number of times that a request to read a map entry in a
    /// smart contract has been made to the stacks node.
    ReadMapEntryRequestsTotal,
}

impl From<Metrics> for metrics::KeyName {
    fn from(value: Metrics) -> Self {
        metrics::KeyName::from_const_str(value.into())
    }
}

impl From<SmartContract> for metrics::SharedString {
    fn from(value: SmartContract) -> Self {
        metrics::SharedString::const_str(value.contract_name())
    }
}

impl From<ClarityName> for metrics::SharedString {
    fn from(value: ClarityName) -> Self {
        metrics::SharedString::const_str(value.0)
    }
}

impl Metrics {
    /// Increment the deposit request counter for incoming deposit requests
    pub fn increment_deposit_total(deposit: &Result<Option<Deposit>, Error>) {
        let deposit_status = match deposit {
            Ok(Some(_)) => "success",
            Ok(None) => "unconfirmed",
            Err(_) => "failed",
        };

        metrics::counter!(
            Metrics::DepositRequestsTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "status" => deposit_status,
        )
        .increment(1);
    }

    /// Increment the gauge for the number of connected peers
    pub fn increment_peers_connected_total() {
        metrics::gauge!(Metrics::PeersConnected).increment(1.0);
    }

    /// Decrement the gauge for the number of connected peers
    pub fn decrement_peers_connected_total() {
        metrics::gauge!(Metrics::PeersConnected).decrement(1.0);
    }

    /// Increment number of presign requests that were processed noting
    /// whether the presign validation finished successfully. Also record
    /// the amount of time that it took to run the validation.
    ///
    /// # Notes
    ///
    /// If the presign validation result is Ok, just means that the request
    /// itself included deposits and withdrawals that we know about and
    /// that there were no duplicates with the request. There could still
    /// be deposits and withdrawals that failed validation.
    pub fn increment_presign_validation(elapsed: Duration, presign_result: &Result<(), Error>) {
        let status = if presign_result.is_ok() {
            "success"
        } else {
            "failure"
        };
        metrics::histogram!(
            Metrics::ValidationDurationSeconds,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep-presign",
            "status" => status,
        )
        .record(elapsed);

        metrics::counter!(
            Metrics::SignRequestsTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep-presign",
            "status" => status,
        )
        .increment(1);
    }

    /// Increment the result of a request to sign stacks transaction after
    /// validation has run. Also note the time it took to run validation.
    pub fn increment_stacks_validation(
        elapsed: Duration,
        request: &StacksTransactionSignRequest,
        validation_result: &Result<(), Error>,
    ) {
        metrics::histogram!(
            Metrics::ValidationDurationSeconds,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => request.tx_kind(),
        )
        .record(elapsed);
        metrics::counter!(
            Metrics::SignRequestsTotal,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => request.tx_kind(),
            "status" => if validation_result.is_ok() { "success" } else { "failed" },
        )
        .increment(1);
    }

    /// Increment the result of a request to sign a particular sighash of a
    /// bitcoin transaction.
    pub fn increment_bitcoin_validation(sighash_result: &Result<AcceptedSigHash, Error>) {
        let validation_status = match &sighash_result {
            Ok(_) => "success",
            Err(Error::SigHashConversion(_)) => "improper-sighash",
            Err(Error::UnknownSigHash(_)) => "unknown-sighash",
            Err(Error::InvalidSigHash(_)) => "invalid-sighash",
            Err(Error::SignatureTypeMismatch { .. }) => "signature-type-mismatch",
            Err(_) => "unexpected-failure",
        };

        metrics::counter!(
            Metrics::SignRequestsTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep",
            "status" => validation_status,
        )
        .increment(1);
    }

    /// Record the amount of time it took to complete a
    /// /v2/contracts/call-read request from the stacks node.
    pub fn record_call_read(
        elapsed: Duration,
        contract_name: SmartContract,
        function_name: ClarityName,
        response: &Response,
    ) {
        metrics::histogram!(
            Metrics::CallReadOnlyDurationSeconds,
            "contract_name" => contract_name,
            "function_name" => function_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .record(elapsed);

        metrics::counter!(
            Metrics::CallReadOnlyRequestsTotal,
            "contract_name" => contract_name,
            "function_name" => function_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .increment(1);
    }

    /// Record the amount of time it took to complete a /v2/data_var
    /// request from the stacks node.
    pub fn record_data_var(
        elapsed: Duration,
        contract_name: SmartContract,
        variable_name: ClarityName,
        response: &Response,
    ) {
        metrics::histogram!(
            Metrics::ReadDataVarDurationSeconds,
            "contract_name" => contract_name,
            "variable_name" => variable_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .record(elapsed);

        metrics::counter!(
            Metrics::ReadDataVarRequestsTotal,
            "contract_name" => contract_name,
            "variable_name" => variable_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .increment(1);
    }

    /// Record the amount of time it took to complete a /v2/map_entry
    /// request from the stacks node.
    pub fn record_map_entry(
        elapsed: Duration,
        contract_name: SmartContract,
        map_name: ClarityName,
        response: &Response,
    ) {
        metrics::histogram!(
            Metrics::ReadMapEntryDurationSeconds,
            "contract_name" => contract_name,
            "map_name" => map_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .record(elapsed);

        metrics::counter!(
            Metrics::ReadMapEntryRequestsTotal,
            "contract_name" => contract_name,
            "map_name" => map_name,
            "status_code" => response.status().as_u16().to_string(),
            "blockchain" => STACKS_BLOCKCHAIN,
        )
        .increment(1);
    }
}

/// Label for bitcoin blockchain based metrics
pub const BITCOIN_BLOCKCHAIN: &str = "bitcoin";

/// Label for stacks blockchain based metrics.
pub const STACKS_BLOCKCHAIN: &str = "stacks";

/// Set up a prometheus exporter for metrics.
pub fn setup_metrics(prometheus_exporter_endpoint: Option<SocketAddr>) {
    if let Some(addr) = prometheus_exporter_endpoint {
        PrometheusBuilder::new()
            .with_http_listener(addr)
            .add_global_label("app", crate::PACKAGE_NAME)
            .set_buckets(&METRIC_BUCKETS)
            .expect("received an empty slice of metric buckets")
            .set_quantiles(&METRIC_QUANTILES)
            .expect("received an empty slice of metric quantiles")
            .install()
            .expect("could not install the prometheus server");
    }

    metrics::gauge!(
        "build_info",
        "rust_version" => crate::RUSTC_VERSION,
        "revision" => crate::GIT_COMMIT,
        "arch" => crate::TARGET_ARCH,
        "env_abi" => crate::TARGET_ENV_ABI,
    )
    .set(1.0);
}
