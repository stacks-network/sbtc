//! A module for setting up metrics in the APP
//!

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

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
}

impl From<Metrics> for metrics::KeyName {
    fn from(value: Metrics) -> Self {
        metrics::KeyName::from_const_str(value.into())
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
