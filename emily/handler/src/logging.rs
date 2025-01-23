//! This module sets up logging for the application using `tracing_subscriber`
//! It provides functions to initialize logging in either JSON format or pretty format

use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Sets up logging based on the provided format preference
///
/// # Arguments
///
/// - `pretty` - A boolean that determines if the logging format should be pretty or JSON
pub fn setup_logging(directives: &str, pretty: bool) {
    match pretty {
        true => setup_logging_pretty(directives),
        false => setup_logging_json(directives),
    }
}

fn setup_logging_json(directives: &str) {
    let main_layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(true)
        .with_span_list(true)
        .with_line_number(true)
        .with_file(true)
        .with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives)))
        .with(main_layer)
        .init()
}

fn setup_logging_pretty(directives: &str) {
    let main_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives)))
        .with(main_layer)
        .init()
}
