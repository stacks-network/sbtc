use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub fn setup_logging() {
    let dirs = "info,signer=debug";

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
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(dirs)))
        .with(main_layer)
        .init()
}
