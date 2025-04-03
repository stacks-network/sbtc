use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use testcontainers::core::logs::{consumer::LogConsumer, LogFrame};

/// Simple implementation of LogConsumer that captures logs with configurable behavior.
/// Can either print logs directly, store them for later inspection, or both.
#[derive(Clone)]
pub struct SimpleLogConsumer {
    /// Whether to print logs to stdout/stderr
    print_logs: bool,
    /// Optional storage for logs if needed for inspection
    captured_logs: Option<Arc<Mutex<Vec<String>>>>,
    /// Optional prefix to add to each log line for identification
    prefix: Option<String>,
}

impl SimpleLogConsumer {
    /// Creates a new SimpleLogConsumer that prints logs to stdout/stderr
    pub fn new() -> Self {
        Self {
            print_logs: true,
            captured_logs: None,
            prefix: None,
        }
    }
}

impl Default for SimpleLogConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl LogConsumer for SimpleLogConsumer {
    fn accept<'a>(&'a self, record: &'a LogFrame) -> BoxFuture<'a, ()> {
        use futures::future::FutureExt;

        // Convert LogFrame to string representation
        // This uses ToString or Display trait implementation
        let log_content = format!("{:?}", record);

        // Format with prefix if configured
        let line = match &self.prefix {
            Some(prefix) => format!("[{}] {}", prefix, log_content),
            None => log_content,
        };

        // Print the log if enabled
        if self.print_logs {
            eprintln!("{}", line);
        }

        // Store the log if capture is enabled
        if let Some(logs) = &self.captured_logs {
            if let Ok(mut logs_guard) = logs.lock() {
                logs_guard.push(line);
            }
            // Silently continue if lock fails - this is a log consumer
            // and shouldn't cause failures in the main application
        }

        // Return an immediately-resolved future
        async move {}.boxed()
    }
}
