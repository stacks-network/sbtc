//! Module that contains termination-related code for the [`Context`].

use tokio_stream::wrappers::BroadcastStream;

use super::SignerCommand;
use super::SignerSignal;

/// Handle to the termination signal. This can be used to signal the application
/// to shutdown or to wait for a shutdown signal.
pub struct TerminationHandle(
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
);

impl Clone for TerminationHandle {
    fn clone(&self) -> Self {
        Self(
            self.0.clone(),     // Sender
            self.0.subscribe(), // Receiver
        )
    }
}

impl TerminationHandle {
    /// Create a new termination handle.
    pub fn new(
        tx: tokio::sync::watch::Sender<bool>,
        rx: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self(tx, rx)
    }

    /// Check if a shutdown signal has been signalled.
    pub fn shutdown_signalled(&self) -> bool {
        *self.1.borrow()
    }

    /// Signal the application to shutdown.
    pub fn signal_shutdown(&self) {
        // We ignore the result here, as if all receivers have been dropped,
        // we're on our way down anyway.
        self.0.send_if_modified(|x| {
            if !(*x) {
                *x = true;
                true
            } else {
                false
            }
        });
    }
    /// Blocks until a shutdown signal is received.
    pub async fn wait_for_shutdown(&mut self) {
        loop {
            // Wait for the termination channel to be updated. If it's updated
            // and the value is true, we break out of the loop.
            // We ignore the result here because it's impossible for the sender
            // to be dropped while this instance is alive (it holds its own sender).
            let _ = self.1.changed().await;
            if *self.1.borrow_and_update() {
                break;
            }
        }
    }

    /// Get a stream for the shutdown signal
    pub fn as_stream(&self) -> BroadcastStream<SignerSignal> {
        let (sender, receiver) = tokio::sync::broadcast::channel(5);
        let mut watch_receiver = self.0.subscribe();
        tokio::spawn(async move {
            loop {
                let signal = SignerSignal::Command(SignerCommand::Shutdown);
                let _ = watch_receiver.changed().await;
                if *watch_receiver.borrow_and_update() {
                    let _ = sender.send(signal);
                }
            }
        });
        BroadcastStream::new(receiver)
    }
}
