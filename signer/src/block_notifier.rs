//! This module defines traits for observing and notifying about Bitcoin block headers.
//!
//! The `BlockObserver` trait should be implemented by any component that wants to receive
//! notifications of new block headers. The `BlockNotifier` trait should be implemented by any
//! component that can notify subscribed observers about new block headers.

use std::future::Future;
use std::sync::Arc;

/// The `BlockObserver` trait defines a method to be notified of new block headers.
pub trait BlockObserver: Send + Sync {
    /// Notify the observer of a new block header
    /// This method is called by the `BlockNotifier` whenever a new block header is detected
    fn notify(&self, block_hash: &bitcoin::BlockHash);
}

/// The `BlockNotifier` trait defines methods for subscribing observers and running the notifier.
pub trait BlockNotifier {
    /// Adds the provided observer to the list of observers that will be notified of new block headers
    fn subscribe(&mut self, observer: Arc<dyn BlockObserver>) -> impl Future<Output = ()> + Send;

    /// Run the notifier to start detecting and notifying observers of new block headers
    /// This method should contain the logic to continuously check for new block headers and notify
    /// all subscribed observers
    fn run(&self) -> impl Future<Output = ()> + Send;
}
