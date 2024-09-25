//! General utilities for the signer.

use std::{
    cmp::min,
    future::Future,
    ops::Deref,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
};

use thiserror::Error;

use crate::error::Error;

/// This is the default minimum number of _retries_ that the fallback client
/// will attempt. A retry count of 2 means that the client will attempt to
/// execute the closure _3 times_ before giving up (i.e. the initial attempt,
/// plus two retries).
const DEFAULT_MINIMUM_RETRY_COUNT: usize = 2;

/// Error variants for the fallback client.
#[derive(Debug, Error)]
pub enum FallbackClientError {
    /// All failover clients failed within the retry limit
    #[error(
        "all fallback clients failed to execute the request within the allotted number of retries"
    )]
    AllClientsFailed,

    /// No endpoints were provided
    #[error("no endpoints were provided")]
    NoEndpoints,
}

/// A fallback-wrapper that can failover to other clients if the current client fails.
pub struct ApiFallbackClient<T> {
    inner: Arc<InnerApiFallbackClient<T>>,
}

impl<T> Deref for ApiFallbackClient<T> {
    type Target = InnerApiFallbackClient<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> Clone for ApiFallbackClient<T> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

/// Inner implementation of the fallback client.
pub struct InnerApiFallbackClient<T> {
    inner_clients: Vec<T>,
    last_client_index: AtomicUsize,
    retry_count: AtomicU8,
}

impl<T> InnerApiFallbackClient<T> {
    /// Set the number of retries to perform before giving up.
    ///
    /// **Note:** the actual number of attempts will be one more than the retry
    /// count, i.e. _initial attempt(1) + retry count(2) = 3 attempts_.
    ///
    /// The default minimum retry count is defined in [`DEFAULT_MINIMUM_RETRY_COUNT`].
    pub fn set_retry_count(&self, retry_count: u8) {
        self.retry_count.store(retry_count, Ordering::Relaxed);
    }

    /// Get a reference to the current inner API client.
    pub fn get_client(&self) -> &T {
        &self.inner_clients[self.last_client_index.load(Ordering::Relaxed)]
    }

    /// Execute a closure on the current client, falling back to remaining clients
    /// if the closure returns an error.
    ///
    /// For more information on the number of attempts made, see [`Self::set_retry_count`].
    pub async fn exec<'a, R, E, F>(&'a self, f: impl Fn(&'a T) -> F) -> Result<R, Error>
    where
        E: std::error::Error + std::fmt::Debug,
        E: Into<Error>,
        F: Future<Output = Result<R, E>> + 'a,
    {
        let retry_count = self.retry_count.load(Ordering::Relaxed);
        for i in 0..=retry_count {
            let client_index = self.last_client_index.load(Ordering::Relaxed);
            let result = f(&self.inner_clients[client_index]).await;

            if let Err(error) = result {
                tracing::warn!(%error, retry_num=i, max_retries=retry_count, "failover client call failed");
                self.last_client_index.store(
                    (client_index + 1) % self.inner_clients.len(),
                    Ordering::Relaxed,
                );
                continue;
            }

            return result.map_err(Into::into);
        }

        Err(FallbackClientError::AllClientsFailed.into())
    }
}

impl<T> ApiFallbackClient<T> {
    /// Create a new fallback client from a list of clients.
    pub fn new(clients: Vec<T>) -> Result<Self, FallbackClientError> {
        if clients.is_empty() {
            return Err(FallbackClientError::NoEndpoints);
        }

        let retry_count = min(DEFAULT_MINIMUM_RETRY_COUNT, clients.len());

        let inner = InnerApiFallbackClient {
            inner_clients: clients,
            last_client_index: AtomicUsize::new(0),
            retry_count: AtomicU8::new(retry_count as u8),
        };

        Ok(Self { inner: Arc::new(inner) })
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct MockClient {
        should_succeed: bool,
        url: String,
    }

    impl MockClient {
        pub async fn call(&self) -> Result<(), Error> {
            if self.should_succeed {
                Ok(())
            } else {
                // Just picked a random error here (which isn't
                // a AllFailoverClientsFailed)
                Err(Error::Encryption)
            }
        }
    }

    impl From<Url> for MockClient {
        fn from(url: Url) -> Self {
            Self {
                should_succeed: url.host_str().unwrap() == "ok",
                url: url.to_string(),
            }
        }
    }

    impl From<&[Url]> for ApiFallbackClient<MockClient> {
        fn from(urls: &[Url]) -> Self {
            let clients = urls
                .iter()
                .map(|url| MockClient::from(url.clone()))
                .collect::<Vec<_>>();

            Self::new(clients).unwrap()
        }
    }

    #[tokio::test]
    async fn client_doesnt_failover_when_successful() {
        let client = ApiFallbackClient::<MockClient>::from(
            &[
                Url::parse("http://ok/1").unwrap(),
                Url::parse("http://fail/2").unwrap(),
            ][..],
        );

        let client1 = &client.inner_clients[0];

        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        let result = client
            .exec(|client| {
                assert_eq!(client1, client);
                client.call()
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        let result = client
            .exec(|client| {
                assert_eq!(client1, client);
                client.call()
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn client_fails_over_when_unsuccessful() {
        let client = ApiFallbackClient::<MockClient>::from(
            &[
                Url::parse("http://fail/1").unwrap(),
                Url::parse("http://ok/2").unwrap(),
            ][..],
        );

        // Get references to the inner clients for comparison
        let client1 = &client.inner_clients[0];
        let client2 = &client.inner_clients[1];

        // Ensure the first client is selected
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        // We'll use this to count how many times the closure is called
        let call_count = AtomicUsize::new(0);

        // Call the client. The first one should fail, triggering a failover,
        // and the second one should succeed.
        let result = client
            .exec(|client| {
                call_count.fetch_add(1, Ordering::Relaxed);

                // Ensure that we've been given the client we're expecting.
                if call_count.load(Ordering::Relaxed) == 1 {
                    assert_eq!(client1, client);
                } else {
                    assert_eq!(client2, client);
                }

                // Make the call
                client.call()
            })
            .await;

        // Ensure the closure was called twice (1 = failed, 2 = succeeded)
        assert_eq!(call_count.load(Ordering::Relaxed), 2);

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 1);

        // Now that the second (success) client is selected, we should be able
        // to call it without failover.
        let result = client
            .exec(|client| {
                assert_eq!(client2, client);
                client.call()
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retry_count_0_tries_exactly_once() {
        let client = ApiFallbackClient::<MockClient>::from(
            &[
                Url::parse("http://fail/1").unwrap(),
                Url::parse("http://fail/2").unwrap(),
            ][..],
        );
        client.set_retry_count(0);

        // We'll use this to count how many times the closure is called
        let call_count = AtomicUsize::new(0);

        let _ = client
            .exec(|client| {
                call_count.fetch_add(1, Ordering::Relaxed);
                client.call()
            })
            .await;

        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn returns_err_when_retries_exhausted_and_no_success() {
        let client = ApiFallbackClient::<MockClient>::from(
            &[
                Url::parse("http://fail/1").unwrap(),
                Url::parse("http://fail/2").unwrap(),
            ][..],
        );
        client.set_retry_count(4);

        // We'll use this to count how many times the closure is called
        let call_count = AtomicUsize::new(0);

        let result = client
            .exec(|client| {
                call_count.fetch_add(1, Ordering::Relaxed);
                client.call()
            })
            .await;

        assert_eq!(call_count.load(Ordering::Relaxed), 5);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::FallbackClient(FallbackClientError::AllClientsFailed)
        ));
    }
}
