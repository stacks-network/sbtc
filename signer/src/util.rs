//! General utilities for the signer.

use std::{cmp::min, future::Future, ops::Deref, sync::{atomic::{AtomicUsize, Ordering}, Arc}};

use std::sync::RwLock;
use url::Url;

use crate::error::Error;

#[mockall::automock]
pub trait TryFromUrl {
    fn try_from_url(url: &Url) -> Result<Self, Error>
    where
        Self: Sized;
}

#[derive(Clone)]
pub struct ApiFallbackClient<T> {
    inner: Arc<InnerApiFallbackClient<T>>
}

impl<T> Deref for ApiFallbackClient<T> {
    type Target = InnerApiFallbackClient<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct InnerApiFallbackClient<T> {
    inner_clients: Vec<T>,
    last_client_index: AtomicUsize,
    retry_count: RwLock<u8>
}

impl<T> InnerApiFallbackClient<T> {
    pub fn with_retry_count(&self, retry_count: u8) -> Result<(), Error> {
        let mut inner = self.retry_count.write();
        inner.
        *inner = retry_count;
        drop(inner);
        self
    }

    /// Get a reference to the current inner API client.
    pub fn get_client(&self) -> &T {
        &self.inner_clients[self.last_client_index.load(Ordering::Relaxed)]
    }

    pub async fn exec<'a, R, E, F>(&'a self, f: impl Fn(&'a T) -> F) -> Result<R, Error> 
    where
        E: std::error::Error + std::fmt::Debug,
        Error: From<E>,
        F: Future<Output = Result<R, E>> + 'a
    {
        let retry_count = *self.retry_count.read();
        for _ in 0..retry_count {
            let client_index = self.last_client_index.load(Ordering::Relaxed);
            let result = f(&self.inner_clients[client_index]).await;

            if result.is_err() {
                self.last_client_index.store((client_index + 1) % self.inner_clients.len(), Ordering::Relaxed);
                continue;
            }

            return result.map_err(Error::from);
        }

        Err(Error::AllFailoverClientsFailed)
    }
}

impl<'a, T> ApiFallbackClient<T>
where 
    T: TryFromUrl + Sync + Send,
{
    /// Create a new API client.
    pub fn new(endpoints: &'a [Url]) -> Result<Self, Error> {
        let clients = endpoints.iter()
            .map(T::try_from_url)
            .collect::<Result<Vec<_>, _>>()?;

        let retry_count = min(3, clients.len());

        let inner = InnerApiFallbackClient {
            inner_clients: clients,
            last_client_index: AtomicUsize::new(0),
            retry_count: RwLock::new(retry_count as u8)
        };

        Ok(Self { 
            inner: Arc::new(inner)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct MockClient {
        should_succeed: bool,
        url: String
    }

    impl MockClient {
        pub async fn call(&self) -> Result<(), Error> {
            if self.should_succeed {
                Ok(())
            } else {
                // Just picked a random error here (which isn't 
                // a AllFailoverClientsFailed)
                Err(Error::CurrentDatabaseName)
            }
        }
    }

    impl TryFromUrl for MockClient {
        fn try_from_url(url: &Url) -> Result<Self, Error> {
            Ok(Self { 
                should_succeed: url.host_str().unwrap() == "ok",
                url: url.to_string()
            })
        }
    }

    #[tokio::test]
    async fn client_doesnt_failover_when_successful() {
        let client = ApiFallbackClient::<MockClient>::new(
            &[Url::parse("http://ok/1").unwrap(), Url::parse("http://fail/2").unwrap()]
        ).unwrap();

        let client1 = &client.inner_clients[0];

        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        let result = client.exec(|client| {
            assert_eq!(client1, client);
            client.call()
        }).await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        let result = client.exec(|client| {
            assert_eq!(client1, client);
            client.call()
            
        }).await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn client_fails_over_when_unsuccessful() {
        let client = ApiFallbackClient::<MockClient>::new(
            &[Url::parse("http://fail/1").unwrap(), Url::parse("http://ok/2").unwrap()]
        ).unwrap();

        // Get references to the inner clients for comparison
        let client1 = &client.inner_clients[0];
        let client2 = &client.inner_clients[1];

        // Ensure the first client is selected
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 0);

        // We'll use this to count how many times the closure is called
        let call_count = AtomicUsize::new(0);

        // Call the client. The first one should fail, triggering a failover,
        // and the second one should succeed.
        let result = client.exec(|client| {
            call_count.fetch_add(1, Ordering::Relaxed);

            // Ensure that we've been given the client we're expecting.
            if call_count.load(Ordering::Relaxed) == 1 {
                assert_eq!(client1, client);
            } else {
                assert_eq!(client2, client);
            }

            // Make the call
            client.call()
        }).await;

        // Ensure the closure was called twice (1 = failed, 2 = succeeded)
        assert_eq!(call_count.load(Ordering::Relaxed), 2);

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 1);

        // Now that the second (success) client is selected, we should be able 
        // to call it without failover.
        let result = client.exec(|client| {
            assert_eq!(client2, client);
            client.call()
        }).await;

        assert!(result.is_ok());
        assert_eq!(client.last_client_index.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn returns_err_when_retries_exhausted_and_no_success() {
        let client = ApiFallbackClient::<MockClient>::new(
            &[
                Url::parse("http://fail/1").unwrap(), Url::parse("http://fail/2").unwrap()]
        ).unwrap();

        // We'll use this to count how many times the closure is called
        let call_count = AtomicUsize::new(0);

        let result = client.exec(|client| {
            call_count.fetch_add(1, Ordering::Relaxed);
            client.call()
        }).await;

        assert_eq!(call_count.load(Ordering::Relaxed), 4);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(), 
            Error::AllFailoverClientsFailed
        ));
    }
}