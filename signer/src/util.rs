//! General utilities for the signer.

use std::{future::Future, ops::Deref, sync::{atomic::{AtomicUsize, Ordering}, Arc}};

use url::Url;

use crate::error::Error;

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
    inner_clients: Arc<Vec<T>>,
    last_client_index: AtomicUsize,
}

impl<T> InnerApiFallbackClient<T> {
    /// Get a reference to the current inner API client.
    pub fn get_client(&self) -> &T {
        &self.inner_clients[self.last_client_index.load(Ordering::Relaxed)]
    }

    pub async fn exec<'a, R, E, F>(&'a self, f: impl Fn(&'a T) -> F) -> Result<R, E> 
    where 
        F: Future<Output = Result<R, E>> + 'a
    {
        let client_index = self.last_client_index.load(Ordering::Relaxed);
        let result = f(&self.inner_clients[client_index]).await;

        if result.is_err() {
            self.last_client_index.store((client_index + 1) % self.inner_clients.len(), Ordering::Relaxed);
        }

        result
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

        let inner = InnerApiFallbackClient {
            inner_clients: Arc::new(clients),
            last_client_index: AtomicUsize::new(0),
        };

        Ok(Self { 
            inner: Arc::new(inner)
        })
    }
}