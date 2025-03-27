#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TestContainers(#[from] testcontainers::TestcontainersError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}
