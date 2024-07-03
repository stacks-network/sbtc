//! Route definitions for the chainstate endpoint.

use warp::Filter;

use super::handlers;

/// Chainstate routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_chainstate()
        .or(set_chainstate())
        .or(update_chainstate())
}

/// Get chainstate endpoint.
fn get_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate" / u64)
        .and(warp::get())
        .map(handlers::chainstate::get_chainstate)
}

/// Set chainstate endpoint.
fn set_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::post())
        .and(warp::body::json())
        .map(handlers::chainstate::set_chainstate)
}

/// Update chainstate endpoint.
fn update_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::put())
        .and(warp::body::json())
        .map(handlers::chainstate::update_chainstate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_get_chainstate() {
        let api = get_chainstate();

        let res = request()
            .method("GET")
            .path("/chainstate/123")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_set_chainstate() {
        let api = set_chainstate();

        let res = request()
            .method("POST")
            .path("/chainstate")
            .json(&serde_json::json!({
                "blockHeight": 0,
                "blockHash": "DUMMY_BLOCK_HASH"
            }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_chainstate() {
        let api = update_chainstate();

        let res = request()
            .method("PUT")
            .path("/chainstate")
            .json(&serde_json::json!({
                "blockHeight": 0,
                "blockHash": "DUMMY_BLOCK_HASH"
            }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }
}
