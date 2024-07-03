//! Route definitions for the withdrawal endpoint.
use warp::Filter;

use crate::api::models::withdrawal::WithdrawalId;

use super::handlers;

/// Withdrawal routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_withdrawal()
        .or(get_withdrawals())
        .or(create_withdrawal())
        .or(update_withdrawals())
}

/// Get withdrawal endpoint.
fn get_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal" / WithdrawalId)
        .and(warp::get())
        .map(handlers::withdrawal::get_withdrawal)
}

/// Get withdrawals endpoint.
fn get_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::get())
        .and(warp::query())
        .map(handlers::withdrawal::get_withdrawals)
}

/// Create withdrawal endpoint.
fn create_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::post())
        .and(warp::body::json())
        .map(handlers::withdrawal::create_withdrawal)
}

/// Update withdrawals endpoint.
fn update_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::put())
        .and(warp::body::json())
        .map(handlers::withdrawal::update_withdrawals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_get_withdrawal() {
        let api = get_withdrawal();

        let res = request()
            .method("GET")
            .path("/withdrawal/123")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_withdrawals() {
        let api = get_withdrawals();

        let res = request()
            .method("GET")
            .path("/withdrawal?status=pending")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_withdrawal() {
        let api = create_withdrawal();

        let res = request()
            .method("POST")
            .path("/withdrawal")
            .json(&serde_json::json!({
                "requestId": 0,
                "blockHash": "DUMMY_BLOCK_HASH",
                "blockHeight": 0,
                "recipient": "DUMMY_RECIPIENT",
                "amount": 0,
                "parameters": {
                  "maxFee": 0
                }
              }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_withdrawals() {
        let api = update_withdrawals();

        let res = request()
            .method("PUT")
            .path("/withdrawal")
            .json(&serde_json::json!({
                "withdrawals": [],
            }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }
}
