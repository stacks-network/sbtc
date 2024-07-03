//! Route definitions for the deposit endpoint.
use warp::Filter;

use crate::api::models::common::*;

use super::handlers;

/// Deposit routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_deposit()
        .or(get_deposits_for_transaction())
        .or(get_deposits())
        .or(create_deposit())
        .or(update_deposits())
}

/// Get deposit endpoint.
fn get_deposit() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit" / BitcoinTransactionId / BitcoinTransactionOutputIndex )
        .and(warp::get())
        .map(handlers::deposit::get_deposit)
}

/// Get deposits for transaction endpoint.
fn get_deposits_for_transaction() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit" / BitcoinTransactionId)
        .and(warp::get())
        .and(warp::query())
        .map(handlers::deposit::get_deposits_for_transaction)
}

/// Get deposits endpoint.
fn get_deposits() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::get())
        .and(warp::query())
        .map(handlers::deposit::get_deposits)
}

/// Create deposit endpoint.
fn create_deposit() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::post())
        .and(warp::body::json())
        .map(handlers::deposit::create_deposit)
}

/// Update deposits endpoint.
fn update_deposits() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::post())
        .and(warp::body::json())
        .map(handlers::deposit::update_deposits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_get_deposit() {
        let api = get_deposit();

        let res = request()
            .method("GET")
            .path("/deposit/some_tx_id/0")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_deposits_for_transaction() {
        let api = get_deposits_for_transaction();

        let res = request()
            .method("GET")
            .path("/deposit/some_tx_id")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_deposits() {
        let api = get_deposits();

        let res = request()
            .method("GET")
            .path("/deposit?status=pending")
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_deposit() {
        let api = create_deposit();

        let res = request()
            .method("POST")
            .path("/deposit")
            .json(&serde_json::json!({
                "bitcoinTxid": "DUMMY_ID",
                "bitcoinTxOutputIndex": 231,
                "reclaim": "DUMMY_RECLAIM",
                "deposit": "DUMMY_DEPOSIT",
            }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_deposits() {
        let api = update_deposits();

        let res = request()
            .method("POST")
            .path("/deposit")
            .json(&serde_json::json!({
                "deposits": [],
            }))
            .reply(&api)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
    }
}
