//! Errors for the bitcoin module

/// Errors for Bitcoin Core
#[derive(Debug, thiserror::Error)]
pub enum BitcoinError {
    /// Received an error in response to getmempooldescendants RPC call
    #[error("bitcoin-core getmempooldescendants error for txid {1}: {0}")]
    GetMempoolDescendants(bitcoincore_rpc::Error, bitcoin::Txid),

    /// Received an error in response to gettxspendingprevout RPC call
    #[error("bitcoin-core gettxspendingprevout error for outpoint: {0}")]
    GetTxSpendingPrevout(#[source] bitcoincore_rpc::Error, bitcoin::OutPoint),

    /// Attempt to fetch a bitcoin blockhash ended in an unexpected error.
    /// This is not triggered if the block is missing.
    #[error("bitcoin-core getblock RPC error for hash {1}: {0}")]
    GetBlock(#[source] bitcoincore_rpc::Error, bitcoin::BlockHash),

    /// Received an error in response to getrawtransaction RPC call
    #[error("failed to retrieve the raw transaction for txid {1} from bitcoin-core. {0}")]
    GetTransaction(#[source] bitcoincore_rpc::Error, bitcoin::Txid),

    /// Error when creating an RPC client to bitcoin-core
    #[error("could not create RPC client to {1}: {0}")]
    RpcClient(#[source] bitcoincore_rpc::Error, String),

    /// Error from the Bitcoin RPC client.
    #[error("bitcoin RPC error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),

    /// Received an error in call to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core for target {1}. {0}")]
    EstimateSmartFee(#[source] bitcoincore_rpc::Error, u16),

    /// Received an error in response to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core in target blocks {1}. errors: {0}")]
    EstimateSmartFeeResponse(String, u16),

    /// Error when breaking out the ZeroMQ message into three parts.
    #[error("bitcoin messages should have a three part layout, received {0} parts")]
    ZmqMessageLayout(usize),

    /// Happens when the bitcoin block hash in the ZeroMQ message is not 32
    /// bytes.
    #[error("block hashes should be 32 bytes, but we received {0} bytes")]
    ZmqBlockHash(usize),

    /// Happens when the ZeroMQ sequence number is not 4 bytes.
    #[error("sequence numbers should be 4 bytes, but we received {0} bytes")]
    ZmqSequenceNumber(usize),

    /// The given message type is unsupported. We attempt to parse what the
    /// topic is but that might fail as well.
    #[error("the message topic {0:?} is unsupported")]
    ZmqUnsupported(Result<String, std::str::Utf8Error>),

    /// Could not connect to bitcoin-core with a zeromq subscription
    /// socket.
    #[error("ZMQ connect error: {0}")]
    ZmqConnect(#[source] zeromq::ZmqError),

    /// Error when receiving a message from to bitcoin-core over zeromq.
    #[error("ZMQ receive error: {0}")]
    ZmqReceive(#[source] zeromq::ZmqError),

    /// Could not subscribe to bitcoin-core with a zeromq subscription
    /// socket.
    #[error("ZMQ subscribe error: {0}")]
    ZmqSubscribe(#[source] zeromq::ZmqError),

    /// This is the error that is returned when validating a bitcoin
    /// transaction.
    #[error("bitcoin validation error: {0}")]
    TransactionValidation(#[from] Box<crate::bitcoin::validation::BitcoinValidationError>),

    /// Parsing the Hex Error
    #[error("could not decode the bitcoin block: {0}")]
    DecodeBlock(#[source] bitcoin::consensus::encode::Error),

    /// Parsing the Hex Error
    #[error("could not decode the bitcoin transaction: {0}")]
    DecodeTransaction(#[source] bitcoin::consensus::encode::Error),
}
