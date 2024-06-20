CREATE TYPE sbtc_signer.transaction_type AS ENUM (
   'sbtc_transaction',
   'deposit_request',
   'withdraw_request',
   'deposit_accept',
   'withdraw_accept',
   'withdraw_reject',
   'update_signer_set',
   'set_aggregate_key'
);

CREATE TABLE sbtc_signer.bitcoin_blocks (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    confirms BYTEA,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sbtc_signer.stacks_blocks (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sbtc_signer.deposit_requests (
    txid BYTEA NOT NULL,
    output_index INTEGER NOT NULL,
    spend_script BYTEA NOT NULL,
    reclaim_script BYTEA NOT NULL,
    recipient TEXT NOT NULL,
    amount BIGINT NOT NULL,
    max_fee BIGINT NOT NULL,
    sender_addresses TEXT[],
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (txid, output_index)
);

CREATE TABLE sbtc_signer.deposit_signers (
    txid BYTEA NOT NULL,
    output_index INTEGER NOT NULL,
    signer_pub_key BYTEA NOT NULL,
    is_accepted BOOL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (txid, output_index, signer_pub_key),
    FOREIGN KEY (txid, output_index) REFERENCES sbtc_signer.deposit_requests(txid, output_index) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.withdraw_requests (
    request_id INTEGER NOT NULL,
    block_hash BYTEA NOT NULL,
    recipient BYTEA NOT NULL,
    amount BIGINT NOT NULL,
    max_fee BIGINT NOT NULL,
    sender_address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (request_id, block_hash),
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.stacks_blocks(block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.withdraw_signers (
    request_id INTEGER NOT NULL,
    block_hash BYTEA NOT NULL,
    signer_pub_key BYTEA NOT NULL,
    is_accepted BOOL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (request_id, block_hash, signer_pub_key),
    FOREIGN KEY (request_id, block_hash) REFERENCES sbtc_signer.withdraw_requests(request_id, block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.transactions (
    txid BYTEA PRIMARY KEY,
    tx BYTEA NOT NULL,
    tx_type sbtc_signer.transaction_type NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sbtc_signer.dkg_shares (
    aggregate_key BYTEA PRIMARY KEY,
    tweaked_aggregate_key BYTEA NOT NULL,
    encrypted_shares BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sbtc_signer.coordinator_broadcasts (
    broadcast_id SERIAL PRIMARY KEY,
    txid BYTEA NOT NULL,
    broadcast_block_height INTEGER NOT NULL,
    market_fee_rate INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.bitcoin_transactions (
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    PRIMARY KEY (txid, block_hash),
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE,
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.bitcoin_blocks(block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.stacks_transactions (
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    PRIMARY KEY (txid, block_hash),
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE,
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.stacks_blocks(block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.aggregate_key_transactions (
    txid BYTEA NOT NULL,
    aggregate_key BYTEA NOT NULL,
    PRIMARY KEY (txid, aggregate_key),
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE,
    FOREIGN KEY (aggregate_key) REFERENCES sbtc_signer.dkg_shares(aggregate_key) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.deposit_responses (
    response_txid BYTEA NOT NULL,
    deposit_txid BYTEA NOT NULL,
    deposit_output_index INTEGER NOT NULL
);

CREATE TABLE sbtc_signer.withdraw_responses (
    response_txid BYTEA NOT NULL,
    withdraw_txid BYTEA NOT NULL,
    withdraw_request_id INTEGER NOT NULL
);
