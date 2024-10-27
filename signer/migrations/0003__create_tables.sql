CREATE TYPE sbtc_signer.transaction_type AS ENUM (
    'sbtc_transaction',
    'deposit_request',
    'withdraw_request',
    'deposit_accept',
    'withdraw_accept',
    'withdraw_reject',
    'rotate_keys',
    'donation'
);

CREATE TABLE sbtc_signer.bitcoin_blocks (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    confirms BYTEA[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- Index to serve queries filtering on `parent_hash`. This is commonly used when
-- "walking" the chain in recursive CTE's.
CREATE INDEX ix_bitcoin_blocks_parent_hash ON sbtc_signer.bitcoin_blocks(parent_hash);

CREATE TABLE sbtc_signer.stacks_blocks (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- Index to serve queries filtering on `parent_hash`. This is commonly used when
-- "walking" the chain in recursive CTE's.

CREATE TABLE sbtc_signer.deposit_requests (
    txid BYTEA NOT NULL,
    output_index INTEGER NOT NULL,
    spend_script BYTEA NOT NULL,
    reclaim_script BYTEA NOT NULL,
    recipient TEXT NOT NULL,
    amount BIGINT NOT NULL,
    max_fee BIGINT NOT NULL,
    lock_time BIGINT NOT NULL,
    -- this is an x-only public key, we need column comments
    signer_public_key BYTEA NOT NULL,
    sender_script_pub_keys BYTEA[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (txid, output_index)
);

CREATE TABLE sbtc_signer.deposit_signers (
    txid BYTEA NOT NULL,
    output_index INTEGER NOT NULL,
    signer_pub_key BYTEA NOT NULL,
    is_accepted BOOL NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (txid, output_index, signer_pub_key),
    FOREIGN KEY (txid, output_index) REFERENCES sbtc_signer.deposit_requests(txid, output_index) ON DELETE CASCADE
);
-- Index to serve queries filtering on `signer_pub_key`.
CREATE INDEX ix_deposit_signers_signer_pub_key ON sbtc_signer.deposit_signers(signer_pub_key);

CREATE TABLE sbtc_signer.withdrawal_requests (
    request_id BIGINT NOT NULL,
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    recipient BYTEA NOT NULL,
    amount BIGINT NOT NULL,
    max_fee BIGINT NOT NULL,
    sender_address TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (request_id, block_hash),
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.stacks_blocks(block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.withdrawal_signers (
    request_id BIGINT NOT NULL,
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    signer_pub_key BYTEA NOT NULL,
    is_accepted BOOL NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (request_id, block_hash, signer_pub_key),
    FOREIGN KEY (request_id, block_hash) REFERENCES sbtc_signer.withdrawal_requests(request_id, block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.transactions (
    txid BYTEA PRIMARY KEY,
    tx BYTEA NOT NULL,
    tx_type sbtc_signer.transaction_type NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- Index to serve queries filtering on `tx_type`.
CREATE INDEX ix_transactions_tx_type ON sbtc_signer.transactions(tx_type);
-- Index to serve queries ordering on `created_at`.
CREATE INDEX ix_transactions_created_at ON sbtc_signer.transactions(created_at);

CREATE TABLE sbtc_signer.dkg_shares (
    aggregate_key BYTEA PRIMARY KEY,
    tweaked_aggregate_key BYTEA NOT NULL,
    encrypted_private_shares BYTEA NOT NULL,
    public_shares BYTEA NOT NULL,
    script_pubkey BYTEA NOT NULL,
    signer_set_public_keys BYTEA[] NOT NULL,
    signature_share_threshold INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.bitcoin_transactions (
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    PRIMARY KEY (txid, block_hash),
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE,
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.bitcoin_blocks(block_hash) ON DELETE CASCADE
);
-- Index to serve queries which filter transactions soley on `block_hash`. The
-- PK won't help here as it is a compound key where `block_hash` is a 2nd level.
CREATE INDEX ix_bitcoin_transactions_block_hash ON sbtc_signer.bitcoin_transactions(block_hash);

CREATE TABLE sbtc_signer.stacks_transactions (
    txid BYTEA NOT NULL,
    block_hash BYTEA NOT NULL,
    PRIMARY KEY (txid, block_hash),
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE,
    FOREIGN KEY (block_hash) REFERENCES sbtc_signer.stacks_blocks(block_hash) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.rotate_keys_transactions (
    txid BYTEA PRIMARY KEY,
    aggregate_key BYTEA NOT NULL,
    signer_set BYTEA[] NOT NULL,
    -- This is one of those fields that might not be required in the future
    -- when Schnorr signatures are introduced.
    signatures_required INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE
);

-- TODO: Unused?
CREATE TABLE sbtc_signer.deposit_responses (
    response_txid BYTEA NOT NULL,
    deposit_txid BYTEA NOT NULL,
    deposit_output_index INTEGER NOT NULL
);

-- TODO: Unused?
CREATE TABLE sbtc_signer.withdrawal_responses (
    response_txid BYTEA NOT NULL,
    withdraw_txid BYTEA NOT NULL,
    withdraw_request_id BIGINT NOT NULL
);

CREATE TABLE sbtc_signer.completed_deposit_events (
    id           BIGSERIAL PRIMARY KEY,
    txid         BYTEA   NOT NULL,
    block_hash   BYTEA   NOT NULL,
    amount       BIGINT  NOT NULL,
    bitcoin_txid BYTEA   NOT NULL,
    output_index BIGINT  NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.withdrawal_create_events (
    id           BIGSERIAL PRIMARY KEY,
    txid         BYTEA   NOT NULL,
    block_hash   BYTEA   NOT NULL,
    request_id   BIGINT  NOT NULL,
    amount       BIGINT  NOT NULL,
    sender       VARCHAR NOT NULL,
    recipient    BYTEA   NOT NULL,
    max_fee      BIGINT  NOT NULL,
    block_height BIGINT  NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.withdrawal_accept_events (
    id            BIGSERIAL PRIMARY KEY,
    txid          BYTEA   NOT NULL,
    block_hash    BYTEA   NOT NULL,
    request_id    BIGINT  NOT NULL,
    signer_bitmap BYTEA   NOT NULL,
    bitcoin_txid  BYTEA   NOT NULL,
    output_index  BIGINT  NOT NULL,
    fee           BIGINT  NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.withdrawal_reject_events (
    id            BIGSERIAL PRIMARY KEY,
    txid          BYTEA  NOT NULL,
    block_hash    BYTEA  NOT NULL,
    request_id    BIGINT NOT NULL,
    signer_bitmap BYTEA  NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Represents a combined transaction package which is broadcasted to the Bitcoin
-- network. The transaction package is built up of multiple transactions which
-- are tracked separately in the `sweep_transactions` table. A transaction
-- package may contain the sweeping transactions for both deposit and
-- withdrawal requests.
CREATE TABLE sbtc_signer.sweep_packages (
    -- Internal ID of the package
    id SERIAL PRIMARY KEY,
    -- The Bitcoin block hash at which this package was created.
    created_at_block_hash BYTEA NOT NULL,
    -- The Bitcoin market fee rate at the time this package was created.
    market_fee_rate DOUBLE PRECISION NOT NULL,
    -- Timestamp of when this package was created.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Represents an individual transaction within a broadcasted sweep transaction
-- package. Individual deposit and withdrawal requests reference back to these
-- transactions to keep track of both the overall transaction package as well as
-- the individual Bitcoin transactions they are related to.
CREATE TABLE sbtc_signer.sweep_transactions (
    -- Internal ID of the transaction.
    id BIGSERIAL PRIMARY KEY,
    -- The ID of the grouping transaction package.
    sweep_package_id INTEGER NOT NULL,
    -- The Bitcoin transaction ID of the transaction.
    txid BYTEA NOT NULL,
    -- The signer UTXO being spent in this transaction.
    utxo_txid BYTEA NOT NULL,
    utxo_output_index INTEGER NOT NULL,
    -- The total amount of the transaction.
    amount BIGINT NOT NULL,
    -- The fee paid for the transaction.
    fee BIGINT NOT NULL,
    -- The fee rate in satoshis per vByte used for this transaction.
    fee_rate DOUBLE PRECISION NOT NULL,
    -- The timestamp that the transaction was broadcast at. This should be
    -- set after we know that the transaction was successfully broadcast.
    is_broadcast BOOLEAN NOT NULL,

    FOREIGN KEY (sweep_package_id)
        REFERENCES sbtc_signer.sweep_packages(id)
);

-- Represents a single withdrawal request which has been included in a sweep
-- transaction package. Withdrawal requests have a unique ID so we use that here
-- to reference the withdrawal request together with its Stacks block hash,
-- which can be retrieved from the `withdrawal_requests` table.
CREATE TABLE sbtc_signer.swept_withdrawals (
    -- Internal ID of the swept withdrawal.
    id BIGSERIAL PRIMARY KEY,
    -- References the `packaged_transaction` in which this withdrawal was
    -- included.
    sweep_transaction_id INTEGER NOT NULL,
    -- The index of the sweep output in the packaged transaction.
    output_index INTEGER NOT NULL,
    -- The ID of the withdrawal request, referencing the `withdrawal_requests`
    -- table.
    withdrawal_request_id BIGINT NOT NULL,
    -- The Stacks block hash of the withdrawal request, referencing the
    -- `withdrawal_requests` table.
    withdrawal_request_block_hash BYTEA NOT NULL,

    FOREIGN KEY (sweep_transaction_id) 
        REFERENCES sbtc_signer.sweep_transactions(id),

    FOREIGN KEY (withdrawal_request_id, withdrawal_request_block_hash) 
        REFERENCES sbtc_signer.withdrawal_requests(request_id, block_hash)
);
-- Our main index which will cover searches by 'withdrawal_request_id' and
-- 'withdrawal_request_block_hash' while also restricting the combination to be
-- unique per 'sweep_transaction_id'.
CREATE UNIQUE INDEX uix_swept_req_id_req_block_hash_pkgd_txid 
    ON sbtc_signer.swept_withdrawals(withdrawal_request_id, withdrawal_request_block_hash, sweep_transaction_id);

-- Represents a single deposit request which has been included in a
-- transaction package. Deposit requests do not have a unique ID in the same way
-- as withdrawal requests, so we reference the Bitcoin transaction ID and output
-- index instead, which can be retrieved from the `deposit_requests` table.
CREATE TABLE sbtc_signer.swept_deposits (
    -- Internal ID of the swept deposit.
    id BIGSERIAL PRIMARY KEY,
    -- References the `packaged_transaction` in which this deposit was included.
    sweep_transaction_id INTEGER NOT NULL,
    -- The Bitcoin transaction ID of the deposit request, referencing the
    -- `deposit_requests` table.
    deposit_request_txid BYTEA NOT NULL,
    -- The output index of the deposit request, referencing the
    -- `deposit_requests` table.
    deposit_request_output_index INTEGER NOT NULL,

    FOREIGN KEY (sweep_transaction_id)
        REFERENCES sbtc_signer.sweep_transactions(id),

    FOREIGN KEY (deposit_request_txid, deposit_request_output_index) 
        REFERENCES sbtc_signer.deposit_requests(txid, output_index)
);
-- Our main index which will cover searches by 'deposit_request_txid' and
-- 'deposit_request_output_index', while also restricting the combination to be
-- unique per 'sweep_transaction_id'.
CREATE UNIQUE INDEX uix_swept_deposits_req_txid_req_output_index_pkgd_txid
    ON sbtc_signer.swept_deposits(deposit_request_txid, deposit_request_output_index, sweep_transaction_id);
-- A separate index for the packaged transaction id as it is included last
-- in the compound unique index.
CREATE INDEX ix_swept_deposits_sweep_transaction_id 
    ON sbtc_signer.swept_deposits(sweep_transaction_id);
