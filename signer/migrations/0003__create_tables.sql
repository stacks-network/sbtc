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
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);
-- Index to serve queries filtering on `parent_hash`. This is commonly used when
-- "walking" the chain in recursive CTE's.
CREATE INDEX ix_bitcoin_blocks_parent_hash ON sbtc_signer.bitcoin_blocks(parent_hash);

CREATE TABLE sbtc_signer.stacks_blocks (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    bitcoin_anchor BYTEA NOT NULL,
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
    signers_public_key BYTEA NOT NULL,
    sender_script_pub_keys BYTEA[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (txid, output_index)
);

CREATE TABLE sbtc_signer.deposit_signers (
    txid BYTEA NOT NULL,
    output_index INTEGER NOT NULL,
    signer_pub_key BYTEA NOT NULL,
    -- this specifies whether the signer is a part of the signer set
    -- associated with the deposit_request.signers_public_key
    can_sign BOOLEAN NOT NULL,
    can_accept BOOLEAN NOT NULL,
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
    is_accepted BOOLEAN NOT NULL,
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
    txid            BYTEA PRIMARY KEY,
    address         TEXT    NOT NULL,
    aggregate_key   BYTEA   NOT NULL,
    signer_set      BYTEA[] NOT NULL,
    -- This is one of those fields that might not be required in the future
    -- when Schnorr signatures are introduced.
    signatures_required INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (txid) REFERENCES sbtc_signer.transactions(txid) ON DELETE CASCADE
);

CREATE TABLE sbtc_signer.completed_deposit_events (
    id                  BIGSERIAL PRIMARY KEY,
    txid                BYTEA   NOT NULL,
    block_hash          BYTEA   NOT NULL,
    amount              BIGINT  NOT NULL,
    bitcoin_txid        BYTEA   NOT NULL,
    output_index        BIGINT  NOT NULL,
    sweep_block_hash    BYTEA   NOT NULL,
    sweep_block_height  BIGINT  NOT NULL,
    sweep_txid          BYTEA   NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
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
    id                  BIGSERIAL PRIMARY KEY,
    txid                BYTEA   NOT NULL,
    block_hash          BYTEA   NOT NULL,
    request_id          BIGINT  NOT NULL,
    signer_bitmap       BYTEA   NOT NULL,
    bitcoin_txid        BYTEA   NOT NULL,
    output_index        BIGINT  NOT NULL,
    fee                 BIGINT  NOT NULL,
    sweep_block_hash    BYTEA   NOT NULL,
    sweep_block_height  BIGINT  NOT NULL,
    sweep_txid          BYTEA   NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.withdrawal_reject_events (
    id            BIGSERIAL PRIMARY KEY,
    txid          BYTEA  NOT NULL,
    block_hash    BYTEA  NOT NULL,
    request_id    BIGINT NOT NULL,
    signer_bitmap BYTEA  NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Represents an individual transaction within a broadcasted sweep transaction
-- package. Individual deposit and withdrawal requests reference back to these
-- transactions to keep track of both the overall transaction package as well as
-- the individual Bitcoin transactions they are related to.
CREATE TABLE sbtc_signer.sweep_transactions (
    -- The Bitcoin transaction ID of the transaction.
    txid BYTEA PRIMARY KEY NOT NULL,
    -- The signer UTXO being spent in this transaction.
    signer_prevout_txid BYTEA NOT NULL,
    signer_prevout_output_index INTEGER NOT NULL,
    signer_prevout_amount BIGINT NOT NULL,
    signer_prevout_script_pubkey BYTEA NOT NULL,
    -- The total _output_ amount of the transaction.
    amount BIGINT NOT NULL,
    -- The fee paid for the transaction.
    fee BIGINT NOT NULL,
    -- The Bitcoin "virtual size" of the transaction.
    vsize INTEGER NOT NULL,
    -- The Bitcoin block hash at which this package was created.
    created_at_block_hash BYTEA NOT NULL,
    -- The Bitcoin market fee rate at the time this package was created.
    market_fee_rate DOUBLE PRECISION NOT NULL,
    -- Timestamp of when this package was created.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TYPE sbtc_signer.output_type AS ENUM (
    'signers_output',
    'signers_op_return',
    'withdrawal',
    'donation'
);

-- A table for all bitcoin transaction outputs relevant for the signers.
CREATE TABLE sbtc_signer.bitcoin_tx_outputs (
    -- the transaction ID that created the output
    txid BYTEA NOT NULL,
    -- The index of the output in the transaction.
    output_index INTEGER NOT NULL,
    -- The amount locked in the output,
    amount BIGINT NOT NULL,
    -- The scriptPubKey of the output
    script_pubkey BYTEA NOT NULL,
    -- The type of UTXO this is
    output_type sbtc_signer.output_type NOT NULL,
    -- a timestamp of when this record was created in the database.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (txid, output_index)
);

CREATE TYPE sbtc_signer.prevout_type AS ENUM (
    'signers_input',
    'deposit'
);

-- A table for all bitcoin transaction inputs spent by the signers.
CREATE TABLE sbtc_signer.bitcoin_tx_inputs (
    -- the ID of the transaction spending the transaction output
    txid BYTEA NOT NULL,
    -- The ID of the transaction that created the TXO being spent.
    prevout_txid BYTEA NOT NULL,
    -- The index of the prevout in the transaction that created the TXO.
    prevout_output_index INTEGER NOT NULL,
    -- The amount of the prevout being spent.
    amount BIGINT NOT NULL,
    -- The scriptPubKey of the prevout
    script_pubkey BYTEA NOT NULL,
    -- The type of UTXO this is
    prevout_type sbtc_signer.prevout_type NOT NULL,
    -- a timestamp of when this record was created in the database.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (txid, prevout_txid, prevout_output_index)
);

-- Represents a single withdrawal request which has been included in a sweep
-- transaction package. Withdrawal requests have a unique ID so we use that here
-- to reference the withdrawal request together with its Stacks block hash,
-- which can be retrieved from the `withdrawal_requests` table.
CREATE TABLE sbtc_signer.swept_withdrawals (
    sweep_transaction_txid BYTEA NOT NULL,
    -- The index of the sweep output in the sweep transaction.
    output_index INTEGER NOT NULL,
    -- The ID of the withdrawal request, referencing the `withdrawal_requests`
    -- table.
    withdrawal_request_id BIGINT NOT NULL,
    -- The Stacks block hash of the withdrawal request, referencing the
    -- `withdrawal_requests` table.
    withdrawal_request_block_hash BYTEA NOT NULL,

    PRIMARY KEY (sweep_transaction_txid, output_index),

    FOREIGN KEY (sweep_transaction_txid) 
        REFERENCES sbtc_signer.sweep_transactions(txid),

    FOREIGN KEY (withdrawal_request_id, withdrawal_request_block_hash) 
        REFERENCES sbtc_signer.withdrawal_requests(request_id, block_hash)
);
-- Our main index which will cover searches by 'withdrawal_request_id' and
-- 'withdrawal_request_block_hash' while also restricting the combination to be
-- unique per 'sweep_transaction_id'.
CREATE UNIQUE INDEX uix_swept_req_id_req_block_hash_pkgd_txid 
    ON sbtc_signer.swept_withdrawals(withdrawal_request_id, withdrawal_request_block_hash, sweep_transaction_txid);

-- Represents a single deposit request which has been included in a
-- transaction package. Deposit requests do not have a unique ID in the same way
-- as withdrawal requests, so we reference the Bitcoin transaction ID and output
-- index instead, which can be retrieved from the `deposit_requests` table.
CREATE TABLE sbtc_signer.swept_deposits (
    -- References the `packaged_transaction` in which this deposit was included.
    sweep_transaction_txid BYTEA NOT NULL,
    -- The index of the sweep input in the sweep transaction.
    input_index INTEGER NOT NULL,
    -- The Bitcoin transaction ID of the deposit request, referencing the
    -- `deposit_requests` table.
    deposit_request_txid BYTEA NOT NULL,
    -- The output index of the deposit request, referencing the
    -- `deposit_requests` table.
    deposit_request_output_index INTEGER NOT NULL,

    PRIMARY KEY (sweep_transaction_txid, input_index),

    FOREIGN KEY (sweep_transaction_txid)
        REFERENCES sbtc_signer.sweep_transactions(txid),

    FOREIGN KEY (deposit_request_txid, deposit_request_output_index) 
        REFERENCES sbtc_signer.deposit_requests(txid, output_index)
);
-- Our main index which will cover searches by 'deposit_request_txid' and
-- 'deposit_request_output_index', while also restricting the combination to be
-- unique per 'sweep_transaction_id'.
CREATE UNIQUE INDEX uix_swept_deposits_req_txid_req_output_index_pkgd_txid
    ON sbtc_signer.swept_deposits(deposit_request_txid, deposit_request_output_index, sweep_transaction_txid);
