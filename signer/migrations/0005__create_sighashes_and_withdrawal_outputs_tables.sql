
CREATE TABLE sbtc_signer.bitcoin_tx_sighashes (
    -- The sighash associated with the prevout.
    sighash BYTEA PRIMARY KEY,
    -- The transaction ID of the bitcoin transaction.
    txid BYTEA NOT NULL,
    -- The bitcoin chain tip when the sign request was submitted.
    chain_tip BYTEA NOT NULL,
    -- The txid that created the output that is being spent.
    prevout_txid BYTEA NOT NULL,
    -- The index of the vout from the transaction that created this output.
    prevout_output_index INTEGER NOT NULL,
    -- The type of prevout that we are dealing with.
    prevout_type sbtc_signer.prevout_type NOT NULL,
    -- The result of validation that was done on the input.
    validation_result TEXT NOT NULL,
    -- Whether the transaction is valid.
    is_valid_tx BOOLEAN NOT NULL,
    -- Whether the signer will participate in a signing round for the sighash.
    will_sign BOOLEAN NOT NULL,
    -- a timestamp of when this record was created in the database.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE sbtc_signer.bitcoin_withdrawals_outputs (
    -- The ID of the bitcoin transaction that includes this withdrawal output.
    bitcoin_txid BYTEA NOT NULL,
    -- The bitcoin chain tip when the sign request was submitted. This is
    -- used to ensure that we do not sign for more than one transaction
    -- containing inputs
    bitcoin_chain_tip BYTEA NOT NULL,
    -- The index of the referenced output in the transaction's outputs.
    output_index INTEGER NOT NULL,
    -- The ID of the stacks transaction lead to the creation of the withdrawal request.
    request_id BIGINT NOT NULL,
    -- The stacks transaction ID that lead to the creation of the withdrawal request.
    stacks_txid BYTEA NOT NULL,
    -- Stacks block ID of the block that includes the associated transaction.
    stacks_block_hash BYTEA NOT NULL,
    -- The outcome of validation of the withdrawal request.
    validation_result TEXT NOT NULL,
    -- Whether the transaction is valid.
    is_valid_tx BOOLEAN NOT NULL,
    -- a timestamp of when this record was created in the database.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    -- The specific outpoint for the withdrawal.
    PRIMARY KEY (bitcoin_txid, output_index)
);
