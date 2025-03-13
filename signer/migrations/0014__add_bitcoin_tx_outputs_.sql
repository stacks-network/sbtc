-- A table for all bitcoin transaction outputs related to withdrawals.
CREATE TABLE sbtc_signer.bitcoin_withdrawal_tx_outputs (
    -- the transaction ID that created the output
    txid BYTEA NOT NULL,
    -- The index of the output in the transaction.
    output_index INTEGER NOT NULL,
    -- The ID of the withdrawal request.
    request_id BIGINT NOT NULL,
    -- a timestamp of when this record was created in the database.
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    PRIMARY KEY (txid, output_index),
    FOREIGN KEY (txid, output_index)
        REFERENCES sbtc_signer.bitcoin_tx_outputs(txid, output_index)
);
