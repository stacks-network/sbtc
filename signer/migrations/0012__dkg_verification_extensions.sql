
CREATE TYPE sbtc_signer.dkg_shares_status AS ENUM (
    'unverified',
    'verified',
    'failed'
);

-- Add the new columns to the `dkg_shares` table. We're not adding indexes for
-- now because the table is so small that the overhead likely outweighs the
-- benefits.
ALTER TABLE sbtc_signer.dkg_shares
    ADD COLUMN dkg_shares_status sbtc_signer.dkg_shares_status,
    ADD COLUMN started_at_bitcoin_block_hash BYTEA,
    ADD COLUMN started_at_bitcoin_block_height BIGINT;


UPDATE sbtc_signer.dkg_shares
SET dkg_shares_status = 'unverified';

-- These are all DKG shares associated scriptPubKeys that have been successfully spent
UPDATE sbtc_signer.dkg_shares
SET dkg_shares_status = 'verified'
FROM sbtc_signer.bitcoin_tx_inputs
WHERE sbtc_signer.dkg_shares.script_pubkey = sbtc_signer.bitcoin_tx_inputs.script_pubkey;


-- Fill in the started at bitcoin blockhash and block height. The timestamp
-- of when we write the DKG shares row to the database should correspond
-- with the tenure of the block that started the DKG round.
WITH block_times AS (
    SELECT 
        bb1.block_hash
      , bb1.block_height
      , bb1.created_at
      , bb2.created_at AS ended_at
    FROM sbtc_signer.bitcoin_blocks AS bb2
    JOIN sbtc_signer.bitcoin_blocks AS bb1
      ON bb2.parent_hash = bb1.block_hash
)
UPDATE sbtc_signer.dkg_shares
SET 
    started_at_bitcoin_block_hash = block_times.block_hash
  , started_at_bitcoin_block_height = block_times.block_height
FROM block_times
WHERE sbtc_signer.dkg_shares.created_at >= block_times.created_at
  AND sbtc_signer.dkg_shares.created_at < block_times.ended_at;

-- Make the new column `NOT NULL` now that they should all have a value.
ALTER TABLE sbtc_signer.dkg_shares
    ALTER COLUMN dkg_shares_status SET NOT NULL,
    ALTER COLUMN started_at_bitcoin_block_hash SET NOT NULL,
    ALTER COLUMN started_at_bitcoin_block_height SET NOT NULL;
