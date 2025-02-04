-- Enum table for DKG shares status
CREATE TABLE sbtc_signer.dkg_shares_status (
    -- The id of the status, not auto-incremented as we want to control the values.
    id INTEGER PRIMARY KEY,
    -- The name of the status.
    key TEXT NOT NULL,
    -- Brief description of what the status means.
    description TEXT NOT NULL
);

-- Insert the initial entries.
INSERT INTO sbtc_signer.dkg_shares_status (id, key, description) VALUES
    (0, 'PENDING', 'DKG round successful, pending verification via signing round'),
    (1, 'VERIFIED', 'Successfully verified via signing round'),
    (2, 'KEY_REVOKED', 'The DKG key has been revoked and should not be used');

-- Add the new columns to the `dkg_shares` table. We're not adding indexes for
-- now because the table is so small that the overhead likely outweighs the
-- benefits.
ALTER TABLE sbtc_signer.dkg_shares
    -- Contains the current 
    ADD COLUMN dkg_shares_status_id INTEGER DEFAULT 0 REFERENCES sbtc_signer.dkg_shares_status (id),
    ADD COLUMN verified_at_bitcoin_block_hash BYTEA DEFAULT NULL,
    ADD COLUMN verified_at_bitcoin_block_height BIGINT DEFAULT NULL,
    ADD CONSTRAINT fk_dkg_shares_bitcoin_block_hash
        FOREIGN KEY (verified_at_bitcoin_block_hash)
        REFERENCES sbtc_signer.bitcoin_blocks (block_hash),
    ADD CONSTRAINT chk_verified_at
        CHECK (
            (dkg_shares_status_id = 1 AND verified_at_bitcoin_block_hash IS NOT NULL AND verified_at_bitcoin_block_height IS NOT NULL) 
            OR (dkg_shares_status_id <> 1 AND verified_at_bitcoin_block_hash IS NULL AND verified_at_bitcoin_block_height IS NULL)
        );

-- Set all of the current `dkg_shares` to `3` (revoked) to start with. Confirmed
-- DKG shares will be updated to `1` (verified) in the next step.
UPDATE sbtc_signer.dkg_shares
SET dkg_shares_status_id = 3;

-- Update the `dkg_shares` which have been included in a
-- `rotate_keys_transactions` which can also be tied to a bitcoin block to `1`
-- (verified) and set the `verified_at_*` fields to the bitcoin block
-- hash/height corresponding to the block where these were anchored.
--
-- This update is not fork aware, but at the time of writing there is no forks
-- that should be problematic (i.e. we shouldn't have any rotate-keys events
-- that have been orphaned).
WITH updated_shares AS (
    SELECT 
        s.aggregate_key,
        bb.block_hash AS verified_at_bitcoin_block_hash,
        bb.block_height AS verified_at_bitcoin_block_height
    FROM sbtc_signer.dkg_shares s
    INNER JOIN sbtc_signer.rotate_keys_transactions rkt 
        ON s.aggregate_key = rkt.aggregate_key
    INNER JOIN sbtc_signer.stacks_transactions stx
        ON rkt.txid = stx.txid
    INNER JOIN sbtc_signer.stacks_blocks sb
        ON stx.block_hash = sb.block_hash
    INNER JOIN sbtc_signer.bitcoin_blocks bb
        ON sb.bitcoin_anchor = bb.block_hash
    ORDER BY bb.block_height DESC
    LIMIT 1
)
UPDATE sbtc_signer.dkg_shares
SET 
    dkg_shares_status_id = 1,
    verified_at_bitcoin_block_hash = updated_shares.verified_at_bitcoin_block_hash,
    verified_at_bitcoin_block_height = updated_shares.verified_at_bitcoin_block_height
FROM updated_shares
WHERE sbtc_signer.dkg_shares.aggregate_key = updated_shares.aggregate_key;

-- Make the `dkg_shares_status_id` column `NOT NULL` now that they should all
-- have a value.
ALTER TABLE sbtc_signer.dkg_shares
    ALTER COLUMN dkg_shares_status_id SET NOT NULL;