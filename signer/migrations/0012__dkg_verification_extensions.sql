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
        REFERENCES sbtc_signer.bitcoin_blocks (block_hash);

-- Set all of the current `dkg_shares` to `3` (revoked) to start with.
UPDATE sbtc_signer.dkg_shares
SET dkg_shares_status_id = 3;

-- Update the `dkg_shares` which have been included in a
-- `rotate_keys_transactions` to `1` (verified). This update is not fork aware,
-- but at the time of writing there is no forks that should be problematic.
UPDATE sbtc_signer.dkg_shares
SET dkg_shares_status_id = 1
WHERE aggregate_key IN (
    SELECT s.aggregate_key
    FROM sbtc_signer.dkg_shares s
    INNER JOIN sbtc_signer.rotate_keys_transactions rkt 
        ON s.aggregate_key = rkt.aggregate_key
);

-- Make the `dkg_shares_status_id` column `NOT NULL` now that they should all
-- have a value.
ALTER TABLE sbtc_signer.dkg_shares
    ALTER COLUMN dkg_shares_status_id SET NOT NULL;