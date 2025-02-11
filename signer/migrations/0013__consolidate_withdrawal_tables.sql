
DROP TABLE sbtc_signer.withdrawal_create_events;

-- Remove the FK `block_hash` REFERENCES `stacks_blocks(block_hash)` constraint.
ALTER TABLE sbtc_signer.withdrawal_requests
    DROP CONSTRAINT withdrawal_requests_block_hash_fkey;

-- Add the new column to the `withdrawal_requests` table.
ALTER TABLE sbtc_signer.withdrawal_requests
    ADD COLUMN block_height BIGINT NOT NULL;
