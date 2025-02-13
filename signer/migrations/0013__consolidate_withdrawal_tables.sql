
-- We cannot guarantee that we have the stacks block in the database by the time we
-- have received a withdrawal request and are ready to write it into the database.
-- So we need to drop the constraint.
ALTER TABLE sbtc_signer.withdrawal_requests
    DROP CONSTRAINT withdrawal_requests_block_hash_fkey;

-- The block height of the bitcoin blockchain when the stacks
-- transaction that emitted this event was executed.
ALTER TABLE sbtc_signer.withdrawal_requests
    ADD COLUMN block_height BIGINT NOT NULL;
