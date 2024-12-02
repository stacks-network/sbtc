CREATE OR REPLACE FUNCTION sbtc_signer.reverse_bytea(input BYTEA) RETURNS BYTEA AS $$
BEGIN
    RETURN decode(
        string_agg(
            reverse(b[1]), ''
        ),
        'hex'
    )
    FROM regexp_matches(reverse(encode(input, 'hex')), '..', 'g') AS b;
END;
$$ LANGUAGE plpgsql;

-- Step 2: Add a new column to store the reversed sweep_block_hash
ALTER TABLE sbtc_signer.completed_deposit_events
ADD COLUMN sweep_block_hash_reversed BYTEA;

-- Step 3: Update the new column with the reversed values of sweep_block_hash
UPDATE sbtc_signer.completed_deposit_events
SET sweep_block_hash_reversed = sbtc_signer.reverse_bytea(sweep_block_hash);

-- Step 4: Drop the original sweep_block_hash column
ALTER TABLE sbtc_signer.completed_deposit_events
DROP COLUMN sweep_block_hash;

-- Step 5: Rename the new column to sweep_block_hash
ALTER TABLE sbtc_signer.completed_deposit_events
RENAME COLUMN sweep_block_hash_reversed TO sweep_block_hash;