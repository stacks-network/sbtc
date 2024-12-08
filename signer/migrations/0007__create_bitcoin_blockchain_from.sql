-- Table-Valued Function (TVF) for fetching a Bitcoin blockchain from a given
-- block hash, only fetching blocks down to a specific height.
--
-- - chain_tip: The block hash to start the blockchain from ("chain tip").
-- - min_block_height: The minimum height of all blocks that are returned.
CREATE FUNCTION sbtc_signer.bitcoin_blockchain_until (
    chain_tip BYTEA,
    min_block_height BIGINT
)
RETURNS TABLE (
    block_hash BYTEA,
    parent_hash BYTEA,
    block_height BIGINT
) 
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE blockchain AS (
        SELECT
            blocks.block_hash
          , blocks.parent_hash
          , blocks.block_height
        FROM sbtc_signer.bitcoin_blocks as blocks
        WHERE blocks.block_hash = chain_tip

        UNION ALL

        SELECT
            parent.block_hash
          , parent.parent_hash
          , parent.block_height
        FROM sbtc_signer.bitcoin_blocks AS parent
        JOIN blockchain AS last
          ON parent.block_hash = last.parent_hash
        WHERE last.block_height > min_block_height
    )
    SELECT
        blocks.block_hash
      , blocks.parent_hash
      , blocks.block_height
    FROM blockchain as blocks;
END;
$$ LANGUAGE plpgsql;
