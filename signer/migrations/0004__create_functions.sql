-- Table-Valued Function (TVF) for fetching a Bitcoin blockchain from a given
-- block hash, only looking back the `max_depth` number of blocks. The most
-- common use case is to fetch the blockchain from the canonical chain tip.
--
-- - chain_tip: The block hash to start the blockchain from ("chain tip").
-- - max_depth: The maximum depth of the blockchain to fetch.
CREATE FUNCTION sbtc_signer.bitcoin_blockchain_of (
    chain_tip BYTEA,
    max_depth INT
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
            blocks.block_hash,
            blocks.parent_hash,
            blocks.block_height,
            1 AS depth
        FROM sbtc_signer.bitcoin_blocks as blocks
        WHERE blocks.block_hash = chain_tip

        UNION ALL

        SELECT
            parent.block_hash,
            parent.parent_hash,
            parent.block_height,
            last.depth + 1
        FROM sbtc_signer.bitcoin_blocks AS parent
        JOIN blockchain AS last
            ON parent.block_hash = last.parent_hash
        WHERE last.depth <= max_depth
    )
    SELECT
        blocks.block_hash,
        blocks.parent_hash,
        blocks.block_height
    FROM blockchain as blocks;
END;
$$ LANGUAGE plpgsql;
