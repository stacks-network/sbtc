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
            blocks.block_hash
          , blocks.parent_hash
          , blocks.block_height
          , 1 AS depth
        FROM sbtc_signer.bitcoin_blocks as blocks
        WHERE blocks.block_hash = chain_tip

        UNION ALL

        SELECT
            parent.block_hash
          , parent.parent_hash
          , parent.block_height
          , last.depth + 1
        FROM sbtc_signer.bitcoin_blocks AS parent
        JOIN blockchain AS last
            ON parent.block_hash = last.parent_hash
        WHERE last.depth <= max_depth
    )
    SELECT
        blocks.block_hash
      , blocks.parent_hash
      , blocks.block_height
    FROM blockchain as blocks;
END;
$$ LANGUAGE plpgsql;

-- Table-Valued Function (TVF) for fetching Bitcoin transactions from a given
-- block hash, only looking back the `max_blocks` number of blocks. The most
-- common use case is to fetch the transactions from the canonical chain tip.

-- The function uses a recursive common table expression (CTE) to traverse the
-- blockchain starting from the given `chain_tip` and moving backwards up to
-- `max_blocks` blocks. It joins the `bitcoin_blocks` and `bitcoin_transactions`
-- tables to retrieve the transactions in each block.
--
-- - chain_tip: The block hash to start the blockchain from ("chain tip").
-- - max_blocks: The maximum number of blocks to look back in the blockchain.
--
-- This function returns a table with the following columns:
-- - txid: The transaction ID (BYTEA).
-- - block_hash: The block hash containing the transaction (BYTEA).
-- - block_height: The height of the block containing the transaction (BIGINT).
--
-- Example usage:
-- SELECT * FROM sbtc_signer.bitcoin_transactions_of(chain_tip, max_blocks);
CREATE FUNCTION sbtc_signer.bitcoin_transactions_of (
    chain_tip BYTEA,
    max_blocks INT
)
RETURNS TABLE (
    txid BYTEA,
    block_hash BYTEA,
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
          , txs.txid
          , 1 AS depth
        FROM sbtc_signer.bitcoin_blocks AS blocks
        INNER JOIN sbtc_signer.bitcoin_transactions AS txs
            ON blocks.block_hash = txs.block_hash
        WHERE blocks.block_hash = chain_tip

        UNION ALL

        SELECT
            parent.block_hash
          , parent.parent_hash
          , parent.block_height
          , txs.txid
          , last.depth + 1
        FROM sbtc_signer.bitcoin_blocks AS parent
        INNER JOIN blockchain AS last
            ON parent.block_hash = last.parent_hash
        INNER JOIN sbtc_signer.bitcoin_transactions AS txs
            ON txs.block_hash = parent.block_hash
        WHERE last.depth < max_blocks
    )
    SELECT
        b.txid
      , b.block_hash
      , b.block_height
    FROM blockchain b;
END;
$$ LANGUAGE plpgsql;

-- Table-Valued Function (TVF) for fetching a Stacks blockchain from a given
-- stacks block hash and bitcoin block hash, only looking back the `max_depth`
-- number of bitcoin blocks. The bitcoin blocks are used to consider only
-- stacks blocks anchored to the canonical bitcoin chain.
--
-- - stacks_chain_tip: The stacks block hash to start the blockchain from ("chain tip").
-- - bitcoin_chain_tip: The bitcoin block hash to start the canonical blockchain from ("chain tip").
-- - max_depth: The maximum depth of the bitcoin blockchain to fetch.
CREATE FUNCTION sbtc_signer.stacks_blockchain_of (
    stacks_chain_tip BYTEA,
    bitcoin_chain_tip BYTEA,
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
    WITH RECURSIVE bc_blocks AS (
        SELECT * FROM sbtc_signer.bitcoin_blockchain_of(bitcoin_chain_tip, max_depth)
    ),
    blockchain AS (
        SELECT
            stacks_blocks.block_hash
          , stacks_blocks.block_height
          , stacks_blocks.parent_hash
        FROM sbtc_signer.stacks_blocks stacks_blocks
        JOIN bc_blocks
            ON bc_blocks.block_hash = stacks_blocks.bitcoin_anchor
        WHERE stacks_blocks.block_hash = stacks_chain_tip

        UNION ALL

        SELECT
            parent.block_hash
          , parent.block_height
          , parent.parent_hash
        FROM sbtc_signer.stacks_blocks parent
        JOIN blockchain last
            ON parent.block_hash = last.parent_hash
        JOIN bc_blocks
            ON bc_blocks.block_hash = parent.bitcoin_anchor
    )
    SELECT
        blocks.block_hash
      , blocks.parent_hash
      , blocks.block_height
    FROM blockchain as blocks;
END;
$$ LANGUAGE plpgsql;
