-- Table used to store the canonical chain instances for the materialized data
-- in `canonical_chain_data`. The primary purpose of this table is to avoid the
-- need to include the 32-byte chain tip in every row of the `canonical_chain_data`
-- and its indexes. This table is also used to enforce the constraint that only
-- one canonical chain can be materialized per chain tip.
CREATE TABLE sbtc_signer.canonical_chain (
    id SERIAL NOT NULL PRIMARY KEY,
    bitcoin_chain_tip BYTEA NOT NULL
);

-- We only allow one canonical chain materialization per chain tip, and this
-- index enforces that constraint while also allowing for fast lookups by chain
-- tip.
CREATE UNIQUE INDEX uk_canonical_chain_bitcoin_chain_tip ON sbtc_signer.canonical_chain(bitcoin_chain_tip);

-- This table holds the canonical chain information for Bitcoin and Stacks
-- chains keyed by the bitcoin chain tip.
-- 
-- This table includes one row for each Stacks block which is anchored to a
-- Bitcoin block in the canonical chain. The `bitcoin_chain_tip` column is used
-- to identify the specific chain tip for which the canonical chain is
-- materialized. If no Stacks block(s) exist for a given Bitcoin block, the
-- `stacks_block_hash` and `stacks_block_height` columns will be `NULL` for that
-- Bitcoin block hash.
CREATE TABLE sbtc_signer.canonical_chain_data (
    canonical_chain_id INT NOT NULL,
    bitcoin_block_hash BYTEA NOT NULL,
    bitcoin_block_height BIGINT NOT NULL,
    stacks_block_hash BYTEA,
    stacks_block_height BIGINT,

    FOREIGN KEY (canonical_chain_id) REFERENCES sbtc_signer.canonical_chain(id),
    FOREIGN KEY (bitcoin_block_hash) REFERENCES sbtc_signer.bitcoin_blocks(block_hash),
    FOREIGN KEY (stacks_block_hash) REFERENCES sbtc_signer.stacks_blocks(block_hash)
);

-- Indexes to support common queries on the canonical chains data table.
CREATE UNIQUE INDEX uk_canonical_chain_data ON sbtc_signer.canonical_chain_data(canonical_chain_id, bitcoin_block_hash, stacks_block_hash);
CREATE INDEX ix_canonical_chain_data_bitcoin_block_hash ON sbtc_signer.canonical_chain_data(bitcoin_block_hash);
CREATE INDEX ix_canonical_chain_data_bitcoin_block_height ON sbtc_signer.canonical_chain_data(bitcoin_block_height DESC);
CREATE INDEX ix_canonical_chain_data_stacks_block_hash ON sbtc_signer.canonical_chain_data(stacks_block_hash);
CREATE INDEX ix_canonical_chain_data_stacks_block_height ON sbtc_signer.canonical_chain_data(stacks_block_height DESC);

-- An intermediate view to `canonical_chain` + `canonical_chain_data` which can
-- be used in queries to avoid needing to manually join them. Note that this
-- view will return multiple canonical chains, so you need to filter the results
-- to the specific chain tip which you are interested in.
CREATE VIEW sbtc_signer.canonical_chains AS
SELECT
    idx.bitcoin_chain_tip,
    dat.bitcoin_block_hash,
    dat.bitcoin_block_height,
    dat.stacks_block_hash,
    dat.stacks_block_height
FROM sbtc_signer.canonical_chain idx
INNER JOIN sbtc_signer.canonical_chain_data dat
    ON idx.id = dat.canonical_chain_id;

-- A helper view to get only the canonical Bitcoin chain information from the
-- materialized chain data if you're not interested in Stacks blocks. Note that
-- if used in queries, the `bitcoin_chain_tip` column should be used to filter
-- the results to the specific chain tip which you are interested in. The
-- results are not ordered by block height, so you should do that yourself if
-- you require the results to be ordered.
CREATE VIEW sbtc_signer.canonical_bitcoin_chain AS
SELECT DISTINCT
    idx.bitcoin_chain_tip,
    dat.bitcoin_block_hash,
    dat.bitcoin_block_height
FROM sbtc_signer.canonical_chain idx
INNER JOIN sbtc_signer.canonical_chain_data dat
    ON idx.id = dat.canonical_chain_id;

-- A helper view to get only the canonical Stacks chain information from the
-- materialized chain data if you're not interested in Bitcoin blocks. Note that
-- if used in queries, the `bitcoin_chain_tip` column should be used to filter
-- the results to the specific chain tip which you are interested in. The
-- results are not ordered by block height, so you should do that yourself if
-- you require the results to be ordered.
CREATE VIEW sbtc_signer.canonical_stacks_chain AS
SELECT DISTINCT
    idx.bitcoin_chain_tip,
    dat.stacks_block_hash,
    dat.stacks_block_height
FROM sbtc_signer.canonical_chain idx
INNER JOIN sbtc_signer.canonical_chain_data dat
    ON idx.id = dat.canonical_chain_id
WHERE dat.stacks_block_hash IS NOT NULL;

-- Function to materialize the canonical chains for a given bitcoin chain tip
-- and the maximum depth of the bitcoin blockchain to consider.
--
-- This function returns the number of rows written to the `canonical_chains`
-- table upon success, and `-1` if rows already exist for the given chain tip.
CREATE OR REPLACE FUNCTION sbtc_signer.materialize_canonical_chains(chain_tip BYTEA, max_depth INT)
RETURNS INTEGER AS $$
DECLARE
    rows_written INTEGER;
	canonical_chain_id BIGINT;
BEGIN
	-- Check if rows exist with the given chain_tip.
    -- If rows exist, return an error code. We only allow one materialized
    -- canonical chain per chain tip. We could have relied on the PK returning
    -- an error, but this allows the calling application to clearly identify
    -- that this is a duplicate chain tip and handle it accordingly.
    IF EXISTS (
        SELECT 1
        FROM sbtc_signer.canonical_chain
        WHERE bitcoin_chain_tip = chain_tip
    ) THEN
        RETURN -1; -- Error code indicating rows already exist
    END IF;

    -- Insert 
    INSERT INTO sbtc_signer.canonical_chain (bitcoin_chain_tip)
    VALUES (chain_tip)
    RETURNING id INTO canonical_chain_id;

    -- Materialize the canonical chains from the given bitcoin chain tip.
    WITH RECURSIVE 
    bitcoin AS (
        SELECT 
              block_hash
            , parent_hash
            , block_height
            , 1 as depth
        FROM sbtc_signer.bitcoin_blocks
        WHERE block_hash = chain_tip

        UNION ALL

        SELECT 
              parent.block_hash
            , parent.parent_hash
            , parent.block_height
            , last.depth + 1
        FROM sbtc_signer.bitcoin_blocks parent
        JOIN bitcoin last ON parent.block_hash = last.parent_hash
            WHERE last.depth < max_depth
    ),
    stacks AS (
        (SELECT 
              blocks.block_hash
            , blocks.parent_hash
            , blocks.block_height
            , blocks.bitcoin_anchor
        FROM sbtc_signer.stacks_blocks blocks
        JOIN bitcoin ON blocks.bitcoin_anchor = bitcoin.block_hash
        ORDER BY bitcoin.block_height DESC, bitcoin.block_hash DESC, blocks.block_height DESC, blocks.block_hash DESC
        LIMIT 1)

        UNION ALL

        SELECT 
              parent.block_hash
            , parent.parent_hash
            , parent.block_height
            , parent.bitcoin_anchor
        FROM sbtc_signer.stacks_blocks parent
        JOIN stacks last ON parent.block_hash = last.parent_hash
        JOIN bitcoin ON bitcoin.block_hash = parent.bitcoin_anchor
    )
    INSERT INTO sbtc_signer.canonical_chain_data (
          canonical_chain_id
        , bitcoin_block_hash
        , bitcoin_block_height
        , stacks_block_hash
        , stacks_block_height
    )
    SELECT 
          canonical_chain_id
        , bb.block_hash AS bitcoin_block_hash
        , bb.block_height AS bitcoin_block_height
        , sb.block_hash AS stacks_block_hash
        , sb.block_height AS stacks_block_height
    FROM bitcoin bb
    LEFT JOIN stacks sb ON sb.bitcoin_anchor = bb.block_hash
    ORDER BY bb.block_height DESC, sb.block_height DESC;

    GET DIAGNOSTICS rows_written = ROW_COUNT;
    RETURN rows_written;
END;
$$ LANGUAGE plpgsql;
