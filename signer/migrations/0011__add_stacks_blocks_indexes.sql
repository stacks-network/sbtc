CREATE INDEX ix_stacks_blocks_block_height ON sbtc_signer.stacks_blocks(block_height DESC);
CREATE INDEX ix_stacks_blocks_block_hash ON sbtc_signer.stacks_transactions(block_hash DESC);