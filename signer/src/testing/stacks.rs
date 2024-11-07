//! Test utilities from the stacks module
//!

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::SortitionId;

use crate::error::Error;
use crate::stacks::api::TenureBlocks;

/// Some dummy sortition info
pub const DUMMY_SORTITION_INFO: SortitionInfo = SortitionInfo {
    burn_block_hash: BurnchainHeaderHash([0; 32]),
    burn_block_height: 0,
    burn_header_timestamp: 0,
    sortition_id: SortitionId([0; 32]),
    parent_sortition_id: SortitionId([0; 32]),
    consensus_hash: ConsensusHash([0; 20]),
    was_sortition: false,
    miner_pk_hash160: None,
    stacks_parent_ch: None,
    last_sortition_ch: None,
    committed_block_hash: None,
};

impl TenureBlocks {
    /// Create a TenureBlocks struct that is basically empty.
    pub fn nearly_empty() -> Result<Self, Error> {
        let block = NakamotoBlock {
            header: NakamotoBlockHeader::empty(),
            txs: Vec::new(),
        };
        Self::try_new(vec![block], DUMMY_SORTITION_INFO)
    }

    /// Create TenureBlocks with some dummy sortition info.
    pub fn from_blocks(blocks: Vec<NakamotoBlock>) -> Result<Self, Error> {
        Self::try_new(blocks, DUMMY_SORTITION_INFO)
    }
}
