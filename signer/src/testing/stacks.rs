//! Test utilities from the stacks module
//!

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use clarity::types::chainstate::StacksBlockId;
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

/// Some dummy tenure info
pub const DUMMY_TENURE_INFO: RPCGetTenureInfo = RPCGetTenureInfo {
    consensus_hash: ConsensusHash([0; 20]),
    tenure_start_block_id: StacksBlockId([0; 32]),
    parent_consensus_hash: ConsensusHash([0; 20]),
    // The following bytes are the ones returned by StacksBlockId::first_mined()
    parent_tenure_start_block_id: StacksBlockId([
        0x55, 0xc9, 0x86, 0x1b, 0xe5, 0xcf, 0xf9, 0x84, 0xa2, 0x0c, 0xe6, 0xd9, 0x9d, 0x4a, 0xa6,
        0x59, 0x41, 0x41, 0x28, 0x89, 0xbd, 0xc6, 0x65, 0x09, 0x41, 0x36, 0x42, 0x9b, 0x84, 0xf8,
        0xc2, 0xee,
    ]),
    tip_block_id: StacksBlockId([0; 32]),
    tip_height: 0,
    reward_cycle: 0,
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
