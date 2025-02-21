from pydantic import BaseModel, field_validator
from enum import Enum


# The type of event that occurred within the transaction.
class TransactionEventType(Enum):
    # A smart contract event
    ContractEvent = "contract_event"
    # A STX transfer event
    StxTransferEvent = "stx_transfer_event"
    # An STX mint event
    StxMintEvent = "stx_mint_event"
    # An STX burn event
    StxBurnEvent = "stx_burn_event"
    # An STX lock event
    StxLockEvent = "stx_lock_event"
    # A transfer event for a NFT
    NftTransferEvent = "nft_transfer_event"
    # A non-fungible-token mint event
    NftMintEvent = "nft_mint_event"
    # A non-fungible-token burn event
    NftBurnEvent = "nft_burn_event"
    # A fungible-token transfer event
    FtTransferEvent = "ft_transfer_event"
    # A fungible-token mint event
    FtMintEvent = "ft_mint_event"
    # A fungible-token burn event
    FtBurnEvent = "ft_burn_event"


# Smart contracts emit events when they are executed. This represents
# such an event. The expected type is taken from stacks-core[^1].
#
# [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L358-L363>
class SmartContractEventModel(BaseModel, extra="allow"):
    contract_identifier: str
    raw_value: str
    topic: str
    value: dict


# An event that was emitted during the execution of the transaction. It
# is defined in [^1].
#
# [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L45-L51>
class TransactionEventModel(BaseModel, extra="allow"):
    txid: str
    event_index: int
    committed: bool
    type: TransactionEventType
    contract_event: SmartContractEventModel | None

    @field_validator("txid", mode="after")
    def remove_prefix(cls, value: str) -> str:
        return value.removeprefix("0x")


# This class represents the minimal body of POST /new_block events from a stacks
# node that the Sidecar needs to handle.
#
## Note
#
# This class leaves out some of the fields that are included. For the
# full payload, see the source here:
# <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L644-L687>
class NewBlockEventModel(BaseModel, extra="allow"):
    block_height: int
    index_block_hash: str
    events: list[TransactionEventModel]

    @field_validator("index_block_hash", mode="after")
    def remove_prefix(cls, value: str) -> str:
        return value.removeprefix("0x")
