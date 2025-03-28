from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import functools
from typing import Any, Optional, Self

from btclib.script import script

from app import settings


class RequestStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REPROCESSING = "reprocessing"


@dataclass
class DepositInfo:
    """Represents a deposit transaction."""

    bitcoin_txid: str
    bitcoin_tx_output_index: int
    recipient: str
    amount: int
    last_update_height: int
    last_update_block_hash: str
    status: str
    reclaim_script: str
    deposit_script: str

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> Self:
        return cls(
            bitcoin_txid=j["bitcoinTxid"],
            bitcoin_tx_output_index=j["bitcoinTxOutputIndex"],
            recipient=j["recipient"],
            amount=j["amount"],
            last_update_height=j["lastUpdateHeight"],
            last_update_block_hash=j["lastUpdateBlockHash"],
            status=j["status"],
            reclaim_script=j["reclaimScript"],
            deposit_script=j["depositScript"],
        )

    @property
    def lock_time(self) -> int:
        """Extracts lock time from reclaim script."""
        lock_time = script.parse(self.reclaim_script)[0]
        if lock_time.startswith("OP_"):
            return int(lock_time[len("OP_") :])
        return int.from_bytes(bytes.fromhex(lock_time), byteorder="little")

    @property
    def max_fee(self) -> int:
        """Extracts the max fee from deposit script."""
        data = script.parse(self.deposit_script)[0]
        return int.from_bytes(bytes.fromhex(data)[:8])

    @functools.cached_property
    def deposit_time(self) -> int:
        """Get the timestamp from the last update block hash."""
        from ..clients import HiroAPI  # Moved import here to avoid circular import

        return HiroAPI.get_stacks_block(self.last_update_block_hash).time


@dataclass
class EnrichedDepositInfo(DepositInfo):
    """Represents a deposit with additional enriched details."""

    in_mempool: bool  # Whether the transaction was found by the mempool API
    total_input: int
    fee: int
    confirmed_height: int
    confirmed_time: int
    spending_outputs: dict[str, int]
    num_inputs: int
    # was_minted: bool

    @property
    def num_outputs(self):
        return len(self.spending_outputs)

    @property
    def total_spent(self):
        return sum(self.spending_outputs.values())

    @classmethod
    def from_deposit_info(cls, d: DepositInfo, additional_data: dict) -> Self:
        return cls(**asdict(d), **additional_data)

    @classmethod
    def from_missing(cls, d: DepositInfo) -> Self:
        """Create an EnrichedDepositInfo with missing values."""
        missing_data = {
            "in_mempool": False,
            "total_input": -1,
            "fee": -1,
            "confirmed_height": -1,
            "confirmed_time": -1,
            "spending_outputs": {},
            "num_inputs": -1,
        }
        return cls(**asdict(d), **missing_data)

    def is_expired(self, bitcoin_chaintip_height: int) -> bool:
        """Check if the deposit is expired.

        Args:
            bitcoin_chaintip_height: The height of the tip of the Bitcoin chain

        Returns:
            bool: True if the deposit is expired, False otherwise
        """
        # Check if the deposit is confirmed
        if self.confirmed_height < 0:
            return False

        return (
            bitcoin_chaintip_height
            >= self.confirmed_height + self.lock_time + settings.MIN_BLOCK_CONFIRMATIONS
        )


@dataclass
class BlockInfo:
    """Represents a block."""

    height: int
    hash: str
    time: int

    @classmethod
    def from_stacks(cls, j: dict[str, Any]) -> Self:
        return cls(
            height=j["height"],
            hash=j["hash"],
            time=j["block_time"],
        )

    @classmethod
    def from_bitcoin(cls, j: dict[str, Any]) -> Self:
        return cls(
            height=j["height"],
            hash=j["hash"],
            time=datetime.fromisoformat(j["timestamp"].replace("Z", "+00:00")).timestamp(),
        )


@dataclass
class Fulfillment:
    """Represents a fulfillment."""

    bitcoin_txid: str
    bitcoin_tx_index: int
    stacks_txid: str
    bitcoin_block_hash: str
    bitcoin_block_height: int
    btc_fee: int


@dataclass
class DepositUpdate:
    """Represents a deposit update."""

    bitcoin_txid: str
    bitcoin_tx_output_index: int
    status: str
    status_message: str
    fulfillment: Optional[Fulfillment] = None
