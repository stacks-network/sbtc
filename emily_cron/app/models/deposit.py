from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import functools
from typing import Any, Optional, Self

from bitcoinlib.scripts import Script

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
        script = Script.parse(self.reclaim_script)
        op_code_maybe = script.view().split()[0]
        if op_code_maybe.startswith("OP_"):
            return int(op_code_maybe[len("OP_") :])
        return int.from_bytes(script.commands[0], byteorder="little", signed=True)

    @property
    def max_fee(self) -> int:
        """Extracts the max fee from deposit script."""
        script = Script.parse(self.deposit_script)
        if script.redeemscript:
            max_fee_bytes = script.redeemscript
        else:
            max_fee_bytes = bytes.fromhex(script.view().split()[0])
        return int.from_bytes(max_fee_bytes[:8], byteorder="big")

    @functools.cached_property
    def deposit_time(self) -> int:
        """Get the timestamp from the last update block hash."""
        from ..clients import HiroAPI  # Moved import here to avoid circular import

        return HiroAPI.get_stacks_block(self.last_update_block_hash).time


@dataclass
class EnrichedDepositInfo(DepositInfo):
    """Represents a deposit with additional enriched details."""

    in_mempool: bool  # Whether the transaction was found by the mempool API
    fee: int
    confirmed_height: int
    confirmed_time: int

    @classmethod
    def from_deposit_info(cls, d: DepositInfo, additional_data: dict) -> Self:
        return cls(**asdict(d), **additional_data)

    @classmethod
    def from_missing(cls, d: DepositInfo) -> Self:
        """Create an EnrichedDepositInfo with missing values."""
        missing_data = {
            "in_mempool": False,
            "fee": -1,
            "confirmed_height": -1,
            "confirmed_time": -1,
        }
        return cls.from_deposit_info(d, missing_data)

    def is_expired(self, bitcoin_chaintip_height: int) -> bool:
        """Check if the deposit's time-based expiry condition has been met.

        Note: This only checks the time component (locktime + confirmations).
        It does NOT check if the UTXO has been spent.

        Args:
            bitcoin_chaintip_height: The height of the tip of the Bitcoin chain

        Returns:
            bool: True if the deposit is expired, False otherwise
        """
        # Check if the deposit is confirmed
        if self.confirmed_height < 0:
            return False

        # Calculate the block height at which the deposit becomes eligible for expiry
        expiry_eligible_height = (
            self.confirmed_height + self.lock_time + settings.MIN_BLOCK_CONFIRMATIONS
        )

        # Check if the current chain tip has passed the expiry eligible height
        is_past_expiry_time = bitcoin_chaintip_height >= expiry_eligible_height

        return is_past_expiry_time


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
