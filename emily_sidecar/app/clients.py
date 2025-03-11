from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import functools
import logging
import requests
from typing import Any, Self, Iterable

from btclib.script import script

logger = logging.getLogger(__name__)


class RequestStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REPROCESSING = "reprocessing"


class APIClient:
    """Base class for handling API requests and error logging."""

    BASE_URL: str = ""

    @classmethod
    def get(cls, endpoint: str, params: dict | None = None) -> dict:
        """Perform a GET request and return JSON response."""
        url = f"{cls.BASE_URL}{endpoint}"
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching data from {url}: {e}")
            return {}

    @classmethod
    def post(cls, endpoint: str, json_data: dict) -> dict:
        """Perform a POST request and return JSON response."""
        url = f"{cls.BASE_URL}{endpoint}"
        try:
            response = requests.post(url, json=json_data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error posting data to {url}: {e}")
            return {}


class EmilyAPI(APIClient):
    BASE_URL = "https://sbtc-emily.com"

    @classmethod
    def fetch_deposits(cls, status: RequestStatus) -> list["DepositInfo"]:
        """Fetch deposits based on status."""
        data = cls.get(f"/deposit?status={status.value}")
        return [DepositInfo.from_json(deposit) for deposit in data.get("deposits", [])]

    def update_deposit_status(self, deposit: DepositInfo, status: RequestStatus) -> bool:
        """Update deposit status."""
        data = {"status": status.value}
        result = self.post(f"/deposit/{deposit.bitcoin_txid}", json_data=data)
        return result.get("status") == status.value


class MempoolAPI(APIClient):
    BASE_URL = "https://mempool.space/api"

    @classmethod
    def check_for_rbf(cls, txid: str) -> bool:
        """Check if a Bitcoin transaction was replaced (RBF)."""
        data = cls.get(f"/v1/tx/{txid}/rbf")
        return bool(data.get("replacements"))

    @classmethod
    def get_bitcoin_block_at(cls, timestamp: int | None = None) -> "BlockInfo":
        """Fetch the Bitcoin block at a given timestamp."""
        if timestamp is None:
            timestamp = int(datetime.now().timestamp())
        return cls.get(f"/v1/mining/blocks/timestamp/{timestamp}")

    @classmethod
    def get_bitcoin_transaction(cls, txid: str) -> dict:
        """Fetch details for a Bitcoin transaction."""
        return cls.get(f"/tx/{txid}")


class HiroAPI(APIClient):
    BASE_URL = "https://api.hiro.so"

    @classmethod
    def fetch_if_stacks_deposit_completed(cls, txid: str) -> bool:
        """Check if a Stacks deposit was completed."""
        params = {
            "sender": "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4",
            "arguments": [f"0x0200000020{txid}", "0x0100000000000000000000000000000000"],
        }
        result = cls.post(
            "/v2/contracts/call-read/SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4/sbtc-registry/get-completed-deposit",
            json_data=params,
        )

        if not result.get("okay") or result.get("result") == "0x09":
            return False  # Not minted yet
        return result.get("result", "").startswith("0x0a0c")


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
            return int(lock_time[len("OP_"):])
        return int.from_bytes(bytes.fromhex(lock_time), byteorder="little")

    @property
    def max_fee(self) -> int:
        """Extracts the max fee from deposit script."""
        data = script.parse(self.deposit_script)[0]
        return int.from_bytes(bytes.fromhex(data)[:8])


@dataclass
class EnrichedDepositInfo(DepositInfo):
    """Represents a deposit with additional enriched details."""
    total_input: int
    fee: int
    confirmed_height: int
    confirmed_time: int
    spending_outputs: dict[str, int]
    num_inputs: int
    rbfd: bool = False
    was_minted: bool

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
            "total_input": -1,
            "fee": -1,
            "confirmed_height": -1,
            "confirmed_time": -1,
            "spending_outputs": {},
            "num_inputs": -1,
        }
        return cls(**asdict(d), **missing_data)


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
            time=j["time"],
        )

    @classmethod
    def from_bitcoin(cls, j: dict[str, Any]) -> Self:
        return cls(
            height=j["height"],
            hash=j["hash"],
            time=j["timestamp"],
        )



def enrich_deposits(deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
    """Fetch transaction details and enrich deposit info."""
    transaction_details = []
    for deposit in deposits:
        tx_data = MempoolAPI.get(f"/tx/{deposit.bitcoin_txid}")
        if not tx_data:
            transaction_details.append(EnrichedDepositInfo.from_missing(deposit))
            continue

        spending_outputs = {
            vout.get("scriptpubkey_address", "Unknown"): vout.get("value", 0)
            for vout in tx_data.get("vout", [])
        }

        additional_info = {
            "total_input": sum(
                vin.get("prevout", {}).get("value", 0) for vin in tx_data.get("vin", [])
            ),
            "fee": tx_data.get("fee", 0),
            "confirmed_height": tx_data.get("status", {}).get("block_height", -1),
            "confirmed_time": tx_data.get("status", {}).get("block_time", -1),
            "num_inputs": len(tx_data.get("vin", [])),
            "spending_outputs": spending_outputs,
            "rbfd": MempoolAPI.check_for_rbf(deposit.bitcoin_txid),
            "was_minted": HiroAPI.fetch_if_stacks_deposit_completed(deposit.bitcoin_txid),
        }
        transaction_details.append(EnrichedDepositInfo.from_deposit_info(deposit, additional_info))
    return sorted(transaction_details, key=lambda x: x.last_update_height, reverse=True)
