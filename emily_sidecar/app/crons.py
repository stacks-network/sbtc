from typing import Any
from dataclasses import asdict, dataclass

from btclib.script import script


EMILY_BASE_URL = "https://sbtc-emily.com"
MEMPOOL_BASE_URL = "https://mempool.space"
HIRO_API_BASE_URL = "https://api.hiro.so"


@dataclass
class DepositInfo:
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
    def from_json(cls, j: dict[str, Any]) -> "DepositInfo":
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
        lock_time = script.parse(self.reclaim_script)[0]
        if lock_time.startswith("OP_"):
            return int(lock_time[len("OP_") :])

        return int.from_bytes(bytes.fromhex(lock_time), byteorder="little")

    @property
    def max_fee(self) -> int | str:
        data = script.parse(self.deposit_script)[0]
        return int.from_bytes(bytes.fromhex(data)[:8])


@dataclass
class EnrichedDepositInfo(DepositInfo):
    total_input: int
    fee: int
    confirmed_height: int
    confirmed_time: int
    spending_outputs: dict[str, int]  # excludes change
    num_inputs: int
    rbfd: bool = False
    was_minted: bool = False

    @property
    def num_outputs(self):
        return len(self.spending_outputs)

    @property
    def total_spent(self):
        return sum(self.spending_outputs.values())

    @classmethod
    def from_deposit_info(cls, d: DepositInfo, j: dict) -> "EnrichedDepositInfo":
        j.update(asdict(d))
        return cls(**j)

    @classmethod
    def from_missing(cls, d: DepositInfo) -> "EnrichedDepositInfo":
        j = {
            "total_input": -1,
            "fee": -1,
            "confirmed_height": -1,
            "confirmed_time": -1,
            "spending_outputs": {},
            "num_inputs": -1,
        }
        j.update(asdict(d))
        return cls(**j)
