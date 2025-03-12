import logging
from datetime import datetime
from typing import Any, Optional

from ..models import BlockInfo
from .base import APIClient
from .. import settings

logger = logging.getLogger(__name__)


def _collect_rbf_txids(data: dict[str, Any]) -> set[str]:
    """Recursively collect all RBF transaction IDs from the replacement chain.

    Args:
        data: Transaction replacement data from mempool API

    Returns:
        Set of transaction IDs that replaced the original transaction
    """
    txids = set()

    if tx := data.get("tx", {}):
        if txid := tx.get("txid"):
            txids.add(txid)

    for replacement in data.get("replaces", []):
        txids.update(_collect_rbf_txids(replacement))

    return txids


class MempoolAPI(APIClient):
    """Client for interacting with the Mempool API."""

    BASE_URL = settings.MEMPOOL_API_URL

    @classmethod
    def check_for_rbf(cls, txid: str) -> set[str]:
        """Check if a Bitcoin transaction was replaced by RBF.

        Args:
            txid: The transaction ID to check

        Returns:
            Set of transaction IDs that replaced the original transaction
        """
        data = cls.get(f"/v1/tx/{txid}/rbf")
        return _collect_rbf_txids(data.get("replacements", {}))

    @classmethod
    def get_bitcoin_block_at(cls, timestamp: Optional[int] = None) -> BlockInfo:
        """Fetch the Bitcoin block at a given timestamp.

        Args:
            timestamp: Unix timestamp to get the block at, or None for current time

        Returns:
            BlockInfo: Information about the Bitcoin block
        """
        if timestamp is None:
            timestamp = int(datetime.now().timestamp())
        return BlockInfo.from_bitcoin(cls.get(f"/v1/mining/blocks/timestamp/{timestamp}"))

    @classmethod
    def get_bitcoin_transaction(cls, txid: str) -> dict[str, Any]:
        """Fetch details for a Bitcoin transaction.

        Args:
            txid: The transaction ID to fetch

        Returns:
            dict: Transaction details or empty dict if not found
        """
        return cls.get(f"/tx/{txid}")
