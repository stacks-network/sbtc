import logging
from datetime import datetime
from typing import Any, Optional

from ..models import BlockInfo
from .base import APIClient
from .. import settings

logger = logging.getLogger(__name__)


class MempoolAPI(APIClient):
    """Client for interacting with the Mempool API."""

    BASE_URL = settings.MEMPOOL_API_URL

    @classmethod
    def get_block_at(cls, timestamp: Optional[int] = None) -> BlockInfo:
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
    def get_tip_height(cls) -> int:
        """Get the height of the tip of the Bitcoin chain.

        Returns:
            int: The height of the tip of the Bitcoin chain
        """
        return cls.get("/v1/blocks/tip/height")

    @classmethod
    def get_transaction(cls, txid: str) -> dict[str, Any]:
        """Fetch details for a Bitcoin transaction.

        Args:
            txid: The transaction ID to fetch

        Returns:
            dict: Transaction details or empty dict if not found
        """
        return cls.get(f"/tx/{txid}")
