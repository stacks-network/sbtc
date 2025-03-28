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
    def get_tip_height(cls) -> int:
        """Get the height of the tip of the Bitcoin chain.

        Returns:
            int: The height of the tip of the Bitcoin chain
        """
        return cls.get("/v1/blocks/tip/height", raise_on_error=True)

    @classmethod
    def get_transaction(cls, txid: str) -> dict[str, Any]:
        """Fetch details for a Bitcoin transaction.

        Args:
            txid: The transaction ID to fetch

        Returns:
            dict: Transaction details or empty dict if not found
        """
        return cls.get(f"/tx/{txid}")
