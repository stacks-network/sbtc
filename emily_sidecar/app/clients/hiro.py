import functools
import logging
from datetime import datetime
from typing import Any

from ..models import BlockInfo
from .base import APIClient

logger = logging.getLogger(__name__)


class HiroAPI(APIClient):
    """Client for interacting with the Hiro API."""

    BASE_URL = "https://api.hiro.so"

    @classmethod
    def fetch_if_stacks_deposit_completed(cls, txid: str) -> bool:
        """Check if a Stacks deposit was completed.

        Args:
            txid: The Bitcoin transaction ID

        Returns:
            bool: True if the deposit was completed, False otherwise
        """
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

    @classmethod
    @functools.lru_cache(maxsize=256)
    def _get_stacks_block_cached(cls, height_or_hash: int | str) -> dict:
        """Cached version of get_stacks_block for non-latest queries.

        Args:
            height_or_hash: Block height or hash

        Returns:
            dict: Block information
        """
        return cls.get(f"/extended/v2/blocks/{height_or_hash}")

    @classmethod
    def get_stacks_block(cls, height_or_hash: int | str = "latest") -> BlockInfo:
        """Fetch the Stacks block at a given height or hash.

        Uses LRU cache for all queries except when height_or_hash is "latest".

        Args:
            height_or_hash: Block height, block hash, or "latest"

        Returns:
            BlockInfo: Block information
        """
        if height_or_hash == "latest":
            # Don't cache "latest" queries
            block_data = cls.get(f"/extended/v2/blocks/{height_or_hash}")
        else:
            # Use cached version for specific heights or hashes
            block_data = cls._get_stacks_block_cached(height_or_hash)
        return BlockInfo.from_stacks(block_data)