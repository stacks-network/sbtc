import logging
import functools
from typing import Any

from ..models import BlockInfo
from .base import APIClient
from .. import settings

logger = logging.getLogger(__name__)


class HiroAPI(APIClient):
    """Client for interacting with the Hiro API."""

    BASE_URL = settings.HIRO_API_URL

    @classmethod
    def fetch_is_deposit_completed(cls, txid: str, vout: int) -> bool:
        """Check if a Stacks deposit was completed.

        Args:
            txid: The Bitcoin transaction ID
            vout: The output index of the deposit

        Returns:
            bool: True if the deposit was completed, False otherwise
        """
        # Convert vout to hex without 0x prefix
        # Add padding to ensure fixed length (36 chars total)
        # 36 = 2 (0x) + 2 (01) + padding + len(vout_hex)
        vout_hex = format(vout, "x").zfill(32)
        params = {
            "sender": settings.DEPLOYER_ADDRESS,
            "arguments": [
                f"0x0200000020{txid}",
                f"0x01{vout_hex}",
            ],
        }
        result: dict[str, Any] = cls.post(
            f"/v2/contracts/call-read/{settings.DEPLOYER_ADDRESS}/sbtc-registry/get-completed-deposit",
            json_data=params,
            ignore_errors=True,
        )
        # Check if the call was successful and returned a value
        # 0x09 represents 'None' in Clarity's option type encoding
        if not result.get("okay") or result.get("result") == "0x09":
            return False  # Not minted yet
        # 0x0a represents 'Some' in Clarity's option type encoding
        # 0x0c represents a Tuple type in Clarity
        # If we get 'Some(Tuple(...))', the deposit is completed
        return result.get("result", "").startswith("0x0a0c")

    @classmethod
    @functools.lru_cache(maxsize=256)
    def _get_stacks_block_cached(cls, height_or_hash: int | str) -> dict[str, Any]:
        """Cached version of get_stacks_block for non-latest queries.

        Errors are not ignored (ignore_errors=False) because block data is critical
        for processing deposits and determining chain state.

        Args:
            height_or_hash: Block height or hash

        Returns:
            dict: Block information

        Raises:
            requests.RequestException: If the request fails (HTTP 400-599)
            ValueError: If the response cannot be parsed as JSON
        """
        return cls.get(f"/extended/v2/blocks/{height_or_hash}", ignore_errors=False)

    @classmethod
    def get_stacks_block(cls, height_or_hash: int | str = "latest") -> BlockInfo:
        """Fetch the Stacks block at a given height or hash.

        Uses LRU cache for all queries except when height_or_hash is "latest".
        Errors are not ignored (ignore_errors=False) because block data is critical
        for processing deposits and determining chain state.

        Args:
            height_or_hash: Block height, block hash, or "latest"

        Returns:
            BlockInfo: Block information

        Raises:
            requests.RequestException: If the request fails (HTTP 400-599)
            ValueError: If the response cannot be parsed as JSON
        """
        if height_or_hash == "latest":
            # Don't cache "latest" queries
            block_data: dict[str, Any] = cls.get(
                f"/extended/v2/blocks/{height_or_hash}", ignore_errors=False
            )
        else:
            # Use cached version for specific heights or hashes
            block_data = cls._get_stacks_block_cached(height_or_hash)
        return BlockInfo.from_stacks(block_data)
