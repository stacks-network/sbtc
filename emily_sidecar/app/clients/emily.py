import logging
from datetime import datetime
from typing import Any, List

from ..models import (
    DepositInfo,
    DepositUpdate,
    RequestStatus,
    asdict_camel,
)
from .base import APIClient

logger = logging.getLogger(__name__)


class EmilyAPI(APIClient):
    """Client for interacting with the Emily API."""

    BASE_URL = "https://sbtc-emily.com"

    def __init__(self, api_key: str):
        self.headers = {"x-api-key": api_key}

    @classmethod
    def fetch_deposits(cls, status: RequestStatus) -> list[DepositInfo]:
        """Fetch deposits based on status."""
        data = cls.get(f"/deposit?status={status.value}")
        return [DepositInfo.from_json(deposit) for deposit in data.get("deposits", [])]

    def update_deposits(self, updates: list[DepositUpdate]) -> list[dict[str, Any]]:
        """Update multiple deposit statuses.

        Args:
            updates: List of DepositUpdate objects

        Returns:
            list[dict[str, Any]]: The updated deposits
        """
        assert len(updates) > 0, "Updates must contain at least one deposit update"

        return self.post(
            f"/deposit/{txid}",
            json_data={"deposits": [asdict_camel(update) for update in updates]},
            headers=self.headers)