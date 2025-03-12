import logging
from typing import Any

from ..models import DepositInfo, DepositUpdate, RequestStatus
from ..utils import asdict_camel
from .base import APIClient
from .. import settings

logger = logging.getLogger(__name__)


class PublicEmilyAPI(APIClient):
    """Client for interacting with the Emily API."""

    BASE_URL = settings.EMILY_ENDPOINT

    def __init__(self, api_key: str):
        self.headers = {"x-api-key": api_key}

    @classmethod
    def fetch_deposits(cls, status: RequestStatus) -> list[DepositInfo]:
        """Fetch deposits based on status."""
        data = cls.get(f"/deposit?status={status.value}")
        return [DepositInfo.from_json(deposit) for deposit in data.get("deposits", [])]


class PrivateEmilyAPI(APIClient):
    """Client for interacting with the Private Emily API."""

    BASE_URL = settings.PRIVATE_EMILY_ENDPOINT
    HEADERS = {"x-api-key": settings.API_KEY}

    @classmethod
    def update_deposits(cls, updates: list[DepositUpdate]) -> list[dict[str, Any]]:
        """Update multiple deposit statuses.

        Args:
            updates: List of DepositUpdate objects

        Returns:
            list[dict[str, Any]]: The updated deposits
        """
        assert len(updates) > 0, "Updates must contain at least one deposit update"

        return cls.put(
            f"/deposit",
            json_data={"deposits": [asdict_camel(update) for update in updates]},
            headers=cls.HEADERS,
        )
