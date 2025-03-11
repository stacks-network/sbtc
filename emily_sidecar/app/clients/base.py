import logging
import requests
from typing import Any

logger = logging.getLogger(__name__)


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
    def post(cls, endpoint: str, json_data: dict, headers: dict | None = None) -> dict:
        """Perform a POST request and return JSON response."""
        url = f"{cls.BASE_URL}{endpoint}"
        try:
            response = requests.post(url, json=json_data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error posting data to {url}: {e}")
            return {}