import logging
import requests
from typing import Any, Optional

logger = logging.getLogger(__name__)


class APIClient:
    """Base class for handling API requests and error logging."""

    BASE_URL: str = ""

    @classmethod
    def _make_request(
        cls,
        method: str,
        endpoint: str,
        params: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        raise_for_error: bool = False,
    ) -> Any:
        """Make an HTTP request and return JSON response.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            endpoint: API endpoint to call
            params: Optional query parameters
            json_data: Optional JSON data for request body
            headers: Optional HTTP headers
            raise_on_error: If True, raises exceptions for HTTP or JSON errors
                            If False, logs errors and returns empty dict

        Returns:
            Parsed JSON response or empty dict on error
        """
        url = f"{cls.BASE_URL}{endpoint}".rstrip("/")

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                timeout=30,  # Add timeout to prevent hanging requests
            )
            response.raise_for_status()

            try:
                return response.json()
            except Exception as e:
                logger.error(f"Invalid JSON response from {method} {url}: {e}")
                if raise_for_error:
                    raise
                return {}

        except requests.RequestException as e:
            logger.error(f"Error {method} {url}: {e}")
            if raise_for_error:
                raise
            return {}

    @classmethod
    def get(cls, endpoint: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Perform a GET request and return JSON response."""
        return cls._make_request("GET", endpoint, params=params)

    @classmethod
    def post(
        cls,
        endpoint: str,
        json_data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Perform a POST request and return JSON response."""
        return cls._make_request("POST", endpoint, json_data=json_data, headers=headers)

    @classmethod
    def put(
        cls,
        endpoint: str,
        json_data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Perform a PUT request and return JSON response."""
        return cls._make_request("PUT", endpoint, json_data=json_data, headers=headers)
