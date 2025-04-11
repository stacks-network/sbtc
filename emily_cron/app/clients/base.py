import logging
import requests
from typing import Any, Optional
from requests.exceptions import RequestException, JSONDecodeError

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
        ignore_errors: bool = False,
    ) -> Any:
        """Make an HTTP request and return JSON response.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            endpoint: API endpoint to call
            params: Optional query parameters
            json_data: Optional JSON data for request body
            headers: Optional HTTP headers
            ignore_errors: If True, logs errors and returns empty dict.
                           If False, raises exceptions for HTTP errors (400-599).
                           Set to False when the response is critical for further processing.

        Returns:
            Parsed JSON response or empty dict on error (if ignore_errors is True)

        Raises:
            requests.RequestException: If the request fails (HTTP 400-599) (if ignore_errors is False)
            ValueError: If the response cannot be parsed as JSON (if ignore_errors is False)
        """
        url = f"{cls.BASE_URL}{endpoint}"

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()

        except (JSONDecodeError, RequestException) as e:
            logger.error(f"Error during {method} {url}: {e}")
            if not ignore_errors:
                raise
            return {}

    @classmethod
    def get(
        cls, endpoint: str, params: Optional[dict[str, Any]] = None, ignore_errors: bool = False
    ) -> Any:
        """Perform a GET request and return JSON response."""
        return cls._make_request("GET", endpoint, params=params, ignore_errors=ignore_errors)

    @classmethod
    def post(
        cls,
        endpoint: str,
        json_data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
        ignore_errors: bool = False,
    ) -> dict[str, Any]:
        """Perform a POST request and return JSON response."""
        return cls._make_request(
            "POST", endpoint, json_data=json_data, headers=headers, ignore_errors=ignore_errors
        )

    @classmethod
    def put(
        cls,
        endpoint: str,
        json_data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
        ignore_errors: bool = False,
    ) -> dict[str, Any]:
        """Perform a PUT request and return JSON response."""
        return cls._make_request(
            "PUT", endpoint, json_data=json_data, headers=headers, ignore_errors=ignore_errors
        )
