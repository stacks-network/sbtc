import os
import json
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
import requests
import logging_config

from main import app


logging_config.silence_logging()


client = TestClient(app)


def read_fixture(filename):
    with open(filename, "r") as file:
        return json.load(file)


BASE_PATH = os.path.join(os.path.dirname(__file__), "..")
FIXTURES_PATH = os.path.join(BASE_PATH, "signer", "tests", "fixtures")

FIXTURE_FILES = {
    "complete_deposit": "completed-deposit-event.json",
    "withdrawal_accept": "withdrawal-accept-event.json",
    "withdrawal_create": "withdrawal-create-event.json",
    "withdrawal_reject": "withdrawal-reject-event.json",
    "rotate_keys": "rotate-keys-event.json",
}

FIXTURES = {
    name: read_fixture(os.path.join(FIXTURES_PATH, file))
    for name, file in FIXTURE_FILES.items()
}


class NewBlockTestCase(unittest.TestCase):
    def setUp(self):
        self.app = client
        self.app.testing = True

    @patch("requests.post")
    def test_new_block_valid_json(self, mock_post: MagicMock):
        # Mock the response from requests.post
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        for fixture in FIXTURES.values():
            response = self.app.post("/new_block", json=fixture)
            self.assertEqual(response.status_code, 200)

    def test_new_block_invalid_json(self):
        response = self.app.post("/new_block", data="Not a JSON")
        self.assertEqual(response.status_code, 422)
        self.assertIn("json_invalid", response.json()["detail"][0]["type"])

    def test_new_block_validation_error(self):
        invalid_data = {"invalid_field": "invalid_value"}
        response = self.app.post("/new_block", json=invalid_data)
        self.assertEqual(response.status_code, 422)

    @patch("requests.post")
    def test_new_block_post_request_failure(self, mock_post: MagicMock):
        # Mock the response from new_block to raise an exception
        mock_post.side_effect = requests.RequestException(
            "Failed to send new_block event"
        )
        response = self.app.post("/new_block", json=FIXTURES["complete_deposit"])
        self.assertEqual(response.status_code, 500)
        self.assertIn("Failed to send new_block event", response.json()["detail"])


class AttachmentsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = client
        self.app.testing = True

    def test_handle_attachments_with_any_json(self):
        test_json = {"key": "value"}
        response = self.app.post("/attachments/new", json=test_json)
        self.assertEqual(response.status_code, 200)

    def test_handle_attachments_with_empty_json(self):
        response = self.app.post("/attachments/new", json={})
        self.assertEqual(response.status_code, 200)

    def test_handle_attachments_with_no_json(self):
        response = self.app.post("/attachments/new")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
