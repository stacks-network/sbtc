import os
import unittest
from unittest.mock import patch, MagicMock

import json
import requests

from app import app


def read_fixture(filename):
    with open(filename, 'r') as file:
        return json.load(file)


BASE_PATH = os.path.join(os.path.dirname(__file__), "..")
FIXTURES_PATH = os.path.join(BASE_PATH, "signer", "tests", "fixtures")

FIXTURE_FILES = {
    "complete_deposit": "completed-deposit-event.json",
    "withdrawal_accept": "withdrawal-accept-event.json",
    "withdrawal_create": "withdrawal-create-event.json",
    "withdrawal_reject": "withdrawal-reject-event.json",
    "rotate_keys": "rotate-keys-event.json"
}

FIXTURES = {name: read_fixture(os.path.join(FIXTURES_PATH, file)) for name, file in FIXTURE_FILES.items()}


class NewBlockTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

<<<<<<< HEAD
    def read_fixture(self, filename):
        with open(filename, 'r') as file:
            return json.load(file)

=======
>>>>>>> main
    @patch('requests.post')
    def test_new_block_valid_json(self, mock_post):
        # Mock the response from requests.post
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Success"}
        mock_post.return_value = mock_response

<<<<<<< HEAD
        base_path = os.path.join(os.path.dirname(__file__), "..")
        fixtures_path = os.path.join(base_path, "signer", "tests", "fixtures")
        fixtures = [
            "completed-deposit-event.json",
            "withdrawal-accept-event.json",
            "withdrawal-create-event.json",
            "withdrawal-reject-event.json",
            "rotate-keys-event.json"
        ]

        for fixture in fixtures:
            path = os.path.join(fixtures_path, fixture)
            data = self.read_fixture(path)
            response = self.app.post('/new_block', json=data)
            self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.get_json())
=======
        for fixture in FIXTURES.values():
            response = self.app.post('/new_block', json=fixture)
            self.assertEqual(response.status_code, 200)
            self.assertEqual({}, response.get_json())
>>>>>>> main

    def test_new_block_invalid_json(self):
        response = self.app.post('/new_block', data="Not a JSON")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Request must be JSON", response.get_json()["error"])

    def test_new_block_validation_error(self):
        invalid_data = {
            "invalid_field": "invalid_value"
        }
        response = self.app.post('/new_block', json=invalid_data)
        self.assertEqual(response.status_code, 400)

    @patch('requests.post')
    def test_new_block_post_request_failure(self, mock_post):
        # Mock the response from requests.post to raise a RequestException
        mock_post.side_effect = requests.RequestException("Failed to send chainstate")
<<<<<<< HEAD

        base_path = os.path.join(os.path.dirname(__file__), "..")
        fixtures_path = os.path.join(base_path, "signer", "tests", "fixtures")
        fixture = "completed-deposit-event.json"

        path = os.path.join(fixtures_path, fixture)
        data = self.read_fixture(path)
        response = self.app.post('/new_block', json=data)
=======
        response = self.app.post('/new_block', json=FIXTURES["complete_deposit"])
>>>>>>> main
        self.assertEqual(response.status_code, 500)
        self.assertIn("Failed to send chainstate", response.get_json()["error"])


if __name__ == '__main__':
    unittest.main()
