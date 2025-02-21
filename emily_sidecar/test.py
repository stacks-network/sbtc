import os
import json
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
import emily_client

from main import app

client = TestClient(app)


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
        self.app = client
        self.app.testing = True

    @patch('emily_client.ChainstateApi.set_chainstate')
    def test_new_block_valid_json(self, mock_post: MagicMock):
        # Mock the response from emily_client.ChainstateApi.set_chainstate
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Success"}
        mock_post.return_value = mock_response

        for fixture in FIXTURES.values():
            response = self.app.post('/new_block', json=fixture)
            self.assertEqual(response.status_code, 200)
            self.assertEqual({}, response.json())

    def test_new_block_invalid_json(self):
        response = self.app.post('/new_block', data="Not a JSON")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid JSON", response.json()["detail"])

    def test_new_block_validation_error(self):
        invalid_data = {
            "invalid_field": "invalid_value"
        }
        response = self.app.post('/new_block', json=invalid_data)
        self.assertEqual(response.status_code, 400)

    @patch('emily_client.ChainstateApi.set_chainstate')
    def test_new_block_post_request_failure(self, mock_post: MagicMock):
        # Mock the response from set_chainstate to raise an exception
        mock_post.side_effect = emily_client.exceptions.ServiceException()
        response = self.app.post('/new_block', json=FIXTURES["complete_deposit"])
        self.assertEqual(response.status_code, 500)
        self.assertIn("Failed to send chainstate", response.json()["detail"])

    @patch('emily_client.ChainstateApi.set_chainstate')
    def test_new_block_post_request_strips_0x_prefix(self, mock_post: MagicMock):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Success"}
        mock_post.return_value = mock_response

        fixture = FIXTURES["complete_deposit"].copy()
        index_block_hash = "0" * 64
        fixture["index_block_hash"] = f"0x{index_block_hash}"

        response = self.app.post('/new_block', json=fixture)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        chainstate = emily_client.Chainstate(
            stacksBlockHeight=fixture["block_height"],
            stacksBlockHash=index_block_hash
        )

        self.assertEqual(mock_post.call_count, 1)
        mock_post.assert_called_with(chainstate)


class AttachmentsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = client
        self.app.testing = True

    def test_handle_attachments_with_any_json(self):
        test_json = {"key": "value"}
        response = self.app.post('/attachments/new', json=test_json)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

    def test_handle_attachments_with_empty_json(self):
        response = self.app.post('/attachments/new', json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

    def test_handle_attachments_with_no_json(self):
        response = self.app.post('/attachments/new')
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())


if __name__ == '__main__':
    unittest.main()
