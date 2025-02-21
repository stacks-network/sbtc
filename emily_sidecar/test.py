import os
import json
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
import emily_client

from main import app
from clarity import parse_clarity_value, parse_clarity_value_safe


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


def mock_success():
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"message": "Success"}
    return mock


class NewBlockTestCase(unittest.TestCase):
    def setUp(self):
        self.app = client
        self.app.testing = True

    @patch("emily_client.ChainstateApi.set_chainstate")
    def test_new_block_valid_json(self, mock_chainstate: MagicMock):
        # Mock the response from emily_client.ChainstateApi.set_chainstate
        mock_chainstate.return_value = mock_success()

        response = self.app.post(
            "/new_block",
            json={"block_height": 1, "index_block_hash": "0x" + "1" * 64, "events": []},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_chainstate.call_count, 1)
        mock_chainstate.assert_called_with(
            emily_client.Chainstate(stacksBlockHeight=1, stacksBlockHash="1" * 64)
        )

    def test_new_block_invalid_json(self):
        response = self.app.post("/new_block", data="Not a JSON")
        self.assertEqual(response.status_code, 422)
        self.assertIn("json_invalid", response.json()["detail"][0]["type"])

    def test_new_block_validation_error(self):
        invalid_data = {"invalid_field": "invalid_value"}
        response = self.app.post("/new_block", json=invalid_data)
        self.assertEqual(response.status_code, 422)

    @patch("emily_client.ChainstateApi.set_chainstate")
    def test_new_block_post_request_failure(self, mock_post: MagicMock):
        # Mock the response from set_chainstate to raise an exception
        mock_post.side_effect = emily_client.exceptions.ServiceException()
        response = self.app.post("/new_block", json=FIXTURES["complete_deposit"])
        self.assertEqual(response.status_code, 500)
        self.assertIn("Failed to send chainstate", response.json()["detail"])

    @patch("emily_client.ChainstateApi.set_chainstate")
    @patch("emily_client.DepositApi.update_deposits")
    def test_new_block_post_request_strips_0x_prefix(
        self, mock_deposit: MagicMock, mock_chainstate: MagicMock
    ):
        mock_chainstate.return_value = mock_success()
        mock_deposit.return_value = mock_success()

        fixture = FIXTURES["complete_deposit"].copy()
        index_block_hash = "0" * 64
        fixture["index_block_hash"] = f"0x{index_block_hash}"

        response = self.app.post("/new_block", json=fixture)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        chainstate = emily_client.Chainstate(
            stacksBlockHeight=fixture["block_height"], stacksBlockHash=index_block_hash
        )

        self.assertEqual(mock_chainstate.call_count, 1)
        mock_chainstate.assert_called_with(chainstate)

    @patch("emily_client.ChainstateApi.set_chainstate")
    @patch("emily_client.DepositApi.update_deposits")
    def test_new_block_complete_deposit(
        self, mock_withdrawals: MagicMock, mock_chainstate: MagicMock
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_withdrawals.return_value = mock_response
        mock_chainstate.return_value = mock_success()

        response = self.app.post("/new_block", json=FIXTURES["complete_deposit"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_withdrawals.call_count, 1)
        mock_withdrawals.assert_called_with(
            emily_client.UpdateDepositsRequestBody(
                deposits=[
                    emily_client.DepositUpdate(
                        bitcoin_tx_output_index=4294967295,
                        bitcoin_txid="0000000000000000000000000000000000000000000000000000000000000000",
                        fulfillment=emily_client.Fulfillment(
                            bitcoin_block_hash="0101010101010101010101010101010101010101010101010101010101010101",
                            bitcoin_block_height=42,
                            bitcoin_tx_index=0,
                            bitcoin_txid="0202020202020202020202020202020202020202020202020202020202020202",
                            btc_fee=0,
                            stacks_txid="58a9074c3299c2f627829b7e5ecf8b7136e380cbce3900461c679939925f77bc",
                        ),
                        last_update_block_hash="acf821a2df6700046a2e2cd8042b394bcae4d62aadd3e940597658ece9852c30",
                        last_update_height=227,
                        status="confirmed",
                        status_message="Included in block 0101010101010101010101010101010101010101010101010101010101010101",
                    )
                ]
            )
        )

    @patch("emily_client.ChainstateApi.set_chainstate")
    @patch("emily_client.WithdrawalApi.update_withdrawals")
    def test_new_block_withdrawal_accept(
        self, mock_withdrawals: MagicMock, mock_chainstate: MagicMock
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_withdrawals.return_value = mock_response
        mock_chainstate.return_value = mock_success()

        response = self.app.post("/new_block", json=FIXTURES["withdrawal_accept"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_withdrawals.call_count, 1)
        mock_withdrawals.assert_called_with(
            emily_client.UpdateWithdrawalsRequestBody(
                withdrawals=[
                    emily_client.WithdrawalUpdate(
                        fulfillment=emily_client.Fulfillment(
                            bitcoin_block_hash="0101010101010101010101010101010101010101010101010101010101010101",
                            bitcoin_block_height=42,
                            bitcoin_tx_index=4294967295,
                            bitcoin_txid="0202020202020202020202020202020202020202020202020202020202020202",
                            btc_fee=2500,
                            stacks_txid="95a8cf1ed4aa559a0cd8b380174272c3629942a57eb1a2b9aa8281020c36359f",
                        ),
                        last_update_block_hash="0ce5807894c9da8cddcd7b00d15b916f067b1d53487ecc4cae98bc4b7e8fc253",
                        last_update_height=301,
                        request_id=1,
                        status="confirmed",
                        status_message="Included in block 0101010101010101010101010101010101010101010101010101010101010101",
                    )
                ]
            )
        )

    @patch("emily_client.ChainstateApi.set_chainstate")
    @patch("emily_client.WithdrawalApi.update_withdrawals")
    def test_new_block_withdrawal_reject(
        self, mock_withdrawals: MagicMock, mock_chainstate: MagicMock
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_withdrawals.return_value = mock_response
        mock_chainstate.return_value = mock_success()

        response = self.app.post("/new_block", json=FIXTURES["withdrawal_reject"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_withdrawals.call_count, 1)
        mock_withdrawals.assert_called_with(
            emily_client.UpdateWithdrawalsRequestBody(
                withdrawals=[
                    emily_client.WithdrawalUpdate(
                        fulfillment=None,
                        last_update_block_hash="fc1b44b2db9997d9f37ea1c8704318ed8c1bce2f077b6e73fb583deac167ce98",
                        last_update_height=350,
                        request_id=2,
                        status="failed",
                        status_message="Rejected",
                    )
                ]
            )
        )

    @patch("emily_client.ChainstateApi.set_chainstate")
    @patch("emily_client.WithdrawalApi.create_withdrawal")
    def test_new_block_withdrawal_create(
        self, mock_withdrawals: MagicMock, mock_chainstate: MagicMock
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_withdrawals.return_value = mock_response
        mock_chainstate.return_value = mock_success()

        response = self.app.post("/new_block", json=FIXTURES["withdrawal_create"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_withdrawals.call_count, 1)
        mock_withdrawals.assert_called_with(
            create_withdrawal_request_body=emily_client.CreateWithdrawalRequestBody(
                amount=22500,
                parameters=emily_client.WithdrawalParameters(max_fee=3000),
                recipient="1EXCN4m6mNL88QzPwksBnpVqr5F1dC4SGa",
                request_id=1,
                stacks_block_hash="75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78",
                stacks_block_height=253,
            )
        )

    @patch("emily_client.ChainstateApi.set_chainstate")
    def test_new_block_unsupported_events(self, mock_chainstate: MagicMock):
        mock_chainstate.return_value = mock_success()

        response = self.app.post("/new_block", json=FIXTURES["rotate_keys"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

        self.assertEqual(mock_chainstate.call_count, 1)


class AttachmentsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = client
        self.app.testing = True

    def test_handle_attachments_with_any_json(self):
        test_json = {"key": "value"}
        response = self.app.post("/attachments/new", json=test_json)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

    def test_handle_attachments_with_empty_json(self):
        response = self.app.post("/attachments/new", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())

    def test_handle_attachments_with_no_json(self):
        response = self.app.post("/attachments/new")
        self.assertEqual(response.status_code, 200)
        self.assertEqual({}, response.json())


class TestParseClarityValue(unittest.TestCase):

    def test_parse_tuple(self):
        clarity_value = {
            "Tuple": {
                "data_map": {
                    "key1": {"UInt": 42},
                    "key2": {
                        "Sequence": {
                            "String": {"ASCII": {"data": [104, 101, 108, 108, 111]}}
                        }
                    },
                }
            }
        }
        expected_result = {"key1": 42, "key2": "hello"}
        result = parse_clarity_value(clarity_value)
        self.assertEqual(result, expected_result)

    def test_parse_sequence_buffer(self):
        clarity_value = {"Sequence": {"Buffer": {"data": [1, 2, 3, 4]}}}
        expected_result = "04030201"
        result = parse_clarity_value(clarity_value)
        self.assertEqual(bytes(reversed(result)).hex(), expected_result)

    def test_parse_sequence_string(self):
        clarity_value = {
            "Sequence": {"String": {"ASCII": {"data": [104, 101, 108, 108, 111]}}}
        }
        expected_result = "hello"
        result = parse_clarity_value(clarity_value)
        self.assertEqual(result, expected_result)

    def test_parse_uint(self):
        clarity_value = {"UInt": 42}
        expected_result = 42
        result = parse_clarity_value(clarity_value)
        self.assertEqual(result, expected_result)

    def test_parse_int(self):
        clarity_value = {"Int": -42}
        expected_result = -42
        result = parse_clarity_value(clarity_value)
        self.assertEqual(result, expected_result)

    def test_unhandled_type(self):
        clarity_value = {"Unhandled": "value"}
        result = parse_clarity_value(clarity_value)
        self.assertEqual(result, clarity_value)


class TestParseClarityValueSafe(unittest.TestCase):

    def test_parse_clarity_value_safe_success(self):
        clarity_value = {"UInt": 42}
        expected_result = 42
        result = parse_clarity_value_safe(clarity_value)
        self.assertEqual(result, expected_result)

    def test_parse_clarity_value_safe_failure(self):
        clarity_value = {"Invalid": "value"}
        result = parse_clarity_value_safe(clarity_value)
        self.assertEqual(result, clarity_value)

    def test_parse_clarity_value_invalid_format(self):
        # Missing ASCII between String and data
        clarity_value = {"Sequence": {"String": {"data": [104, 101, 108, 108, 111]}}}
        result = parse_clarity_value_safe(clarity_value)
        self.assertEqual(result, None)


if __name__ == "__main__":
    unittest.main()
