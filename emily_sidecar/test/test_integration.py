import os
import json
import unittest
import requests

from fastapi.testclient import TestClient

from app import logging_config, settings
from app.main import app, headers


logging_config.silence_logging()

WIPE_URL = f"{settings.EMILY_ENDPOINT}/testing/wipe"
DEPOSITS_URL = f"{settings.EMILY_ENDPOINT}/deposit"
WITHDRAWALS_URL = f"{settings.EMILY_ENDPOINT}/withdrawal"

client = TestClient(app)


def read_fixture(filename):
    with open(filename, "r") as file:
        return json.load(file)


BASE_PATH = os.path.join(os.path.dirname(__file__), "..", "..")
NEW_BLOCK_FIXTURES_PATH = os.path.join(BASE_PATH, "signer", "tests", "fixtures")
DEPOSIT_TESTNET_FIXTURES_PATH = os.path.join(
    BASE_PATH, "emily", "handler", "tests", "fixtures"
)


TESTNET_DEPOSIT_FIXTURES_FILES = {
    "create_deposit": "create-deposit-valid-testnet.json",
    "complete_deposit": "completed-deposit-testnet-event.json",
}


NEW_BLOCK_FIXTURE_FILES = {
    "complete_deposit": "completed-deposit-event.json",
    "withdrawal_accept": "withdrawal-accept-event.json",
    "withdrawal_create": "withdrawal-create-event.json",
    "withdrawal_reject": "withdrawal-reject-event.json",
    "rotate_keys": "rotate-keys-event.json",
}

TESTNET_DEPOSIT_FIXTURES = {
    name: read_fixture(os.path.join(DEPOSIT_TESTNET_FIXTURES_PATH, file))
    for name, file in TESTNET_DEPOSIT_FIXTURES_FILES.items()
}


NEW_BLOCK_FIXTURES = {
    name: read_fixture(os.path.join(NEW_BLOCK_FIXTURES_PATH, file))
    for name, file in NEW_BLOCK_FIXTURE_FILES.items()
}


def create_deposit(deposit: dict) -> requests.Response:
    return requests.post(DEPOSITS_URL, json=deposit, headers=headers)


def get_deposit(bitcoin_txid: str, bitcoin_tx_output_index: int) -> requests.Response:
    return requests.get(
        f"{DEPOSITS_URL}/{bitcoin_txid}/{bitcoin_tx_output_index}", headers=headers
    )


def get_withdrawal(request_id: int) -> requests.Response:
    return requests.get(f"{WITHDRAWALS_URL}/{request_id}", headers=headers)


class IntegrationTests(unittest.TestCase):

    def setUp(self):
        # Wipe the state before each test
        requests.post(WIPE_URL, headers=headers)
        self.app = client
        self.app.testing = True

    def test_withdrawal_create(self):
        fixture = NEW_BLOCK_FIXTURES["withdrawal_create"]
        response = self.app.post("/new_block", json=fixture)
        self.assertEqual(response.status_code, 200)

        withdrawal = requests.get(f"{WITHDRAWALS_URL}/1", headers=headers)
        self.assertEqual(withdrawal.status_code, 200)
        self.assertEqual(
            withdrawal.json(),
            {
                "requestId": 1,
                "stacksBlockHash": "75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78",
                "stacksBlockHeight": 0,
                "recipient": "76a914000000000000000000000000000000000000000088ac",
                "sender": "SN2V7WTJ7BHR03MPHZ1C9A9ZR6NZGR4WM8HT4V67Y",
                "amount": 22500,
                "lastUpdateHeight": 253,
                "lastUpdateBlockHash": "75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78",
                "status": "pending",
                "statusMessage": "Just received withdrawal",
                "parameters": {"maxFee": 3000},
            },
        )

    def test_complete_deposit(self):
        create_deposit_fixture = TESTNET_DEPOSIT_FIXTURES["create_deposit"]
        response = create_deposit(create_deposit_fixture)
        self.assertEqual(response.status_code, 201)
        response = self.app.post(
            "/new_block", json=TESTNET_DEPOSIT_FIXTURES["complete_deposit"]
        )
        self.assertEqual(response.status_code, 200)
        deposit = get_deposit(
            create_deposit_fixture["bitcoinTxid"],
            create_deposit_fixture["bitcoinTxOutputIndex"],
        )
        self.assertEqual(deposit.status_code, 200)

        self.assertEqual(
            deposit.json(),
            {
                "bitcoinTxid": "672f77ce3c16b36ec6c443f5b8a0a9684d0203482a3068567e792fe2559d54cf",
                "bitcoinTxOutputIndex": 0,
                "recipient": "051a0000000000000000000000000000000000000000",
                "amount": 10000,
                "lastUpdateHeight": 227,
                "lastUpdateBlockHash": "acf821a2df6700046a2e2cd8042b394bcae4d62aadd3e940597658ece9852c30",
                "status": "confirmed",
                "statusMessage": "Included in block acf821a2df6700046a2e2cd8042b394bcae4d62aadd3e940597658ece9852c30",
                "parameters": {"maxFee": 8000, "lockTime": 14},
                "reclaimScript": "5eb2",
                "depositScript": "1e0000000000001f40051a00000000000000000000000000000000000000007520567467ad8005b9a240160b3c8f6cbd229f3e52f100004c138054d4dbae363e5eac",
                "fulfillment": {
                    "BitcoinTxid": "0202020202020202020202020202020202020202020202020202020202020202",
                    "BitcoinTxIndex": 0,
                    "StacksTxid": "58a9074c3299c2f627829b7e5ecf8b7136e380cbce3900461c679939925f77bc",
                    "BitcoinBlockHash": "0101010101010101010101010101010101010101010101010101010101010101",
                    "BitcoinBlockHeight": 42,
                    "BtcFee": 0,
                },
            },
        )

    def test_withdrawal_accept(self):
        response = self.app.post(
            "/new_block", json=NEW_BLOCK_FIXTURES["withdrawal_create"]
        )
        self.assertEqual(response.status_code, 200)

        response = self.app.post(
            "/new_block", json=NEW_BLOCK_FIXTURES["withdrawal_accept"]
        )
        self.assertEqual(response.status_code, 200)

        withdrawal = get_withdrawal(1)
        self.assertEqual(withdrawal.status_code, 200)
        self.assertEqual(
            withdrawal.json(),
            {
                "requestId": 1,
                "stacksBlockHash": "75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78",
                "stacksBlockHeight": 0,
                "recipient": "76a914000000000000000000000000000000000000000088ac",
                "sender": "SN2V7WTJ7BHR03MPHZ1C9A9ZR6NZGR4WM8HT4V67Y",
                "amount": 22500,
                "lastUpdateHeight": 301,
                "lastUpdateBlockHash": "0ce5807894c9da8cddcd7b00d15b916f067b1d53487ecc4cae98bc4b7e8fc253",
                "status": "confirmed",
                "statusMessage": "Included in block 0ce5807894c9da8cddcd7b00d15b916f067b1d53487ecc4cae98bc4b7e8fc253",
                "parameters": {"maxFee": 3000},
                "fulfillment": {
                    "BitcoinTxid": "0000000000000000000000000000000000000000000000000000000000000000",
                    "BitcoinTxIndex": 4294967295,
                    "StacksTxid": "95a8cf1ed4aa559a0cd8b380174272c3629942a57eb1a2b9aa8281020c36359f",
                    "BitcoinBlockHash": "0101010101010101010101010101010101010101010101010101010101010101",
                    "BitcoinBlockHeight": 42,
                    "BtcFee": 2500,
                },
            },
        )

    def test_withdrawal_reject(self):
        response = self.app.post(
            "/new_block", json=NEW_BLOCK_FIXTURES["withdrawal_create"]
        )
        self.assertEqual(response.status_code, 200)

        response = self.app.post(
            "/new_block", json=NEW_BLOCK_FIXTURES["withdrawal_reject"]
        )
        self.assertEqual(response.status_code, 200)

        withdrawal = get_withdrawal(1)
        self.assertEqual(withdrawal.status_code, 200)
        self.assertEqual(
            withdrawal.json(),
            {
                "requestId": 1,
                "stacksBlockHash": "75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78",
                "stacksBlockHeight": 0,
                "recipient": "76a914000000000000000000000000000000000000000088ac",
                "sender": "SN2V7WTJ7BHR03MPHZ1C9A9ZR6NZGR4WM8HT4V67Y",
                "amount": 22500,
                "lastUpdateHeight": 350,
                "lastUpdateBlockHash": "fc1b44b2db9997d9f37ea1c8704318ed8c1bce2f077b6e73fb583deac167ce98",
                "status": "failed",
                "statusMessage": "Rejected",
                "parameters": {"maxFee": 3000},
            },
        )

    def test_rotate_keys(self):
        response = self.app.post("/new_block", json=NEW_BLOCK_FIXTURES["rotate_keys"])
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
