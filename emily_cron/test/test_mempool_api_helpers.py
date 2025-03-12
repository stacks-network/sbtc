# test/test_rbf_processor.py
import unittest
import json
import os
from datetime import datetime
from unittest.mock import patch, MagicMock, mock_open

from app.models import EnrichedDepositInfo, BlockInfo, RequestStatus, DepositInfo
from app.services.deposit_processor import DepositProcessor
from app.clients.mempool import _collect_rbf_txids, MempoolAPI
from app import settings


class TestRbfHelpers(unittest.TestCase):
    """Tests for RBF helper functions."""

    def setUp(self):
        # Load test fixtures
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')

        with open(os.path.join(fixtures_dir, 'fixture-mempool-rbf-multi.json'), 'r') as f:
            self.rbf_data = json.load(f)

        with open(os.path.join(fixtures_dir, 'fixture-mempool-rbf-empty.json'), 'r') as f:
            self.empty_rbf_data = json.load(f)

    def test_collect_rbf_txids_complex(self):
        """Test collecting RBF txids from a complex replacement chain."""
        txids = _collect_rbf_txids(self.rbf_data["replacements"])

        # Expected txids from the fixture
        expected_txids = {
            "afe18f246b9624b17b21f2ebf84594bb75b582209d55dfc0b6edb34bfb785c3a",
            "2f1c7f3fcfa444781825491efe38912839ccabec20086767605b947245bbce5f",
            "c1a83eb973b7904224d54003329eb97bf62088c0bd2906640a0a3c005bf65cd3",
            "8fd3fdd5632f1a7459c381e5e51bebc1f59f82f8ab3a16778cfb7c3973de3d30",
            "3a4940a712111361b66a9df6d0eb9d410f2cf1a94da32405fcd4b34500785e3f",
            "99d6fd9c1b3e22f85aabacea66db9cfa959f20f6877f8dc9360627e63f0cdae8",
            "51c79e6dbd6232547d446614d8a573c00e027e9f2690c9dd336b77e6c644fd7d",
            "3ed54d49e84f804b117fca784e43caad15787bbbcd9ce34e3bdecd007b91cf3f"
        }

        self.assertEqual(txids, expected_txids)

    def test_collect_rbf_txids_empty(self):
        """Test collecting RBF txids from an empty replacement chain."""
        txids = _collect_rbf_txids(self.empty_rbf_data["replacements"])
        self.assertEqual(txids, set())

    def test_collect_rbf_txids_simple(self):
        """Test collecting RBF txids from a simple replacement chain."""
        simple_data = {
            "tx": {
                "txid": "abc123"
            },
            "replaces": []
        }

        txids = _collect_rbf_txids(simple_data)
        self.assertEqual(txids, {"abc123"})

    def test_collect_rbf_txids_nested(self):
        """Test collecting RBF txids from a nested replacement chain."""
        nested_data = {
            "tx": {
                "txid": "parent"
            },
            "replaces": [
                {
                    "tx": {
                        "txid": "child1"
                    },
                    "replaces": []
                },
                {
                    "tx": {
                        "txid": "child2"
                    },
                    "replaces": [
                        {
                            "tx": {
                                "txid": "grandchild"
                            },
                            "replaces": []
                        }
                    ]
                }
            ]
        }

        txids = _collect_rbf_txids(nested_data)
        self.assertEqual(txids, {"parent", "child1", "child2", "grandchild"})


class TestRbfProcessor(unittest.TestCase):
    """Tests for the process_rbf_transactions method."""

    def setUp(self):
        self.processor = DepositProcessor()
        self.current_time = int(datetime.now().timestamp())

        # Mock blockchain state
        self.stacks_chaintip = BlockInfo(height=50000, hash="stx_hash", time=self.current_time)

        # Create test deposits
        self.unconfirmed_with_rbf = self._create_mock_deposit(
            txid="unconfirmed_with_rbf",
            confirmed_height=-1,
            rbf_txids=["confirmed_replacement"]
        )

        self.confirmed_replacement = self._create_mock_deposit(
            txid="confirmed_replacement",
            confirmed_height=700000,
            rbf_txids=[]
        )

        self.unconfirmed_no_rbf = self._create_mock_deposit(
            txid="unconfirmed_no_rbf",
            confirmed_height=-1,
            rbf_txids=[]
        )

        self.unconfirmed_with_unconfirmed_rbf = self._create_mock_deposit(
            txid="unconfirmed_with_unconfirmed_rbf",
            confirmed_height=-1,
            rbf_txids=["another_unconfirmed"]
        )

        self.another_unconfirmed = self._create_mock_deposit(
            txid="another_unconfirmed",
            confirmed_height=-1,
            rbf_txids=[]
        )

        # Complex RBF chain
        self.tx1 = self._create_mock_deposit(
            txid="tx1",
            confirmed_height=-1,
            rbf_txids=["tx2"]
        )

        self.tx2 = self._create_mock_deposit(
            txid="tx2",
            confirmed_height=-1,
            rbf_txids=["tx3"]
        )

        self.tx3 = self._create_mock_deposit(
            txid="tx3",
            confirmed_height=700000,
            rbf_txids=[]
        )

    def _create_mock_deposit(self, txid, confirmed_height, rbf_txids):
        deposit = MagicMock(spec=EnrichedDepositInfo)
        deposit.bitcoin_txid = txid
        deposit.bitcoin_tx_output_index = 0
        deposit.confirmed_height = confirmed_height
        deposit.rbf_txids = rbf_txids
        return deposit

    def test_no_rbf_transactions(self):
        """Test with no RBF transactions."""
        deposits = [self.unconfirmed_no_rbf]

        updates = self.processor.process_rbf_transactions(deposits, self.stacks_chaintip)

        self.assertEqual(len(updates), 0, "No transactions should be marked as failed")

    def test_unconfirmed_with_confirmed_replacement(self):
        """Test with an unconfirmed transaction that has a confirmed replacement."""
        deposits = [self.unconfirmed_with_rbf, self.confirmed_replacement]

        updates = self.processor.process_rbf_transactions(deposits, self.stacks_chaintip)

        self.assertEqual(len(updates), 1, "One transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "unconfirmed_with_rbf")
        self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
        self.assertTrue("Replaced by confirmed tx" in updates[0].status_message)
        self.assertTrue("confirmed_replacement" in updates[0].status_message)

    def test_unconfirmed_with_unconfirmed_replacement(self):
        """Test with an unconfirmed transaction that has an unconfirmed replacement."""
        deposits = [self.unconfirmed_with_unconfirmed_rbf, self.another_unconfirmed]

        updates = self.processor.process_rbf_transactions(deposits, self.stacks_chaintip)

        self.assertEqual(len(updates), 0, "No transactions should be marked as failed")

    def test_complex_rbf_chain(self):
        """Test with a complex RBF chain where the final transaction is confirmed."""
        deposits = [self.tx1, self.tx2, self.tx3]

        updates = self.processor.process_rbf_transactions(deposits, self.stacks_chaintip)

        self.assertEqual(len(updates), 2, "Two transactions should be marked as failed")
        txids = [update.bitcoin_txid for update in updates]
        self.assertIn("tx1", txids)
        self.assertIn("tx2", txids)

        for update in updates:
            self.assertEqual(update.status, RequestStatus.FAILED.value)
            self.assertTrue("Replaced by confirmed tx" in update.status_message)
            self.assertTrue("tx3" in update.status_message)

    def test_group_rbf_transactions(self):
        """Test the _group_rbf_transactions helper method."""
        # Create deposits with overlapping RBF chains
        tx_a = self._create_mock_deposit(txid="tx_a", confirmed_height=-1, rbf_txids=["tx_b"])
        tx_b = self._create_mock_deposit(txid="tx_b", confirmed_height=-1, rbf_txids=["tx_c"])
        tx_c = self._create_mock_deposit(txid="tx_c", confirmed_height=700000, rbf_txids=[])

        tx_d = self._create_mock_deposit(txid="tx_d", confirmed_height=-1, rbf_txids=["tx_e"])
        tx_e = self._create_mock_deposit(txid="tx_e", confirmed_height=-1, rbf_txids=[])

        # Create a deposit that connects the two chains
        tx_b_d = self._create_mock_deposit(txid="tx_b_d", confirmed_height=-1, rbf_txids=["tx_b", "tx_d"])

        deposits = [tx_a, tx_b, tx_c, tx_d, tx_e, tx_b_d]

        # Group the transactions
        groups = self.processor._group_rbf_transactions(deposits)

        # With the fixed implementation, we expect a single group containing all transactions
        self.assertEqual(len(groups), 1, "Should have one group")

        # The group should contain all txids
        group_txids = next(iter(groups.values()))
        expected_txids = {"tx_a", "tx_b", "tx_c", "tx_d", "tx_e", "tx_b_d"}
        self.assertEqual(group_txids, expected_txids)

class TestMempoolRbfApi(unittest.TestCase):
    """Tests for the MempoolAPI.check_for_rbf method."""

    def setUp(self):
        # Load test fixtures
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')

        with open(os.path.join(fixtures_dir, 'fixture-mempool-rbf-multi.json'), 'r') as f:
            self.rbf_data = json.load(f)

        with open(os.path.join(fixtures_dir, 'fixture-mempool-rbf-empty.json'), 'r') as f:
            self.empty_rbf_data = json.load(f)

    @patch('app.clients.mempool.MempoolAPI.get')
    def test_check_for_rbf_with_replacements(self, mock_get):
        """Test checking for RBF with replacements."""
        mock_get.return_value = self.rbf_data

        txids = MempoolAPI.check_for_rbf("some_txid")

        mock_get.assert_called_once_with("/v1/tx/some_txid/rbf")
        self.assertEqual(len(txids), 8, "Should have 8 replacement txids")
        self.assertIn("afe18f246b9624b17b21f2ebf84594bb75b582209d55dfc0b6edb34bfb785c3a", txids)

    @patch('app.clients.mempool.MempoolAPI.get')
    def test_check_for_rbf_without_replacements(self, mock_get):
        """Test checking for RBF without replacements."""
        mock_get.return_value = self.empty_rbf_data

        txids = MempoolAPI.check_for_rbf("some_txid")

        mock_get.assert_called_once_with("/v1/tx/some_txid/rbf")
        self.assertEqual(len(txids), 0, "Should have no replacement txids")
