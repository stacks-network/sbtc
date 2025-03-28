import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.models import EnrichedDepositInfo, BlockInfo, RequestStatus, DepositUpdate, DepositInfo
from app.services.deposit_processor import DepositProcessor
from app import settings


class TestExpiredLocktimeProcessor(unittest.TestCase):
    """Tests for the process_expired_locktime method."""

    def setUp(self):
        self.processor = DepositProcessor()
        self.current_time = int(datetime.now().timestamp())

        # Mock blockchain state
        self.bitcoin_chaintip = BlockInfo(height=1000, hash="btc_hash", time=self.current_time)
        self.stacks_chaintip = BlockInfo(height=100, hash="stx_hash", time=self.current_time)

        # Create test deposits
        self.confirmed_expired = self._create_mock_deposit(
            txid="confirmed_expired",
            confirmed_height=890,  # Confirmed 110 blocks ago
            lock_time=50,  # Locktime of 50 blocks
        )

        self.confirmed_active = self._create_mock_deposit(
            txid="confirmed_active",
            confirmed_height=990,  # Confirmed 10 blocks ago
            lock_time=50,  # Locktime of 50 blocks
        )

        self.unconfirmed = self._create_mock_deposit(
            txid="unconfirmed", confirmed_height=-1, lock_time=20  # Not confirmed
        )

    def _create_mock_deposit(self, txid, confirmed_height, lock_time):
        deposit = MagicMock(spec=EnrichedDepositInfo)
        deposit.bitcoin_txid = txid
        deposit.bitcoin_tx_output_index = 0
        deposit.confirmed_height = confirmed_height
        deposit.lock_time = lock_time
        return deposit

    def test_no_expired_locktime(self):
        # Test with only transactions that shouldn't be marked as failed
        deposits = [self.confirmed_active, self.unconfirmed]

        updates = self.processor.process_expired_locktime(
            deposits, self.bitcoin_chaintip, self.stacks_chaintip
        )

        self.assertEqual(len(updates), 0, "No transactions should be marked as failed")

    def test_expired_locktime(self):
        # Test with a transaction that should be marked as failed
        deposits = [self.confirmed_expired]

        updates = self.processor.process_expired_locktime(
            deposits, self.bitcoin_chaintip, self.stacks_chaintip
        )

        self.assertEqual(len(updates), 1, "One transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "confirmed_expired")
        self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
        self.assertTrue("Locktime expired" in updates[0].status_message)

    def test_mixed_transactions(self):
        # Test with a mix of transactions
        deposits = [self.confirmed_expired, self.confirmed_active, self.unconfirmed]

        updates = self.processor.process_expired_locktime(
            deposits, self.bitcoin_chaintip, self.stacks_chaintip
        )

        self.assertEqual(len(updates), 1, "Only one transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "confirmed_expired")

    @patch("app.settings.MIN_BLOCK_CONFIRMATIONS", 10)  # Increase confirmations required
    def test_with_custom_confirmations(self):
        # Test with a custom confirmations setting
        # Create a deposit that would expire with default settings but not with increased confirmations
        edge_case = self._create_mock_deposit(
            txid="edge_case",
            confirmed_height=944,  # Just 56 blocks ago
            lock_time=50,  # Locktime of 50 blocks
        )

        deposits = [edge_case]

        updates = self.processor.process_expired_locktime(
            deposits, self.bitcoin_chaintip, self.stacks_chaintip
        )

        # With MIN_BLOCK_CONFIRMATIONS=10, this should not be marked as expired yet
        self.assertEqual(
            len(updates),
            0,
            "Transaction should not be marked as failed with increased confirmations",
        )


class TestDepositProcessor(unittest.TestCase):
    """Tests for the DepositProcessor class."""

    def setUp(self):
        self.processor = DepositProcessor()
        self.current_time = int(datetime.now().timestamp())

        # Mock blockchain state
        self.bitcoin_chaintip = BlockInfo(height=1000, hash="btc_hash", time=self.current_time)
        self.stacks_chaintip = BlockInfo(height=100, hash="stx_hash", time=self.current_time)

        # Create mock deposits for testing
        self.mock_deposits = self._create_test_deposits()

    def _create_test_deposits(self):
        """Create a set of mock deposits for testing."""
        # Create a deposit with expired locktime
        expired_locktime = MagicMock(spec=EnrichedDepositInfo)
        expired_locktime.bitcoin_txid = "expired_locktime_tx"
        expired_locktime.bitcoin_tx_output_index = 0
        expired_locktime.confirmed_height = 890  # Confirmed 110 blocks ago
        expired_locktime.lock_time = 50  # Locktime of 50 blocks

        # Create a deposit with non-expired locktime
        active_locktime = MagicMock(spec=EnrichedDepositInfo)
        active_locktime.bitcoin_txid = "active_locktime_tx"
        active_locktime.bitcoin_tx_output_index = 0
        active_locktime.confirmed_height = 990  # Confirmed 10 blocks ago
        active_locktime.lock_time = 50  # Locktime of 50 blocks

        return {
            "expired_locktime": expired_locktime,
            "active_locktime": active_locktime,
        }

    @patch("app.clients.PublicEmilyAPI.fetch_deposits")
    @patch("app.clients.PrivateEmilyAPI.update_deposits")
    @patch("app.clients.MempoolAPI.get_block_at")
    @patch("app.clients.HiroAPI.get_stacks_block")
    def test_update_deposits_workflow(
        self, mock_stacks_block, mock_btc_block, mock_update_deposits, mock_fetch_deposits
    ):
        """Test the complete deposit update workflow."""
        # Set up mocks
        mock_btc_block.return_value = self.bitcoin_chaintip
        mock_stacks_block.return_value = self.stacks_chaintip

        # Mock deposit fetching
        pending_deposit = MagicMock(spec=DepositInfo)
        accepted_deposit = MagicMock(spec=DepositInfo)

        mock_fetch_deposits.side_effect = lambda status: {
            RequestStatus.PENDING: [pending_deposit],
            RequestStatus.ACCEPTED: [accepted_deposit],
        }[status]

        # Mock the _enrich_deposits method
        with patch.object(self.processor, "_enrich_deposits") as mock_enrich:
            # Return our test deposits when enriching
            mock_enrich.return_value = [
                self.mock_deposits["expired_locktime"],
                self.mock_deposits["active_locktime"],
            ]

            # Mock the processing methods to return known updates
            with patch.object(self.processor, "process_expired_locktime") as mock_process_locktime:

                # Set up the mock returns
                locktime_update = DepositUpdate(
                    bitcoin_txid="expired_locktime_tx",
                    bitcoin_tx_output_index=0,
                    status=RequestStatus.FAILED.value,
                    status_message="Locktime expired",
                )

                mock_process_locktime.return_value = [locktime_update]

                # Run the update_deposits method
                self.processor.update_deposits()

                # Verify the correct API calls were made
                mock_fetch_deposits.assert_any_call(RequestStatus.PENDING)
                mock_fetch_deposits.assert_any_call(RequestStatus.ACCEPTED)

                # Verify the enrichment was called with both deposits
                mock_enrich.assert_called_once()
                self.assertEqual(len(list(mock_enrich.call_args[0][0])), 2)

                # Verify the processing methods were called
                mock_process_locktime.assert_called_once()

                # Verify the update was called with the locktime update
                mock_update_deposits.assert_called_once()
                updates = mock_update_deposits.call_args[0][0]
                self.assertEqual(len(updates), 1)
                self.assertEqual(updates[0].bitcoin_txid, "expired_locktime_tx")

    @patch("app.clients.MempoolAPI.get_transaction")
    def test_enrich_deposits(self, mock_get_tx):
        """Test the deposit enrichment process."""
        # Create test deposits
        deposit1 = MagicMock(spec=DepositInfo)
        deposit1.bitcoin_txid = "tx1"

        deposit2 = MagicMock(spec=DepositInfo)
        deposit2.bitcoin_txid = "tx2"

        # Mock the transaction data returned by the Mempool API
        tx1_data = {
            "vin": [{"prevout": {"value": 2000000}}],
            "vout": [{"scriptpubkey_address": "bc1q...", "value": 1900000}],
            "fee": 100000,
            "status": {"block_height": 1000, "block_time": self.current_time - 3600},
        }

        # tx2 is not found in mempool
        tx2_data = {}

        mock_get_tx.side_effect = lambda txid: tx1_data if txid == "tx1" else tx2_data

        # Mock the from_deposit_info and from_missing methods
        with patch("app.models.EnrichedDepositInfo.from_deposit_info") as mock_from_info, patch(
            "app.models.EnrichedDepositInfo.from_missing"
        ) as mock_from_missing:

            # Set up the mock returns
            enriched1 = MagicMock(spec=EnrichedDepositInfo)
            enriched2 = MagicMock(spec=EnrichedDepositInfo)

            mock_from_info.return_value = enriched1
            mock_from_missing.return_value = enriched2

            # Run the _enrich_deposits method
            result = self.processor._enrich_deposits([deposit1, deposit2])

            # Verify the correct methods were called
            mock_get_tx.assert_any_call("tx1")
            mock_get_tx.assert_any_call("tx2")

            mock_from_info.assert_called_once()
            mock_from_missing.assert_called_once()

            # Verify the result contains both enriched deposits
            self.assertEqual(len(result), 2)
            self.assertIn(enriched1, result)
            self.assertIn(enriched2, result)
