import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.models import EnrichedDepositInfo, BlockInfo, RequestStatus, DepositUpdate, DepositInfo
from app.services.deposit_processor import DepositProcessor
from app import settings


class TestDepositProcessorBase(unittest.TestCase):
    """Base class for DepositProcessor tests with common setup."""

    def setUp(self):
        self.processor = DepositProcessor()
        self.current_time = int(datetime.now().timestamp())

        # Mock blockchain state
        self.bitcoin_chaintip = BlockInfo(height=1000, hash="btc_hash", time=self.current_time)
        self.stacks_chaintip = BlockInfo(height=500, hash="stx_hash", time=self.current_time)

    def _create_mock_deposit(self, txid, confirmed_height, lock_time, rbf_txids=None):
        """Helper method to create mock deposits."""
        deposit = MagicMock(spec=EnrichedDepositInfo)
        deposit.bitcoin_txid = txid
        deposit.bitcoin_tx_output_index = 0
        deposit.confirmed_height = confirmed_height
        deposit.lock_time = lock_time
        deposit.rbf_txids = rbf_txids or []
        return deposit


class TestExpiredLocktimeProcessor(TestDepositProcessorBase):
    """Tests for the process_expired_locktime method."""

    def setUp(self):
        super().setUp()

        # Override blockchain state for these specific tests
        self.bitcoin_chaintip = BlockInfo(height=100, hash="btc_hash", time=self.current_time)
        self.stacks_chaintip = BlockInfo(height=50, hash="stx_hash", time=self.current_time)

        # Create test deposits
        self.confirmed_expired = self._create_mock_deposit(
            txid="confirmed_expired",
            confirmed_height=80,  # Confirmed 20 blocks ago
            lock_time=10  # Locktime of 10 blocks
        )

        self.confirmed_active = self._create_mock_deposit(
            txid="confirmed_active",
            confirmed_height=95,  # Confirmed 5 blocks ago
            lock_time=10  # Locktime of 10 blocks
        )

        self.unconfirmed = self._create_mock_deposit(
            txid="unconfirmed",
            confirmed_height=-1,  # Not confirmed
            lock_time=5
        )

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

    @patch('app.settings.MIN_BLOCK_CONFIRMATIONS', 10)  # Increase confirmations required
    def test_with_custom_confirmations(self):
        # Test with a custom confirmations setting
        # Create a deposit that would expire with default settings but not with increased confirmations
        edge_case = self._create_mock_deposit(
            txid="edge_case",
            confirmed_height=85,  # Just 15 blocks ago
            lock_time=10  # Locktime of 10 blocks
        )

        deposits = [edge_case]

        updates = self.processor.process_expired_locktime(
            deposits, self.bitcoin_chaintip, self.stacks_chaintip
        )

        # With MIN_BLOCK_CONFIRMATIONS=10, this should not be marked as expired yet
        self.assertEqual(len(updates), 0, "Transaction should not be marked as failed with increased confirmations")


class TestDepositProcessorWithRbf(TestDepositProcessorBase):
    """Tests for the DepositProcessor with RBF functionality."""

    def setUp(self):
        super().setUp()

        # Create mock deposits for testing
        self.expired_locktime = self._create_mock_deposit(
            txid="expired_locktime_tx",
            confirmed_height=900,  # Confirmed 100 blocks ago
            lock_time=50  # Locktime of 50 blocks
        )

        self.rbf_original = self._create_mock_deposit(
            txid="rbf_original_tx",
            confirmed_height=-1,  # Not confirmed
            lock_time=0,
            rbf_txids=["rbf_replacement_tx"]
        )

        self.rbf_replacement = self._create_mock_deposit(
            txid="rbf_replacement_tx",
            confirmed_height=990,  # Confirmed
            lock_time=20
        )

    @patch('app.clients.PublicEmilyAPI.fetch_deposits')
    @patch('app.clients.PrivateEmilyAPI.update_deposits')
    @patch('app.clients.MempoolAPI.get_bitcoin_block_at')
    @patch('app.clients.HiroAPI.get_stacks_block')
    def test_update_deposits_workflow_with_rbf(self, mock_stacks_block, mock_btc_block,
                                             mock_update_deposits, mock_fetch_deposits):
        """Test the complete deposit update workflow with RBF."""
        # Set up mocks
        mock_btc_block.return_value = self.bitcoin_chaintip
        mock_stacks_block.return_value = self.stacks_chaintip

        # Mock deposit fetching
        pending_deposit = MagicMock(spec=DepositInfo)
        accepted_deposit = MagicMock(spec=DepositInfo)

        mock_fetch_deposits.side_effect = lambda status: {
            RequestStatus.PENDING: [pending_deposit],
            RequestStatus.ACCEPTED: [accepted_deposit]
        }[status]

        # Mock the _enrich_deposits method
        with patch.object(self.processor, '_enrich_deposits') as mock_enrich:
            # Return our test deposits when enriching
            mock_enrich.return_value = [
                self.expired_locktime,
                self.rbf_original,
                self.rbf_replacement
            ]

            # Run the update_deposits method
            self.processor.update_deposits()

            # Verify the correct API calls were made
            mock_fetch_deposits.assert_any_call(RequestStatus.PENDING)
            mock_fetch_deposits.assert_any_call(RequestStatus.ACCEPTED)

            # Verify the enrichment was called with both deposits
            mock_enrich.assert_called_once()

            # Verify the update was called with the correct updates
            mock_update_deposits.assert_called_once()
            updates = mock_update_deposits.call_args[0][0]

            # We expect 2 updates: one for expired_locktime_tx and one for rbf_original_tx
            self.assertEqual(len(updates), 2)
            # Let's check the actual updates to understand what's happening
            update_txids = [update.bitcoin_txid for update in updates]
            self.assertIn("expired_locktime_tx", update_txids, "Should include expired locktime transaction")
            self.assertIn("rbf_original_tx", update_txids, "Should include RBF original transaction")

            # Count the updates by type
            expired_locktime_updates = [u for u in updates if u.bitcoin_txid == "expired_locktime_tx"]
            rbf_updates = [u for u in updates if u.bitcoin_txid == "rbf_original_tx"]

            self.assertEqual(len(expired_locktime_updates), 1, "Should have 1 expired locktime update")
            self.assertEqual(len(rbf_updates), 1, "Should have 1 RBF update")

            # Check the status messages
            for update in updates:
                if update.bitcoin_txid == "expired_locktime_tx":
                    self.assertTrue("Locktime expired" in update.status_message)
                elif update.bitcoin_txid == "rbf_original_tx":
                    self.assertTrue("Replaced by confirmed tx" in update.status_message)

    @patch('app.clients.MempoolAPI.get_bitcoin_transaction')
    @patch('app.clients.MempoolAPI.check_for_rbf')
    def test_enrich_deposits_with_rbf(self, mock_check_rbf, mock_get_tx):
        """Test the deposit enrichment process with RBF."""
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
            "status": {"block_height": -1, "block_time": -1}  # Unconfirmed
        }

        tx2_data = {
            "vin": [{"prevout": {"value": 2000000}}],
            "vout": [{"scriptpubkey_address": "bc1q...", "value": 1900000}],
            "fee": 100000,
            "status": {"block_height": 700000, "block_time": self.current_time - 3600}  # Confirmed
        }

        mock_get_tx.side_effect = lambda txid: tx1_data if txid == "tx1" else tx2_data

        # Mock the RBF check
        mock_check_rbf.side_effect = lambda txid: {"replacement1", "replacement2"} if txid == "tx1" else set()

        # Mock the from_deposit_info method
        with patch('app.models.EnrichedDepositInfo.from_deposit_info') as mock_from_info:
            # Set up the mock returns
            enriched1 = MagicMock(spec=EnrichedDepositInfo)
            enriched2 = MagicMock(spec=EnrichedDepositInfo)

            mock_from_info.side_effect = [enriched1, enriched2]

            # Run the _enrich_deposits method
            result = self.processor._enrich_deposits([deposit1, deposit2])

            # Verify the correct methods were called
            mock_get_tx.assert_any_call("tx1")
            mock_get_tx.assert_any_call("tx2")

            # Verify RBF check was called only for the unconfirmed transaction
            mock_check_rbf.assert_called_once_with("tx1")

            # Verify from_deposit_info was called with the correct parameters
            self.assertEqual(mock_from_info.call_count, 2)

            # Check the additional_info for the first call (unconfirmed tx)
            additional_info1 = mock_from_info.call_args_list[0][0][1]
            self.assertCountEqual(additional_info1["rbf_txids"], {"replacement1", "replacement2"})

            # Check the additional_info for the second call (confirmed tx)
            additional_info2 = mock_from_info.call_args_list[1][0][1]
            self.assertEqual(additional_info2["rbf_txids"], set())


class TestDepositProcessor(TestDepositProcessorBase):
    """Tests for the DepositProcessor class."""

    def setUp(self):
        super().setUp()

        # Override blockchain state for these specific tests
        self.bitcoin_chaintip = BlockInfo(height=100, hash="btc_hash", time=self.current_time)
        self.stacks_chaintip = BlockInfo(height=50, hash="stx_hash", time=self.current_time)

        # Create mock deposits for testing
        self.expired_locktime = self._create_mock_deposit(
            txid="expired_locktime_tx",
            confirmed_height=80,  # Confirmed 20 blocks ago
            lock_time=10  # Locktime of 10 blocks
        )

        self.active_locktime = self._create_mock_deposit(
            txid="active_locktime_tx",
            confirmed_height=95,  # Confirmed 5 blocks ago
            lock_time=10  # Locktime of 10 blocks
        )

    @patch('app.clients.PublicEmilyAPI.fetch_deposits')
    @patch('app.clients.PrivateEmilyAPI.update_deposits')
    @patch('app.clients.MempoolAPI.get_bitcoin_block_at')
    @patch('app.clients.HiroAPI.get_stacks_block')
    def test_update_deposits_workflow(self, mock_stacks_block, mock_btc_block,
                                     mock_update_deposits, mock_fetch_deposits):
        """Test the complete deposit update workflow."""
        # Set up mocks
        mock_btc_block.return_value = self.bitcoin_chaintip
        mock_stacks_block.return_value = self.stacks_chaintip

        # Mock deposit fetching
        pending_deposit = MagicMock(spec=DepositInfo)
        accepted_deposit = MagicMock(spec=DepositInfo)

        mock_fetch_deposits.side_effect = lambda status: {
            RequestStatus.PENDING: [pending_deposit],
            RequestStatus.ACCEPTED: [accepted_deposit]
        }[status]

        # Mock the _enrich_deposits method
        with patch.object(self.processor, '_enrich_deposits') as mock_enrich:
            # Return our test deposits when enriching
            mock_enrich.return_value = [
                self.expired_locktime,
                self.active_locktime
            ]

            # Mock the processing methods to return known updates
            with patch.object(self.processor, 'process_expired_locktime') as mock_process_locktime:

                # Set up the mock returns
                locktime_update = DepositUpdate(
                    bitcoin_txid="expired_locktime_tx",
                    bitcoin_tx_output_index=0,
                    last_update_height=self.stacks_chaintip.height,
                    last_update_block_hash=self.stacks_chaintip.hash,
                    status=RequestStatus.FAILED.value,
                    status_message="Locktime expired"
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

    @patch('app.clients.MempoolAPI.get_bitcoin_transaction')
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
            "status": {"block_height": 100, "block_time": self.current_time - 3600}
        }

        # tx2 is not found in mempool
        tx2_data = {}

        mock_get_tx.side_effect = lambda txid: tx1_data if txid == "tx1" else tx2_data

        # Mock the from_deposit_info and from_missing methods
        with patch('app.models.EnrichedDepositInfo.from_deposit_info') as mock_from_info, \
             patch('app.models.EnrichedDepositInfo.from_missing') as mock_from_missing:

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
