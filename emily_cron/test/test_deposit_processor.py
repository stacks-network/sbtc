import unittest
import json
import os
from datetime import datetime, UTC
from unittest.mock import patch, MagicMock

from app.models import EnrichedDepositInfo, RequestStatus, DepositInfo
from app.services.deposit_processor import DepositProcessor
from app import settings
from app.clients import MempoolAPI, ElectrsAPI


# Load fixtures from JSON file
FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "transactions.json")
with open(FIXTURES_PATH, "r") as f:
    TRANSACTION_FIXTURES = json.load(f)

RECLAIMED_DEPOSIT_DATA = TRANSACTION_FIXTURES["reclaimed_deposit"]["deposit_info"]
RECLAIM_SPENDING_TX_DATA = TRANSACTION_FIXTURES["reclaimed_deposit"]["spending_tx_data"]
RECLAIMED_UTXO_TX_OUTSPENT = TRANSACTION_FIXTURES["reclaimed_deposit"]["utxo_outspent"]

ACCEPTED_DEPOSIT_DATA = TRANSACTION_FIXTURES["accepted_deposit"]["deposit_info"]
ACCEPTED_DEPOSIT_DATA_TX = TRANSACTION_FIXTURES["accepted_deposit"]["deposit_tx_data"]
ACCEPTED_SPENDING_TX_DATA = TRANSACTION_FIXTURES["accepted_deposit"]["spending_tx_data"]
ACCEPTED_UTXO_TX_OUTSPENT = TRANSACTION_FIXTURES["accepted_deposit"]["utxo_outspent"]

INFLIGHT_UTXO_STATUS = TRANSACTION_FIXTURES["inflight_utxo"]


class TestDepositProcessorBase(unittest.TestCase):
    """Base class for DepositProcessor tests with common setup."""

    def setUp(self):
        self.processor = DepositProcessor()
        self.current_time = int(datetime.now(UTC).timestamp())

        # Mock blockchain state
        self.bitcoin_chaintip_height = 1000

    def _create_mock_deposit(
        self,
        txid,
        confirmed_height,
        lock_time,
        rbf_txids=None,
        in_mempool=False,
        deposit_last_update=None,
        status=RequestStatus.PENDING.value,
    ):
        """Helper method to create mock deposits."""
        deposit = MagicMock(spec=EnrichedDepositInfo)
        deposit.bitcoin_txid = txid
        deposit.bitcoin_tx_output_index = 0
        deposit.confirmed_height = confirmed_height
        deposit.lock_time = lock_time
        deposit.rbf_txids = rbf_txids or []
        deposit.is_expired = lambda x: EnrichedDepositInfo.is_expired(deposit, x)
        deposit.in_mempool = in_mempool
        deposit.deposit_last_update = lambda: deposit_last_update or int(datetime.now().timestamp())
        deposit.status = status
        return deposit


class TestExpiredLocktimeProcessor(TestDepositProcessorBase):
    """Tests for the process_expired_locktime method."""

    def setUp(self):
        super().setUp()

        # Create test deposits
        self.confirmed_expired = self._create_mock_deposit(
            txid="confirmed_expired",
            confirmed_height=890,  # Confirmed 110 blocks ago (890 + 50 + 6 = 946 < 1000)
            lock_time=50,  # Locktime of 50 blocks
        )

        self.confirmed_active = self._create_mock_deposit(
            txid="confirmed_active",
            confirmed_height=990,  # Confirmed 10 blocks ago (990 + 50 + 6 = 1046 > 1000)
            lock_time=50,  # Locktime of 50 blocks
        )

        self.unconfirmed = self._create_mock_deposit(
            txid="unconfirmed",
            confirmed_height=None,  # Not confirmed
            lock_time=20,
        )

    def test_no_failures(self):
        """Test case where no deposits should be marked as failed."""
        # Includes active deposits (spent and unspent) and unconfirmed
        deposits = [self.confirmed_active, self.unconfirmed]

        updates = self.processor.process_expired_locktime(deposits, self.bitcoin_chaintip_height)

        self.assertEqual(len(updates), 0, "No transactions should be marked as failed")

    def test_failure_expired_unspent(self):
        """Test case where a deposit is failed because locktime passed and UTXO is unspent."""
        # Mock get_utxo_status to return unspent for the deposit that passes the time check
        with patch(
            "app.clients.ElectrsAPI.get_utxo_status", return_value={"spent": False}
        ) as mock_utxo_status:
            deposits = [self.confirmed_expired]
            updates = self.processor.process_expired_locktime(
                deposits, self.bitcoin_chaintip_height
            )

            mock_utxo_status.assert_called_once_with(
                self.confirmed_expired.bitcoin_txid,
                self.confirmed_expired.bitcoin_tx_output_index,
            )
        self.assertEqual(len(updates), 1, "One transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "confirmed_expired")
        self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
        self.assertTrue("Locktime expired" in updates[0].status_message)

    def test_no_failure_expired_spent_signer(self):
        """Test case where locktime passed, but UTXO is spent (signer sweep), so it should NOT fail."""
        # Mock UTXO status (spent) and spending tx (no reclaim script)
        confirmed_expired_spent_mempool = self._create_mock_deposit(
            txid="confirmed_expired_spent_mempool",
            confirmed_height=890,  # Confirmed 110 blocks ago
            lock_time=50,  # Locktime of 50 blocks
        )

        utxo_status_spent = {
            "spent": True,
            "txid": "signer_sweep_tx",
            "vin": 0,
            "status": {"confirmed": False},
        }
        spending_tx_signer = {
            "txid": "signer_sweep_tx",
            "vin": [
                {
                    "txid": confirmed_expired_spent_mempool.bitcoin_txid,
                    "vout": confirmed_expired_spent_mempool.bitcoin_tx_output_index,
                    "witness": ["signer_sig1", "signer_sig2"],  # Does NOT contain reclaim script
                }
            ],
        }

        with (
            patch(
                "app.clients.ElectrsAPI.get_utxo_status", return_value=utxo_status_spent
            ) as mock_utxo,
            patch(
                "app.clients.MempoolAPI.get_transaction", return_value=spending_tx_signer
            ) as mock_tx,
        ):

            # We need to use a deposit that actually has a reclaim script defined
            deposit_with_script = self._create_mock_deposit(
                txid="confirmed_expired_spent_mempool",
                confirmed_height=890,
                lock_time=50,
            )
            deposit_with_script.reclaim_script = "reclaim_hex_placeholder"  # Assign a dummy script

            deposits = [deposit_with_script]
            updates = self.processor.process_expired_locktime(
                deposits, self.bitcoin_chaintip_height
            )

            mock_utxo.assert_called_once()
            mock_tx.assert_called_once_with("signer_sweep_tx")
            self.assertEqual(
                len(updates), 0, "Transactions spent by signer should not be marked failed"
            )

    def test_failure_reclaimed(self):
        """Test case where the deposit UTXO was spent via reclaim."""
        reclaim_script_hex = "0340000051"  # Example: Locktime 64, OP_TRUE
        reclaimed_deposit = self._create_mock_deposit(
            txid="reclaimed_tx",
            confirmed_height=890,
            lock_time=64,  # Matches hex above for consistency
        )
        # Assign the actual reclaim script hex used in the mocked spending tx witness
        reclaimed_deposit.reclaim_script = reclaim_script_hex

        # Mock UTXO status (spent) and spending tx (contains reclaim script)
        utxo_status_reclaim = {
            "spent": True,
            "txid": "reclaim_spending_tx",
            "vin": 0,
            "status": {"confirmed": True},
        }
        spending_tx_reclaim = {
            "txid": "reclaim_spending_tx",
            "vin": [
                {
                    "txid": reclaimed_deposit.bitcoin_txid,
                    "vout": reclaimed_deposit.bitcoin_tx_output_index,
                    "witness": [
                        "sig_data",
                        "pubkey_data",
                        reclaim_script_hex,
                    ],  # Contains reclaim script hex
                }
            ],
        }

        with (
            patch(
                "app.clients.ElectrsAPI.get_utxo_status", return_value=utxo_status_reclaim
            ) as mock_utxo,
            patch(
                "app.clients.MempoolAPI.get_transaction", return_value=spending_tx_reclaim
            ) as mock_tx,
        ):

            deposits = [reclaimed_deposit]
            updates = self.processor.process_expired_locktime(
                deposits, self.bitcoin_chaintip_height
            )

            mock_utxo.assert_called_once()
            mock_tx.assert_called_once_with("reclaim_spending_tx")
            self.assertEqual(len(updates), 1, "Reclaimed transaction should be marked failed")
            self.assertEqual(updates[0].bitcoin_txid, "reclaimed_tx")
            self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
            self.assertTrue("Depositor reclaim detected" in updates[0].status_message)

    def test_mixed_transactions_failures(self):
        """Test with a mix of transactions, only expired-unspent and reclaimed should fail."""

        # --- Mock Data Setup ---
        reclaim_script_hex_1 = "0340000051"  # 64 blocks
        reclaim_script_hex_2 = "0350000051"  # 80 blocks

        # Deposits
        d_expired_unspent = self._create_mock_deposit(
            txid="exp_unspent", confirmed_height=890, lock_time=50
        )
        d_expired_spent_signer = self._create_mock_deposit(
            txid="exp_signer", confirmed_height=890, lock_time=50
        )
        d_active_unspent = self._create_mock_deposit(
            txid="active_unspent", confirmed_height=990, lock_time=50
        )
        d_reclaimed = self._create_mock_deposit(
            txid="reclaimed", confirmed_height=880, lock_time=64
        )
        d_unconfirmed = self._create_mock_deposit(
            txid="unconfirmed", confirmed_height=None, lock_time=20
        )

        # Assign reclaim scripts needed for checks where UTXO is spent
        d_expired_spent_signer.reclaim_script = reclaim_script_hex_1
        d_reclaimed.reclaim_script = reclaim_script_hex_2

        # Mock UTXO Statuses (maps (txid, vout) -> status_dict)
        utxo_statuses = {
            ("exp_unspent", 0): {"spent": False},
            ("exp_signer", 0): {"spent": True, "txid": "signer_tx", "vin": 0},
            ("reclaimed", 0): {"spent": True, "txid": "reclaim_tx", "vin": 0},
            # No entries needed for active_unspent or unconfirmed as time check fails
        }

        # Mock Spending Transactions (maps spending_txid -> tx_details_dict)
        spending_txs = {
            "signer_tx": {
                "vin": [{"txid": "exp_signer", "vout": 0, "witness": ["sig"]}]
            },  # No reclaim script
            "reclaim_tx": {
                "vin": [{"txid": "reclaimed", "vout": 0, "witness": ["sig", reclaim_script_hex_2]}]
            },  # Contains reclaim script
        }

        # Side effect functions for mocks
        def mock_get_utxo_status(txid, vout):
            return utxo_statuses.get((txid, vout), {})

        def mock_get_transaction(txid):
            return spending_txs.get(txid)

        # --- End Mock Data Setup ---

        deposits_to_process = [
            d_expired_unspent,
            d_expired_spent_signer,
            d_active_unspent,
            d_reclaimed,
            d_unconfirmed,
        ]

        # Patch the API calls
        with (
            patch(
                "app.clients.ElectrsAPI.get_utxo_status", side_effect=mock_get_utxo_status
            ) as mock_utxo,
            patch(
                "app.clients.MempoolAPI.get_transaction", side_effect=mock_get_transaction
            ) as mock_tx,
        ):

            # Run the processor method
            updates = self.processor.process_expired_locktime(
                deposits_to_process, self.bitcoin_chaintip_height
            )

            # Assertions
            self.assertEqual(len(updates), 2, "Only expired-unspent and reclaimed should fail")
            failed_txids = {u.bitcoin_txid for u in updates}
            self.assertIn("exp_unspent", failed_txids)
            self.assertIn("reclaimed", failed_txids)

            # Check API calls (only called for deposits passing time check)
            self.assertEqual(mock_utxo.call_count, 3)  # exp_unspent, exp_signer, reclaimed
            mock_utxo.assert_any_call("exp_unspent", 0)
            mock_utxo.assert_any_call("exp_signer", 0)
            mock_utxo.assert_any_call("reclaimed", 0)

            self.assertEqual(mock_tx.call_count, 2)  # signer_tx, reclaim_tx
            mock_tx.assert_any_call("signer_tx")
            mock_tx.assert_any_call("reclaim_tx")

    @patch("app.settings.MIN_BLOCK_CONFIRMATIONS", 10)  # Increase confirmations required
    def test_with_custom_confirmations_failures(self):
        """Test failure logic with custom confirmations."""
        # Deposits meeting time condition with custom confirmations (1000 >= 940 + 50 + 10)
        edge_case_unspent = self._create_mock_deposit(
            txid="edge_case_unspent", confirmed_height=940, lock_time=50
        )
        edge_case_spent_not_reclaim = self._create_mock_deposit(
            txid="edge_case_spent", confirmed_height=940, lock_time=50
        )
        edge_case_spent_not_reclaim.reclaim_script = "edge_reclaim_hex"  # Needed for reclaim check

        # --- Test Unspent Case ---
        with patch(
            "app.clients.ElectrsAPI.get_utxo_status", return_value={"spent": False}
        ) as mock_utxo_unspent:
            updates_unspent = self.processor.process_expired_locktime(
                [edge_case_unspent], self.bitcoin_chaintip_height
            )
            # Assertions for unspent case
            mock_utxo_unspent.assert_called_once_with(edge_case_unspent.bitcoin_txid, 0)
            self.assertEqual(
                len(updates_unspent), 1, "Unspent edge case should fail as time condition met"
            )
            self.assertEqual(updates_unspent[0].bitcoin_txid, "edge_case_unspent")

        # --- Test Spent (Signer) Case ---
        utxo_status_edge_spent = {"spent": True, "txid": "edge_signer_tx", "vin": 0}
        spending_tx_edge_signer = {
            "vin": [{"txid": "edge_case_spent", "vout": 0, "witness": ["sig"]}]
        }

        with (
            patch(
                "app.clients.ElectrsAPI.get_utxo_status", return_value=utxo_status_edge_spent
            ) as mock_utxo_spent,
            patch(
                "app.clients.MempoolAPI.get_transaction", return_value=spending_tx_edge_signer
            ) as mock_tx_spent,
        ):

            updates_spent = self.processor.process_expired_locktime(
                [edge_case_spent_not_reclaim], self.bitcoin_chaintip_height
            )
            # Assertions for spent (signer) case
            mock_utxo_spent.assert_called_once_with(edge_case_spent_not_reclaim.bitcoin_txid, 0)
            mock_tx_spent.assert_called_once_with("edge_signer_tx")
            self.assertEqual(len(updates_spent), 0, "Spent (signer) edge case should NOT fail")


# Reset confirmations after test class
def tearDownModule():
    settings.MIN_BLOCK_CONFIRMATIONS = 6


class TestDepositProcessorWithRbf(TestDepositProcessorBase):
    """Tests for the DepositProcessor with RBF functionality."""

    def setUp(self):
        super().setUp()
        settings.MIN_BLOCK_CONFIRMATIONS = 6

        # Create mock deposits for testing
        self.expired_locktime = self._create_mock_deposit(
            txid="expired_locktime_tx",
            confirmed_height=900,  # Confirmed 100 blocks ago
            lock_time=50,  # Locktime of 50 blocks
        )

        self.rbf_original = self._create_mock_deposit(
            txid="rbf_original_tx",
            confirmed_height=None,  # Not confirmed
            lock_time=0,
            rbf_txids=["rbf_replacement_tx", "rbf_original_tx"],
            deposit_last_update=int(datetime.now().timestamp()) - 3600,  # 1 hour ago
        )

        self.rbf_replacement = self._create_mock_deposit(
            txid="rbf_replacement_tx",
            confirmed_height=994,  # Confirmed 6 blocks ago
            lock_time=20,
            rbf_txids=["rbf_replacement_tx", "rbf_original_tx"],
        )

    @patch("app.clients.PublicEmilyAPI.fetch_deposits")
    @patch("app.clients.PrivateEmilyAPI.update_deposits")
    @patch("app.clients.ElectrsAPI.get_utxo_status")
    @patch("app.clients.MempoolAPI.get_tip_height")
    def test_update_deposits_workflow_with_rbf(
        self,
        mock_btc_tip_height,
        mock_get_utxo_status,
        mock_update_deposits,
        mock_fetch_deposits,
    ):
        """Test the complete deposit update workflow with RBF."""
        # Set up mocks
        # Ensure chaintip is high enough for rbf_replacement to be considered confirmed
        mock_btc_tip_height.return_value = self.bitcoin_chaintip_height
        mock_get_utxo_status.return_value = {"spent": False}

        # Create a long pending deposit for testing
        long_pending = self._create_mock_deposit(
            txid="long_pending_tx",
            confirmed_height=None,
            lock_time=0,
            deposit_last_update=int(datetime.now().timestamp())
            - settings.MAX_UNCONFIRMED_TIME
            - 3600,
            status=RequestStatus.PENDING.value,
        )

        # Mock enrichment and RBF registration (tested separately)
        with (
            patch.object(self.processor, "_enrich_deposits") as mock_enrich,
            patch.object(self.processor, "register_rbf_deposits", return_value=0) as mock_register,
        ):
            # Return our test deposits when enriching
            mock_enrich.return_value = [
                self.expired_locktime,
                self.rbf_original,
                self.rbf_replacement,
                long_pending,
            ]

            # Run the update_deposits method
            self.processor.update_deposits()
            # Verify the correct API calls were made
            mock_fetch_deposits.assert_any_call(RequestStatus.PENDING)
            mock_fetch_deposits.assert_any_call(RequestStatus.ACCEPTED)

            # Verify the enrichment was called with both deposits
            mock_enrich.assert_called_once()
            mock_register.assert_called_once()

            # Verify the get_utxo_status was called for the expired_locktime deposit
            mock_get_utxo_status.assert_called_once()

            # Verify the update was called with the correct updates
            mock_update_deposits.assert_called_once()
            updates = mock_update_deposits.call_args[0][0]

            # We expect 3 updates: one for expired_locktime_tx, one for rbf_original_tx, and one for long_pending_tx
            self.assertEqual(len(updates), 3)
            # Let's check the actual updates to understand what's happening
            update_txids = [update.bitcoin_txid for update in updates]
            self.assertIn(
                "expired_locktime_tx", update_txids, "Should include expired locktime transaction"
            )
            self.assertIn(
                "rbf_original_tx", update_txids, "Should include RBF original transaction"
            )
            self.assertIn(
                "long_pending_tx", update_txids, "Should include long pending transaction"
            )

            # Count the updates by type
            expired_locktime_updates = [
                u for u in updates if u.bitcoin_txid == "expired_locktime_tx"
            ]
            rbf_updates = [u for u in updates if u.bitcoin_txid == "rbf_original_tx"]
            long_pending_updates = [u for u in updates if u.bitcoin_txid == "long_pending_tx"]

            self.assertEqual(
                len(expired_locktime_updates), 1, "Should have 1 expired locktime update"
            )
            self.assertEqual(len(rbf_updates), 1, "Should have 1 RBF update")
            self.assertEqual(len(long_pending_updates), 1, "Should have 1 long pending update")

            # Check the status messages
            for update in updates:
                if update.bitcoin_txid == "expired_locktime_tx":
                    self.assertTrue("Locktime expired" in update.status_message)
                elif update.bitcoin_txid == "rbf_original_tx":
                    self.assertTrue("Replaced by confirmed tx" in update.status_message)
                    self.assertEqual(update.status, RequestStatus.RBF.value)
                    self.assertEqual(update.replaced_by_tx, "rbf_replacement_tx")
                elif update.bitcoin_txid == "long_pending_tx":
                    self.assertTrue(
                        f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)"
                        in update.status_message
                    )

    @patch("app.clients.MempoolAPI.get_transaction")
    @patch("app.clients.MempoolAPI.check_for_rbf")
    def test_enrich_deposits_with_rbf(self, mock_check_rbf, mock_get_tx):
        """Test the deposit enrichment process with RBF."""
        # Create test deposits
        deposit1 = self._create_mock_deposit(
            txid="replacement1",
            confirmed_height=None,
            lock_time=10,
        )
        deposit2 = self._create_mock_deposit(
            txid="replacement2",
            confirmed_height=700000,
            lock_time=10,
        )

        # Mock the transaction data returned by the Mempool API
        tx1_data = {
            "vin": [{"prevout": {"value": 2000000}}],
            "vout": [{"scriptpubkey_address": "bc1q...", "value": 1900000}],
            "fee": 100000,
            "status": {"block_height": None, "block_time": None},  # Unconfirmed
        }

        tx2_data = {
            "vin": [{"prevout": {"value": 2000000}}],
            "vout": [{"scriptpubkey_address": "bc1q...", "value": 1900000}],
            "fee": 100000,
            "status": {"block_height": 700000, "block_time": self.current_time - 3600},  # Confirmed
        }

        mock_get_tx.side_effect = lambda txid: tx1_data if txid == "replacement1" else tx2_data

        # Mock the RBF check
        mock_check_rbf.side_effect = lambda txid: (
            ["replacement1", "replacement2"] if txid == "replacement1" else []
        )

        # Mock the from_deposit_info method, because MagicMock would not work with asdict
        with patch("app.models.EnrichedDepositInfo.from_deposit_info") as mock_from_info:
            # Set up the mock returns
            def mock_from_info_side_effect(deposit, additional_info):
                enriched = MagicMock(spec=EnrichedDepositInfo)
                enriched.bitcoin_txid = deposit.bitcoin_txid
                enriched.confirmed_height = additional_info.get("confirmed_height")
                enriched.confirmed_time = additional_info.get("confirmed_time")
                enriched.fee = additional_info.get("fee")
                enriched.in_mempool = additional_info.get("in_mempool", False)
                enriched.rbf_txids = additional_info.get("rbf_txids", [])
                return enriched

            mock_from_info.side_effect = mock_from_info_side_effect

            # Run the _enrich_deposits method
            result = self.processor._enrich_deposits([deposit1, deposit2])
            # Verify the correct methods were called
            mock_get_tx.assert_any_call("replacement1")
            mock_get_tx.assert_any_call("replacement2")

            # Verify RBF check was called only for the unconfirmed transaction
            mock_check_rbf.assert_called_once_with("replacement1")

            # Verify from_deposit_info was called with the correct parameters
            self.assertEqual(mock_from_info.call_count, 2)

            # Assertions on the configured mock results
            self.assertEqual(result[0].bitcoin_txid, deposit1.bitcoin_txid)
            self.assertEqual(result[0].confirmed_height, deposit1.confirmed_height)
            self.assertEqual(result[0].fee, 100000)
            self.assertEqual(result[0].in_mempool, True)
            self.assertEqual(result[0].rbf_txids, ["replacement1", "replacement2"])

            self.assertEqual(result[1].bitcoin_txid, deposit2.bitcoin_txid)
            self.assertEqual(result[1].confirmed_height, deposit2.confirmed_height)
            self.assertEqual(result[1].fee, 100000)
            self.assertEqual(result[1].in_mempool, True)
            self.assertEqual(result[1].rbf_txids, [])


class TestRegisterRbfDeposits(TestDepositProcessorBase):
    """Tests for registering valid RBF replacements as Emily deposits."""

    DEPOSIT_SCRIPT = (
        "1e000000000001388005168ac681961281d3c932210a3608ce28f0e819831d"
        "7520f898f8a6ddb86dd4608dd168355ec6135fe2839222240c01942e8e7e50dd4c89ac"
    )
    RECLAIM_SCRIPT = (
        "60b275207271dd92896e50c81052c4fd1c100a02e656fa3db43807549be345dc42114c84ac"
    )
    EXPECTED_SPK = "51200a7ef39302e03b8dd9bd44500165adb32fa9ef0ceb75231cb433040dc771c07d"

    def _deposit(self, txid: str, rbf_txids: list[str] | None = None) -> EnrichedDepositInfo:
        return EnrichedDepositInfo(
            bitcoin_txid=txid,
            bitcoin_tx_output_index=0,
            recipient="05168ac681961281d3c932210a3608ce28f0e819831d",
            amount=1000000,
            last_update_height=100,
            last_update_block_hash="hash",
            status=RequestStatus.PENDING.value,
            reclaim_script=self.RECLAIM_SCRIPT,
            deposit_script=self.DEPOSIT_SCRIPT,
            in_mempool=True,
            rbf_txids=rbf_txids or [],
        )

    @patch("app.services.deposit_processor.PublicEmilyAPI.create_deposit")
    @patch("app.services.deposit_processor.MempoolAPI.get_transaction_hex")
    @patch("app.services.deposit_processor.MempoolAPI.get_transaction")
    def test_registers_matching_replacement(
        self, mock_get_tx, mock_get_hex, mock_create_deposit
    ):
        original = self._deposit(
            "original_tx", rbf_txids=["original_tx", "replacement_tx", "unrelated_rbf_tx"]
        )
        mock_get_tx.side_effect = lambda txid: {
            "replacement_tx": {
                "txid": "replacement_tx",
                "vout": [
                    {"scriptpubkey": self.EXPECTED_SPK, "value": 1000000},
                    {"scriptpubkey": "5120" + "11" * 32, "value": 1000},
                ],
            },
            "unrelated_rbf_tx": {
                "txid": "unrelated_rbf_tx",
                "vout": [{"scriptpubkey": "5120" + "22" * 32, "value": 1000000}],
            },
        }.get(txid)
        mock_get_hex.return_value = "02000000000100deadbeef"
        mock_create_deposit.return_value = {"bitcoinTxid": "replacement_tx"}

        registered = self.processor.register_rbf_deposits([original])

        self.assertEqual(registered, 1)
        mock_create_deposit.assert_called_once()
        request = mock_create_deposit.call_args[0][0]
        self.assertEqual(request.bitcoin_txid, "replacement_tx")
        self.assertEqual(request.bitcoin_tx_output_index, 0)
        self.assertEqual(request.deposit_script, self.DEPOSIT_SCRIPT)
        self.assertEqual(request.reclaim_script, self.RECLAIM_SCRIPT)
        self.assertEqual(request.transaction_hex, "02000000000100deadbeef")
        mock_get_hex.assert_called_once_with("replacement_tx")

    @patch("app.services.deposit_processor.PublicEmilyAPI.create_deposit")
    @patch("app.services.deposit_processor.MempoolAPI.get_transaction_hex")
    @patch("app.services.deposit_processor.MempoolAPI.get_transaction")
    def test_skips_already_known_replacement(
        self, mock_get_tx, mock_get_hex, mock_create_deposit
    ):
        original = self._deposit("original_tx", rbf_txids=["original_tx", "replacement_tx"])
        already_registered = self._deposit("replacement_tx")
        mock_get_tx.return_value = {
            "txid": "replacement_tx",
            "vout": [{"scriptpubkey": self.EXPECTED_SPK, "value": 1000000}],
        }

        registered = self.processor.register_rbf_deposits([original, already_registered])

        self.assertEqual(registered, 0)
        mock_create_deposit.assert_not_called()
        mock_get_hex.assert_not_called()

    @patch("app.services.deposit_processor.PublicEmilyAPI.create_deposit")
    @patch("app.services.deposit_processor.MempoolAPI.get_transaction")
    def test_ignores_replacements_without_deposit_output(
        self, mock_get_tx, mock_create_deposit
    ):
        original = self._deposit("original_tx", rbf_txids=["original_tx", "replacement_tx"])
        mock_get_tx.return_value = {
            "txid": "replacement_tx",
            "vout": [{"scriptpubkey": "5120" + "33" * 32, "value": 1000000}],
        }

        registered = self.processor.register_rbf_deposits([original])

        self.assertEqual(registered, 0)
        mock_create_deposit.assert_not_called()


class TestLongPendingProcessor(TestDepositProcessorBase):
    """Tests for the process_long_pending method."""

    def setUp(self):
        super().setUp()

        # Set current time for testing
        self.current_time = int(datetime.now(UTC).timestamp())

        # Create test deposits
        self.long_pending = self._create_mock_deposit(
            txid="long_pending_tx",
            confirmed_height=None,  # Not confirmed
            lock_time=0,
            in_mempool=False,
            deposit_last_update=self.current_time
            - settings.MAX_UNCONFIRMED_TIME
            - 3600,  # 1 hour over limit
        )

        self.recent_pending = self._create_mock_deposit(
            txid="recent_pending_tx",
            confirmed_height=None,  # Not confirmed
            lock_time=0,
            in_mempool=False,
            deposit_last_update=self.current_time - 3600,  # Just 1 hour old
        )

        self.in_mempool = self._create_mock_deposit(
            txid="in_mempool_tx",
            confirmed_height=None,  # Not confirmed
            lock_time=0,
            in_mempool=True,
            deposit_last_update=self.current_time
            - settings.MAX_UNCONFIRMED_TIME
            - 3600,  # Old but in mempool
        )

    def test_no_long_pending(self):
        # Test with only transactions that shouldn't be marked as failed
        deposits = [self.recent_pending, self.in_mempool]

        updates = self.processor.process_long_pending(deposits)

        self.assertEqual(len(updates), 0, "No transactions should be marked as failed")

    def test_long_pending(self):
        # Test with a transaction that should be marked as failed
        deposits = [self.long_pending]

        updates = self.processor.process_long_pending(deposits)

        self.assertEqual(len(updates), 1, "One transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "long_pending_tx")
        self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
        self.assertTrue(
            f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)"
            in updates[0].status_message
        )

    def test_mixed_transactions(self):
        # Test with a mix of transactions
        deposits = [self.long_pending, self.recent_pending, self.in_mempool]

        updates = self.processor.process_long_pending(deposits)

        self.assertEqual(len(updates), 1, "Only one transaction should be marked as failed")
        self.assertEqual(updates[0].bitcoin_txid, "long_pending_tx")

    @patch("app.settings.MAX_UNCONFIRMED_TIME", 60 * 60)  # 1 hour instead of 24 hours
    def test_with_custom_timeout(self):
        # Test with a custom timeout setting
        # Create a deposit that would be considered recent with default settings but long pending with reduced timeout
        edge_case = self._create_mock_deposit(
            txid="edge_case",
            confirmed_height=None,
            lock_time=0,
            in_mempool=False,
            deposit_last_update=self.current_time - 7200,  # 2 hours old
        )

        deposits = [edge_case]

        updates = self.processor.process_long_pending(deposits)

        # With MAX_UNCONFIRMED_TIME=1 hour, this should be marked as long pending
        self.assertEqual(
            len(updates), 1, "Transaction should be marked as failed with reduced timeout"
        )
        self.assertEqual(updates[0].bitcoin_txid, "edge_case")
        self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
        self.assertEqual(
            updates[0].status_message,
            f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)",
        )


class TestDepositProcessor(TestDepositProcessorBase):
    """Tests for the DepositProcessor class."""

    def setUp(self):
        super().setUp()

        # Override blockchain state for these specific tests
        self.bitcoin_chaintip_height = 1000

        # Create mock deposits for testing
        self.expired_locktime = self._create_mock_deposit(
            txid="expired_locktime_tx",
            confirmed_height=80,  # Confirmed 20 blocks ago
            lock_time=10,  # Locktime of 10 blocks
        )

        self.active_locktime = self._create_mock_deposit(
            txid="active_locktime_tx",
            confirmed_height=95,  # Confirmed 5 blocks ago
            lock_time=10,  # Locktime of 10 blocks
        )

    @patch("app.clients.MempoolAPI.get_bitcoin_transaction")
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
            "status": {"block_height": 100, "block_time": self.current_time - 3600},
        }

        # tx2 is not found in mempool
        tx2_data = {}

        mock_get_tx.side_effect = lambda txid: tx1_data if txid == "tx1" else tx2_data

        # Mock the from_deposit_info and from_missing methods
        with (
            patch("app.models.EnrichedDepositInfo.from_deposit_info") as mock_from_info,
            patch("app.models.EnrichedDepositInfo.from_missing") as mock_from_missing,
        ):

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

    @patch("app.clients.PrivateEmilyAPI.fetch_deposits")
    @patch("app.clients.PrivateEmilyAPI.update_deposits")
    @patch("app.clients.MempoolAPI.get_tip_height")
    @patch("app.services.deposit_processor.DepositProcessor._enrich_deposits")
    def test_update_deposits_workflow_with_failures(
        self,
        mock_enrich,  # Order matters
        mock_btc_tip_height,
        mock_update_deposits,
        mock_fetch_deposits,
    ):
        """Test the complete deposit update workflow."""
        # Set up mocks
        mock_btc_tip_height.return_value = self.bitcoin_chaintip_height

        # Mock deposit fetching - use real instances for asdict
        expired_locktime = DepositInfo(
            bitcoin_txid="expired_locktime_tx",
            bitcoin_tx_output_index=0,
            recipient="r_pending",
            amount=10,
            last_update_height=800,
            last_update_block_hash="hp",
            status="pending",
            reclaim_script="51",  # Locktime 1, will expire
            deposit_script="51",
        )
        accepted_deposit = DepositInfo(
            bitcoin_txid="active_locktime_tx",
            bitcoin_tx_output_index=0,
            recipient="r_accepted",
            amount=20,
            last_update_height=950,
            last_update_block_hash="ha",
            status="accepted",
            reclaim_script="03400000",  # Locktime 64 (0x40), will NOT expire
            deposit_script="51",
        )
        long_pending = DepositInfo(
            bitcoin_txid="long_pending_tx",
            bitcoin_tx_output_index=0,
            recipient="r_pending",
            amount=10,
            last_update_height=10,
            last_update_block_hash="hb",
            status="pending",
            reclaim_script="51",
            deposit_script="51",
        )

        mock_fetch_deposits.side_effect = lambda status: {
            RequestStatus.PENDING.value: [expired_locktime, long_pending],
            RequestStatus.ACCEPTED.value: [accepted_deposit],
        }[
            status.value
        ]  # Access value property of Enum

        # Mock enrichment to return deposits where one will fail due to expiry
        # and one is active.
        expired_deposit_enriched = EnrichedDepositInfo.from_deposit_info(
            expired_locktime,
            {
                "in_mempool": True,
                "fee": 100,
                "confirmed_height": 890,
                "confirmed_time": 12345,
            },
        )
        # Ensure the active deposit uses the correct (non-expiring) reclaim script info implicitly via asdict
        active_deposit_enriched = EnrichedDepositInfo.from_deposit_info(
            accepted_deposit,
            {
                "in_mempool": True,
                "fee": 200,
                "confirmed_height": 990,
                "confirmed_time": 12346,
            },
        )

        long_pending_enriched = EnrichedDepositInfo.from_deposit_info(
            long_pending,
            {
                "in_mempool": False,
                "fee": 100,
            },
        )
        # mock deposit time
        long_pending_enriched.deposit_last_update = lambda: (
            self.current_time - settings.MAX_UNCONFIRMED_TIME - 1
        )
        mock_enrich.return_value = [
            expired_deposit_enriched,
            active_deposit_enriched,
            long_pending_enriched,
        ]

        # Define mocks for the lazy calls within process_expired_locktime
        def mock_utxo_lazy(txid, vout):
            if txid == "expired_locktime_tx":
                return {"spent": False}  # Expired and unspent
            # Add other cases if needed for more complex workflow tests
            return {}

        with patch(
            "app.clients.ElectrsAPI.get_utxo_status",
            side_effect=mock_utxo_lazy,
        ) as mock_utxo_status_lazy:
            # Run the update_deposits method
            self.processor.update_deposits()

            # Verify fetch calls
            mock_fetch_deposits.assert_any_call(RequestStatus.PENDING)
            mock_fetch_deposits.assert_any_call(RequestStatus.ACCEPTED)

            # Verify enrichment call
            mock_enrich.assert_called_once()
            call_args_list = list(mock_enrich.call_args[0][0])
            self.assertEqual(len(call_args_list), 3)
            self.assertIn(expired_locktime, call_args_list)
            self.assertIn(accepted_deposit, call_args_list)
            self.assertIn(long_pending, call_args_list)

            # Verify lazy call to get_utxo_status happened for the expired deposit
            mock_utxo_status_lazy.assert_called_once_with(
                expired_locktime.bitcoin_txid, expired_locktime.bitcoin_tx_output_index
            )

            # Verify the update was called with the failure update for the expired one ONLY
            mock_update_deposits.assert_called_once()
            updates = mock_update_deposits.call_args[0][0]
            self.assertEqual(len(updates), 2)
            self.assertEqual(updates[0].bitcoin_txid, "expired_locktime_tx")  # The one that expired
            self.assertEqual(updates[0].status, RequestStatus.FAILED.value)
            self.assertEqual(updates[1].bitcoin_txid, "long_pending_tx")
            self.assertEqual(updates[1].status, RequestStatus.FAILED.value)

    @patch("app.clients.MempoolAPI.get_transaction")
    @patch("app.clients.MempoolAPI.check_for_rbf")
    def test_enrich_deposits(self, mock_check_rbf, mock_get_tx):
        """Test the simplified deposit enrichment process."""
        # Create actual DepositInfo instances for testing asdict
        deposit1 = DepositInfo(
            bitcoin_txid="tx1",
            bitcoin_tx_output_index=0,
            recipient="recipient1",
            amount=100000,
            last_update_height=900,
            last_update_block_hash="hash1",
            status="pending",
            reclaim_script="reclaim1",
            deposit_script="deposit1",
        )

        deposit2 = DepositInfo(
            bitcoin_txid="tx2",
            bitcoin_tx_output_index=1,
            recipient="recipient2",
            amount=200000,
            last_update_height=910,
            last_update_block_hash="hash2",
            status="accepted",
            reclaim_script="reclaim2",
            deposit_script="deposit2",
        )

        deposit3 = DepositInfo(  # Deposit where TX not found
            bitcoin_txid="tx3",
            bitcoin_tx_output_index=0,
            recipient="recipient3",
            amount=300000,
            last_update_height=920,
            last_update_block_hash="hash3",
            status="pending",
            reclaim_script="reclaim3",
            deposit_script="deposit3",
        )

        deposit4 = DepositInfo(
            bitcoin_txid="tx4",
            bitcoin_tx_output_index=0,
            recipient="r4",
            amount=60000,
            last_update_height=930,
            last_update_block_hash="h4",
            status="accepted",
            reclaim_script="reclaim4",
            deposit_script="deposit4",
        )

        deposit5 = DepositInfo(  # In mempool, but not confirmed yet
            bitcoin_txid="tx5",
            bitcoin_tx_output_index=0,
            recipient="r5",
            amount=90000,
            last_update_height=940,
            last_update_block_hash="h5",
            status="pending",
            reclaim_script="reclaim5",
            deposit_script="deposit5",
        )

        mock_get_tx.side_effect = lambda txid: {
            "tx1": {
                "vin": [{"prevout": {"value": 2000000}}],
                "vout": [{"scriptpubkey_address": "bc1q...", "value": 1900000}],
                "fee": 100000,
                "status": {"block_height": 1000, "block_time": self.current_time - 3600},
            },
            "tx2": {
                "vin": [{"prevout": {"value": 500000}}],
                "vout": [
                    {"scriptpubkey_address": "bc1a...", "value": 100000},
                    {"scriptpubkey_address": "bc1b...", "value": 390000},  # Output index 1
                ],
                "fee": 10000,
                "status": {"block_height": 1001, "block_time": self.current_time - 1800},
            },
            "tx3": None,  # TX not found
            "tx4": {
                "fee": 10000,
                "status": {"block_height": 930, "block_time": self.current_time - 900},
            },  # Minimal data for deposit4
            "tx5": {"fee": 10000, "status": {"confirmed": False}},  # In-flight
        }.get(txid)
        # There are no RBF txids in this test
        mock_check_rbf.side_effect = lambda txid: set()

        # Run the _enrich_deposits method
        result = self.processor._enrich_deposits([deposit1, deposit2, deposit3, deposit4, deposit5])

        # Verify the correct API calls were made (only get_transaction)
        mock_get_tx.assert_any_call("tx1")
        mock_get_tx.assert_any_call("tx2")
        mock_get_tx.assert_any_call("tx3")
        mock_get_tx.assert_any_call("tx4")
        mock_get_tx.assert_any_call("tx5")
        # Verify the result contains enriched deposits WITHOUT utxo/reclaim info
        self.assertEqual(len(result), 5)

        enriched1 = next(r for r in result if r.bitcoin_txid == "tx1")
        self.assertTrue(enriched1.in_mempool)
        self.assertEqual(enriched1.fee, 100000)
        self.assertEqual(enriched1.confirmed_height, 1000)
        self.assertEqual(enriched1.confirmed_time, self.current_time - 3600)

        enriched2 = next(r for r in result if r.bitcoin_txid == "tx2")
        self.assertTrue(enriched2.in_mempool)
        self.assertEqual(enriched2.fee, 10000)
        self.assertEqual(enriched2.confirmed_height, 1001)
        self.assertEqual(enriched2.confirmed_time, self.current_time - 1800)

        enriched3 = next(r for r in result if r.bitcoin_txid == "tx3")  # This uses from_missing
        self.assertFalse(enriched3.in_mempool)
        self.assertEqual(enriched3.confirmed_height, None)
        self.assertEqual(enriched3.confirmed_time, None)
        self.assertEqual(enriched3.fee, None)

        enriched4 = next(r for r in result if r.bitcoin_txid == "tx4")
        self.assertTrue(enriched4.in_mempool)
        self.assertEqual(enriched4.confirmed_height, 930)
        self.assertEqual(enriched4.confirmed_time, self.current_time - 900)
        self.assertEqual(enriched4.fee, 10000)

        enriched5 = next(r for r in result if r.bitcoin_txid == "tx5")
        self.assertTrue(enriched5.in_mempool)
        self.assertEqual(enriched5.fee, 10000)
        self.assertEqual(enriched5.confirmed_height, None)
        self.assertEqual(enriched5.confirmed_time, None)


class TestDepositProcessorIntegration(unittest.TestCase):
    """Integration-style tests for the deposit update workflow using example txids."""

    def setUp(self):
        self.processor = DepositProcessor()
        # Set a chaintip height high enough to ensure the reclaimed deposit's time has passed
        # Reclaim locktime (from 60b2...) is 96 blocks (0x60)
        # Confirmation height is 675229. MIN_CONFIRMATIONS is 6.
        # Expiry height = 675229 + 96 + 6 = 675331
        self.bitcoin_chaintip_height = 678410  # Well past expiry
        settings.MIN_BLOCK_CONFIRMATIONS = 6

    @patch("app.clients.PrivateEmilyAPI.update_deposits")
    @patch("app.clients.MempoolAPI.get_transaction")
    @patch("app.clients.ElectrsAPI.get_utxo_status")
    @patch("app.clients.MempoolAPI.get_tip_height")
    @patch("app.clients.PrivateEmilyAPI.fetch_deposits")
    def test_reclaimed_deposit_marked_failed(
        self,
        mock_fetch_deposits,
        mock_btc_tip_height,
        mock_get_utxo_status,
        mock_get_transaction,
        mock_update_deposits,
    ):
        """Verify a known reclaimed deposit is correctly identified and marked FAILED."""
        mock_btc_tip_height.return_value = self.bitcoin_chaintip_height

        # Simulate fetching this specific deposit (as pending or accepted)
        reclaimed_deposit_info = DepositInfo(**RECLAIMED_DEPOSIT_DATA)
        mock_fetch_deposits.side_effect = lambda status: (
            [reclaimed_deposit_info] if status == RequestStatus.PENDING else []
        )

        # Mock Mempool API responses specific to this test
        def get_tx_side_effect(txid):
            if txid == RECLAIMED_DEPOSIT_DATA["bitcoin_txid"]:
                # Return data for the original deposit tx (needed for enrichment)
                return {"status": {"block_height": RECLAIMED_DEPOSIT_DATA["last_update_height"]}}
            elif txid == RECLAIM_SPENDING_TX_DATA["txid"]:
                # Return data for the spending (reclaim) tx (needed for reclaim check)
                return RECLAIM_SPENDING_TX_DATA
            return {}

        mock_get_transaction.side_effect = get_tx_side_effect
        mock_get_utxo_status.return_value = RECLAIMED_UTXO_TX_OUTSPENT

        self.processor.update_deposits()

        # Verify update_deposits was called once
        mock_update_deposits.assert_called_once()

        # Get the arguments passed to update_deposits
        call_args = mock_update_deposits.call_args[0][0]

        # Ensure exactly one update was generated
        self.assertEqual(len(call_args), 1)
        update = call_args[0]

        # Verify the update details
        self.assertEqual(update.bitcoin_txid, RECLAIMED_DEPOSIT_DATA["bitcoin_txid"])
        self.assertEqual(update.status, RequestStatus.FAILED.value)
        self.assertIn("Depositor reclaim detected", update.status_message)

    @patch("app.clients.PrivateEmilyAPI.update_deposits")
    @patch("app.clients.MempoolAPI.get_transaction")
    @patch("app.clients.ElectrsAPI.get_utxo_status")
    @patch("app.clients.MempoolAPI.get_tip_height")
    @patch("app.clients.PrivateEmilyAPI.fetch_deposits")
    def test_accepted_deposit_not_failed(
        self,
        mock_fetch_deposits,
        mock_btc_tip_height,
        mock_get_utxo_status,
        mock_get_transaction,
        mock_update_deposits,
    ):
        """Verify a known accepted (signer-swept) deposit is NOT marked FAILED."""
        # --- Mock Setup ---
        # Set chaintip high enough that time *would* expire if not spent
        # Locktime (from 02b6...) = 950 blocks. Confirmed = 678404. MIN_CONF = 6
        # Current chaintip = 678410
        # Expiry height = 678404 + 950 + 6 = 679360  # expired
        mock_btc_tip_height.return_value = self.bitcoin_chaintip_height

        # Simulate fetching this specific deposit
        accepted_deposit_info = DepositInfo(**ACCEPTED_DEPOSIT_DATA)
        mock_fetch_deposits.side_effect = lambda status: (
            [accepted_deposit_info] if status == RequestStatus.ACCEPTED else []
        )

        # Mock Mempool API responses
        def get_tx_side_effect(txid):
            if txid == ACCEPTED_DEPOSIT_DATA["bitcoin_txid"]:
                return ACCEPTED_DEPOSIT_DATA_TX
            elif txid == ACCEPTED_SPENDING_TX_DATA["txid"]:
                return ACCEPTED_SPENDING_TX_DATA
            return {}

        mock_get_transaction.side_effect = get_tx_side_effect
        mock_get_utxo_status.return_value = ACCEPTED_UTXO_TX_OUTSPENT

        self.processor.update_deposits()

        # Verify update_deposits was called with an EMPTY list (or not called at all if no updates)
        if mock_update_deposits.called:
            call_args = mock_update_deposits.call_args[0][0]
            self.assertEqual(
                len(call_args),
                0,
                "No failure updates should be generated for accepted/signer-swept deposit",
            )
        else:
            # If no updates are generated, update_deposits should not be called
            pass


class TestMempoolAPI(unittest.TestCase):
    """Tests for the MempoolAPI client."""

    def setUp(self):
        self.api = MempoolAPI()

    @patch("app.clients.base.APIClient.get")
    def test_get_transaction(self, mock_get):
        """Test getting transaction details."""
        # Test getting a deposit transaction
        mock_get.return_value = ACCEPTED_DEPOSIT_DATA_TX
        tx_data = MempoolAPI.get_transaction(ACCEPTED_DEPOSIT_DATA["bitcoin_txid"])
        self.assertEqual(tx_data["txid"], ACCEPTED_DEPOSIT_DATA["bitcoin_txid"])
        self.assertEqual(tx_data["vout"][0]["value"], ACCEPTED_DEPOSIT_DATA["amount"])
        mock_get.assert_called_once_with(
            f"/v1/tx/{ACCEPTED_DEPOSIT_DATA['bitcoin_txid']}", ignore_errors=True
        )

        # Test getting a spending transaction
        mock_get.reset_mock()
        mock_get.return_value = ACCEPTED_SPENDING_TX_DATA
        tx_data = MempoolAPI.get_transaction(ACCEPTED_SPENDING_TX_DATA["txid"])
        self.assertEqual(tx_data["txid"], ACCEPTED_SPENDING_TX_DATA["txid"])
        self.assertEqual(len(tx_data["vin"]), 2)  # Has two inputs
        mock_get.assert_called_once_with(
            f"/v1/tx/{ACCEPTED_SPENDING_TX_DATA['txid']}", ignore_errors=True
        )


class TestElectrsAPI(unittest.TestCase):
    """Tests for the ElectrsAPI client."""

    def setUp(self):
        self.api = ElectrsAPI()

    @patch("app.clients.base.APIClient.get")
    def test_get_utxo_status(self, mock_get):
        """Test getting UTXO status."""
        # Test spent UTXO
        mock_get.return_value = ACCEPTED_UTXO_TX_OUTSPENT
        utxo_status = ElectrsAPI.get_utxo_status(
            ACCEPTED_DEPOSIT_DATA["bitcoin_txid"], ACCEPTED_DEPOSIT_DATA["bitcoin_tx_output_index"]
        )
        self.assertTrue(utxo_status["spent"])
        self.assertEqual(utxo_status["txid"], ACCEPTED_UTXO_TX_OUTSPENT["txid"])
        self.assertTrue(utxo_status["status"]["confirmed"])
        mock_get.assert_called_once_with(
            f"/tx/{ACCEPTED_DEPOSIT_DATA['bitcoin_txid']}/outspend/{ACCEPTED_DEPOSIT_DATA['bitcoin_tx_output_index']}",
            ignore_errors=True,
        )

        # Test unspent UTXO (404 response)
        mock_get.reset_mock()
        # Simulate 404 - MempoolAPI expects get(ignore_errors=True) to return empty dict, not raise
        mock_get.return_value = {}
        utxo_status = ElectrsAPI.get_utxo_status(
            RECLAIMED_DEPOSIT_DATA["bitcoin_txid"],
            RECLAIMED_DEPOSIT_DATA["bitcoin_tx_output_index"],
        )
        self.assertFalse(utxo_status["spent"])
        # Ensure the mock was still called
        mock_get.assert_called_once_with(
            f"/tx/{RECLAIMED_DEPOSIT_DATA['bitcoin_txid']}/outspend/{RECLAIMED_DEPOSIT_DATA['bitcoin_tx_output_index']}",
            ignore_errors=True,
        )

        # Test in-flight UTXO
        mock_get.reset_mock()
        mock_get.side_effect = None  # Reset side effect
        mock_get.return_value = INFLIGHT_UTXO_STATUS
        utxo_status = ElectrsAPI.get_utxo_status(
            INFLIGHT_UTXO_STATUS["txid"], INFLIGHT_UTXO_STATUS["vin"]
        )
        self.assertFalse(utxo_status["spent"])
        mock_get.assert_called_once_with(
            f"/tx/{INFLIGHT_UTXO_STATUS['txid']}/outspend/{INFLIGHT_UTXO_STATUS['vin']}",
            ignore_errors=True,
        )
