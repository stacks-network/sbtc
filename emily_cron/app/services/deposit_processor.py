import logging
from datetime import datetime, UTC
from itertools import chain, groupby
from json import JSONDecodeError
from typing import Iterable

from requests.exceptions import RequestException, JSONDecodeError

from ..clients import PrivateEmilyAPI, MempoolAPI, ElectrsAPI
from ..models import (
    DepositUpdate,
    EnrichedDepositInfo,
    RequestStatus,
    DepositInfo,
)
from .. import settings

logger = logging.getLogger(__name__)


class DepositProcessor:
    """Service for processing deposits."""

    def process_rbf_transactions(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        bitcoin_chaintip_height: int,
    ) -> list[DepositUpdate]:
        """Identifies and handles confirmed RBF scenarios.

        This function scans the provided deposits to find groups of transactions
        linked by RBF (where one transaction attempts to replace another).

        If a group of RBF-related transactions contains at least one transaction
        that has been confirmed on the Bitcoin blockchain, this function generates
        updates to mark all other unconfirmed transactions within that same
        RBF group as FAILED. This signifies that they were successfully replaced
        by the confirmed transaction.

        Args:
            enriched_deposits: List of enriched deposit information
        Returns:
            A list of DepositUpdate objects, specifically for those deposits
            that were identified as unconfirmed parts of an RBF chain where
            another transaction in the chain got confirmed. Returns an empty
            list if no such scenarios are found.
        """
        updates = []

        # Find transactions with RBF replacements
        rbf_txs = [tx for tx in enriched_deposits if tx.rbf_txids]
        if not rbf_txs:
            return updates

        logger.info(f"Found {len(rbf_txs)} transactions with RBF replacements")

        # Group txs by RBF chain. All txs in a group have the same RBF chain.
        for rbf_key, group_iter in groupby(rbf_txs, key=lambda tx: ",".join(sorted(tx.rbf_txids))):

            confirmed_txid_in_group: str | None = None
            unconfirmed_txs_in_group: list[EnrichedDepositInfo] = []

            # Identify confirmed tx and collect unconfirmed ones
            for tx in group_iter:
                if tx.confirmed_height is not None:
                    # Should ideally only be one confirmed tx per RBF group
                    if confirmed_txid_in_group is not None:
                        logger.warning(
                            f"Multiple confirmed transactions found in RBF group {rbf_key}: "
                            f"{confirmed_txid_in_group} and {tx.bitcoin_txid}. Using first found."
                        )
                    elif (
                        bitcoin_chaintip_height
                        < tx.confirmed_height + settings.MIN_BLOCK_CONFIRMATIONS
                    ):
                        logger.info(
                            f"Confirmed transaction {tx.bitcoin_txid} is not yet eligible for RBF replacement"
                        )
                    else:
                        confirmed_txid_in_group = tx.bitcoin_txid
                else:
                    unconfirmed_txs_in_group.append(tx)

            if confirmed_txid_in_group is None:
                logger.debug(f"No confirmed transactions found for RBF group {rbf_key}")
                continue

            logger.info(
                f"Confirmed transaction {confirmed_txid_in_group} found for RBF group {rbf_key}"
            )
            # Mark all collected unconfirmed transactions as RBF'd
            for tx in unconfirmed_txs_in_group:
                logger.info(
                    f"Marking RBF'd transaction {tx.bitcoin_txid} as RBF (replaced by confirmed tx {confirmed_txid_in_group})"
                )
                updates.append(
                    DepositUpdate(
                        bitcoin_txid=tx.bitcoin_txid,
                        bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                        status=RequestStatus.RBF.value,
                        status_message=f"Replaced by confirmed tx {confirmed_txid_in_group}",
                        replaced_by_tx=confirmed_txid_in_group,
                    )
                )

        return updates

    def process_expired_locktime(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        bitcoin_chaintip_height: int,
    ) -> list[DepositUpdate]:
        """Process transactions with expired locktime.

        This includes:
        - Transactions where locktime expired and the UTXO was NOT spent.
        - Transactions where the UTXO was reclaimed.

        Args:
            enriched_deposits: List of enriched deposit information
            bitcoin_chaintip_height: Current Bitcoin chain tip height

        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        for tx in enriched_deposits:
            # Step 1: Check if the time-based expiry condition is met
            if not tx.is_expired(bitcoin_chaintip_height):
                continue  # Not eligible for failure yet based on time

            # Step 2: Time has expired, now check UTXO status
            logger.debug(f"Deposit {tx.bitcoin_txid} time expired, checking UTXO status...")
            utxo_status = ElectrsAPI.get_utxo_status(tx.bitcoin_txid, tx.bitcoin_tx_output_index)
            is_utxo_spent = utxo_status.get("spent", False)
            if not is_utxo_spent:
                # Case 1: Time expired AND UTXO is unspent -> Mark FAILED
                logger.info(
                    f"Marking transaction {tx.bitcoin_txid} as FAILED (Locktime expired, unspent)"
                )
                updates.append(
                    DepositUpdate(
                        bitcoin_txid=tx.bitcoin_txid,
                        bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                        status=RequestStatus.FAILED.value,
                        status_message=f"Locktime expired at height {bitcoin_chaintip_height} and UTXO unspent",
                    )
                )
                continue

            # Step 3: UTXO is spent, check if it was a reclaim
            spending_txid = utxo_status.get("txid")
            if spending_txid is None:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO is spent, but spending TXID is missing from API response. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time
            vin_index = utxo_status.get("vin")
            if vin_index is None:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, but no vin index found in API response. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time

            logger.debug(
                f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, checking for reclaim..."
            )
            spending_tx_details = MempoolAPI.get_transaction(spending_txid)
            if not spending_tx_details:
                logger.warning(
                    f"Could not fetch spending tx details for {spending_txid} to check for reclaim of {tx.bitcoin_txid}."
                )
                continue  # Cannot determine reclaim, skip at this time

            vin = spending_tx_details.get("vin", [])
            try:
                vin = vin[vin_index]
            except IndexError:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, but vin index {vin_index} is out of bounds. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time
            witness_data = vin.get("witness", [])
            # Simple check: does witness contain the reclaim script?
            is_reclaim_check = any(tx.reclaim_script in item for item in witness_data)

            if is_reclaim_check:
                # Case 2: Time expired, UTXO spent, AND identified as reclaim -> Mark FAILED
                logger.info(
                    f"Marking transaction {tx.bitcoin_txid} as FAILED (Depositor reclaim detected)"
                )
                updates.append(
                    DepositUpdate(
                        bitcoin_txid=tx.bitcoin_txid,
                        bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                        status=RequestStatus.FAILED.value,
                        status_message=f"Depositor reclaim detected in tx {spending_txid}",
                    )
                )
            else:
                # Case 3: Time expired, UTXO spent, but NOT identified as reclaim -> Assume signer sweep, do nothing.
                logger.debug(
                    f"Deposit {tx.bitcoin_txid} time expired, but UTXO spent by {spending_txid} (likely signer sweep). Not failing."
                )

        logger.info(f"Found {len(updates)} transactions to mark as FAILED (expired or reclaimed)")

        return updates

    def process_long_pending(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
    ) -> list[DepositUpdate]:
        """Process long-pending transactions.

        Args:
            enriched_deposits: List of enriched deposit information

        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        current_time = int(datetime.now(UTC).timestamp())

        long_pending_txs = []
        for tx in enriched_deposits:
            # Only check pending transactions
            if tx.status != RequestStatus.PENDING.value:
                continue
            # that we can't find via the mempool API (it might have been dropped)
            if tx.in_mempool:
                continue

            try:
                # and have been pending for too long
                if current_time - tx.deposit_last_update() > settings.MAX_UNCONFIRMED_TIME:
                    long_pending_txs.append(tx)
            except (RequestException, ValueError, JSONDecodeError) as e:
                logger.warning(
                    f"Could not check pending status for deposit {tx.bitcoin_txid} due to "
                    f"API error fetching block {tx.last_update_block_hash}: {e}. Skipping."
                )

        for tx in long_pending_txs:
            logger.info(f"Marking long-pending transaction {tx.bitcoin_txid} as FAILED")
            updates.append(
                DepositUpdate(
                    bitcoin_txid=tx.bitcoin_txid,
                    bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                    status=RequestStatus.FAILED.value,
                    status_message=f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)",
                )
            )

        logger.info(f"Found {len(long_pending_txs)} long-pending transactions to mark as FAILED")
        return updates

    def update_deposits(self) -> None:
        """Update deposit statuses.

        This is the main entry point for the deposit processor.
        It fetches deposits, enriches them, processes them, and updates their status.
        """
        logger.info("Running deposit status update job")

        # Get current blockchain state
        bitcoin_chaintip_height = MempoolAPI.get_tip_height()

        logger.info(f"Bitcoin chain tip: {bitcoin_chaintip_height}")

        # Fetch pending and accepted deposits.
        # Accepted deposits are included because Bitcoin forks could invalidate
        # a previously accepted deposit, or a malicious signer may have modified
        # a pending or invalid deposit to Accepted.
        pending_deposits = PrivateEmilyAPI.fetch_deposits(RequestStatus.PENDING)
        accepted_deposits = PrivateEmilyAPI.fetch_deposits(RequestStatus.ACCEPTED)

        # Enrich deposits with additional transaction data
        enriched_deposits = self._enrich_deposits(chain(pending_deposits, accepted_deposits))

        # Process deposits and collect updates
        updates = []

        # Process transactions with expired locktime or reclaimed
        locktime_updates = self.process_expired_locktime(enriched_deposits, bitcoin_chaintip_height)
        updates.extend(locktime_updates)

        # Process RBF transactions
        rbf_updates = self.process_rbf_transactions(enriched_deposits, bitcoin_chaintip_height)
        updates.extend(rbf_updates)

        # Process long-pending transactions
        pending_updates = self.process_long_pending(enriched_deposits)
        updates.extend(pending_updates)
        # Apply updates
        if updates:
            logger.info(f"Updating {len(updates)} deposit statuses")
            PrivateEmilyAPI.update_deposits(updates)
        else:
            logger.info("No deposit updates needed")

        logger.info("Deposit status update job completed")

    def _enrich_deposits(self, deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
        """Fetch transaction details and UTXO status, and enrich deposit info.

        Args:
            deposits: Iterable of DepositInfo objects

        Returns:
            list[EnrichedDepositInfo]: List of enriched deposit information
        """
        transaction_details = []
        for deposit in deposits:
            tx_data = MempoolAPI.get_transaction(deposit.bitcoin_txid)

            if not tx_data:
                transaction_details.append(EnrichedDepositInfo.from_missing(deposit))
                continue

            if "fee" not in tx_data:
                logger.debug(f"Fee is missing for transaction {deposit.bitcoin_txid}")

            additional_info = {
                "in_mempool": True,
                "fee": tx_data.get("fee"),
                "confirmed_height": tx_data.get("status", {}).get("block_height"),
                "confirmed_time": tx_data.get("status", {}).get("block_time"),
            }

            # Only check for RBF if not confirmed
            if additional_info["confirmed_height"] is None:
                additional_info["rbf_txids"] = MempoolAPI.check_for_rbf(deposit.bitcoin_txid)

            transaction_details.append(
                EnrichedDepositInfo.from_deposit_info(deposit, additional_info)
            )

        return transaction_details
