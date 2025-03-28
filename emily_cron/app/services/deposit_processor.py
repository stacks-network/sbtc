import logging
from datetime import datetime
from itertools import chain
from typing import Iterable

from ..clients import PublicEmilyAPI, PrivateEmilyAPI, HiroAPI, MempoolAPI
from ..models import (
    DepositUpdate,
    EnrichedDepositInfo,
    RequestStatus,
    BlockInfo,
    DepositInfo,
)
from .. import settings

logger = logging.getLogger(__name__)


class DepositProcessor:
    """Service for processing deposits."""

    def process_expired_locktime(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        bitcoin_chaintip: BlockInfo,
    ) -> list[DepositUpdate]:
        """Process transactions with expired locktime.

        Args:
            enriched_deposits: List of enriched deposit information
            bitcoin_chaintip: Current Bitcoin block info
            stacks_chaintip: Current Stacks block info

        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Find transactions with expired locktime
        locktime_expired_txs = [
            tx for tx in enriched_deposits if tx.is_expired(bitcoin_chaintip.height)
        ]

        if not locktime_expired_txs:
            return updates

        logger.info(
            f"Found {len(locktime_expired_txs)} transactions with expired locktime to mark as FAILED"
        )

        for tx in locktime_expired_txs:
            logger.info(f"Marking transaction {tx.bitcoin_txid} with expired locktime as FAILED")
            updates.append(
                DepositUpdate(
                    bitcoin_txid=tx.bitcoin_txid,
                    bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                    status=RequestStatus.FAILED.value,
                    status_message=f"Locktime expired at height {bitcoin_chaintip.height}",
                )
            )

        return updates

    def update_deposits(self) -> None:
        """Update deposit statuses.

        This is the main entry point for the deposit processor.
        It fetches deposits, enriches them, processes them, and updates their status.
        """
        logger.info("Running deposit status update job")

        # Get current blockchain state
        bitcoin_chaintip = MempoolAPI.get_block_at()
        stacks_chaintip = HiroAPI.get_stacks_block()

        logger.info(f"Bitcoin chain tip: {bitcoin_chaintip}")
        logger.info(f"Stacks chain tip: {stacks_chaintip}")

        # Fetch pending and accepted deposits
        pending_deposits = PublicEmilyAPI.fetch_deposits(RequestStatus.PENDING)
        accepted_deposits = PublicEmilyAPI.fetch_deposits(RequestStatus.ACCEPTED)

        # Enrich deposits with additional transaction data
        enriched_deposits = self._enrich_deposits(chain(pending_deposits, accepted_deposits))

        # Process deposits and collect updates
        updates = []

        # Process transactions with expired locktime
        locktime_updates = self.process_expired_locktime(
            enriched_deposits,
            bitcoin_chaintip,
        )
        updates.extend(locktime_updates)

        # Apply updates
        if updates:
            logger.info(f"Updating {len(updates)} deposit statuses")
            PrivateEmilyAPI.update_deposits(updates)
        else:
            logger.info("No deposit updates needed")

        logger.info("Deposit status update job completed")

    def _enrich_deposits(self, deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
        """Fetch transaction details and enrich deposit info.

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

            spending_outputs = {
                vout.get("scriptpubkey_address", "Unknown"): vout.get("value", 0)
                for vout in tx_data.get("vout", [])
            }

            additional_info = {
                "in_mempool": True,
                "total_input": sum(
                    vin.get("prevout", {}).get("value", 0) for vin in tx_data.get("vin", [])
                ),
                "fee": tx_data.get("fee", 0),
                "confirmed_height": tx_data.get("status", {}).get("block_height", -1),
                "confirmed_time": tx_data.get("status", {}).get("block_time", -1),
                "num_inputs": len(tx_data.get("vin", [])),
                "spending_outputs": spending_outputs,
            }

            transaction_details.append(
                EnrichedDepositInfo.from_deposit_info(deposit, additional_info)
            )

        return transaction_details
