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

    def process_rbf_transactions(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        stacks_chaintip: BlockInfo,
    ) -> list[DepositUpdate]:
        """Process RBF transactions.
        Args:
            enriched_deposits: List of enriched deposit information
            stacks_chaintip: Current Stacks block info
        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Find transactions with RBF replacements
        rbf_txs = [tx for tx in enriched_deposits if tx.rbf_txids]
        if not rbf_txs:
            return updates

        logger.info(f"Found {len(rbf_txs)} transactions with RBF replacements")

        # Group by replacement chain
        rbf_groups = self._group_rbf_transactions(rbf_txs)

        # Process each group
        for group_txids in rbf_groups.values():
            # Find all transactions in this group
            group_txs = [tx for tx in enriched_deposits if tx.bitcoin_txid in group_txids]

            # Check if any transaction in this group is confirmed
            confirmed_txs = [tx for tx in group_txs if tx.confirmed_height > 0]

            if confirmed_txs:
                # If we have confirmed transactions, mark all unconfirmed ones as FAILED
                for tx in group_txs:
                    if tx.confirmed_height <= 0:
                        logger.info(
                            f"Marking RBF'd transaction {tx.bitcoin_txid} as FAILED (replaced by confirmed tx)"
                        )
                        updates.append(
                            DepositUpdate(
                                bitcoin_txid=tx.bitcoin_txid,
                                bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                                last_update_height=stacks_chaintip.height,
                                last_update_block_hash=stacks_chaintip.hash,
                                status=RequestStatus.FAILED.value,
                                status_message=f"Replaced by confirmed tx {confirmed_txs[0].bitcoin_txid}",
                            )
                        )
        return updates

    def process_expired_locktime(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        bitcoin_chaintip: BlockInfo,
        stacks_chaintip: BlockInfo,
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
            tx
            for tx in enriched_deposits
            if tx.confirmed_height > 0  # Only process confirmed transactions
            and bitcoin_chaintip.height >= tx.confirmed_height + tx.lock_time + settings.MIN_BLOCK_CONFIRMATIONS  # Check if locktime has expired
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
                    last_update_height=stacks_chaintip.height,
                    last_update_block_hash=stacks_chaintip.hash,
                    status=RequestStatus.FAILED.value,
                    status_message=f"Locktime expired at height {bitcoin_chaintip.height}",
                )
            )

        return updates

    def process_long_pending(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        stacks_chaintip: BlockInfo,
    ) -> list[DepositUpdate]:
        """Process long-pending transactions.
        Args:
            enriched_deposits: List of enriched deposit information
            stacks_chaintip: Current Stacks block info
        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Get the current time
        current_time = int(datetime.now().timestamp())

        long_pending_txs = [
            tx
            for tx in enriched_deposits
            if tx.status == RequestStatus.PENDING.value  # Only check pending transactions
            and not tx.in_mempool  # that we can't find via the mempool API (it might have been dropped)
            and current_time - tx.deposit_time >= settings.MAX_UNCONFIRMED_TIME  # and has been pending for too long
        ]

        if not long_pending_txs:
            return updates

        logger.info(f"Found {len(long_pending_txs)} long-pending transactions to mark as FAILED")

        for tx in long_pending_txs:
            logger.info(f"Marking long-pending transaction {tx.bitcoin_txid} as FAILED")
            updates.append(
                DepositUpdate(
                    bitcoin_txid=tx.bitcoin_txid,
                    bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                    last_update_height=stacks_chaintip.height,
                    last_update_block_hash=stacks_chaintip.hash,
                    status=RequestStatus.FAILED.value,
                    status_message=f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)",
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
        bitcoin_chaintip = MempoolAPI.get_bitcoin_block_at()
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
            stacks_chaintip,
        )
        updates.extend(locktime_updates)

        # Process RBF transactions
        rbf_updates = self.process_rbf_transactions(
            enriched_deposits,
            stacks_chaintip,
        )
        updates.extend(rbf_updates)

        # Process long-pending transactions
        pending_updates = self.process_long_pending(
            enriched_deposits,
            stacks_chaintip,
        )
        updates.extend(pending_updates)

        # Apply updates
        if updates:
            logger.info(f"Updating {len(updates)} deposit statuses")
            PrivateEmilyAPI.update_deposits(updates)
        else:
            logger.info("No deposit updates needed")

        logger.info("Deposit status update job completed")

    def _group_rbf_transactions(self, rbf_txs: list[EnrichedDepositInfo]) -> dict[str, set[str]]:
        """Group RBF transactions by their replacement chains.
        Args:
            rbf_txs: List of transactions with RBF replacements
        Returns:
            dict[str, set[str]]: Dictionary mapping group IDs to sets of transaction IDs
        """
        rbf_groups: dict[str, set[str]] = {}

        # First, build groups of related transactions (original + replacements)
        for tx in rbf_txs:
            # Create a set of all txids in this RBF chain
            chain_txids = set(tx.rbf_txids)
            chain_txids.add(tx.bitcoin_txid)

            # Find all groups that overlap with this chain
            overlapping_groups = []
            for group_id, group_txids in list(rbf_groups.items()):
                if chain_txids.intersection(group_txids):
                    overlapping_groups.append(group_id)

            if overlapping_groups:
                # Merge all overlapping groups into the first one
                primary_group_id = overlapping_groups[0]
                merged_txids = set(rbf_groups[primary_group_id])

                # Add the current chain
                merged_txids.update(chain_txids)

                # Merge in all other overlapping groups
                for group_id in overlapping_groups[1:]:
                    merged_txids.update(rbf_groups[group_id])
                    # Remove the merged group
                    del rbf_groups[group_id]

                # Update the primary group with the merged set
                rbf_groups[primary_group_id] = merged_txids
            else:
                # Create a new group
                rbf_groups[tx.bitcoin_txid] = chain_txids

        return rbf_groups

    def _enrich_deposits(self, deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
        """Fetch transaction details and enrich deposit info.

        Args:
            deposits: Iterable of DepositInfo objects

        Returns:
            list[EnrichedDepositInfo]: List of enriched deposit information
        """
        transaction_details = []
        for deposit in deposits:
            tx_data = MempoolAPI.get_bitcoin_transaction(deposit.bitcoin_txid)

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
                "rbf_txids": set(),
            }

            # Only check for RBF if not confirmed
            if additional_info["confirmed_height"] == -1:
                additional_info["rbf_txids"] = MempoolAPI.check_for_rbf(deposit.bitcoin_txid)

            transaction_details.append(
                EnrichedDepositInfo.from_deposit_info(deposit, additional_info)
            )

        return transaction_details
