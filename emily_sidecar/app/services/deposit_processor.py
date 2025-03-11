import logging
from datetime import datetime
from itertools import chain
from typing import List, Set, Dict, Tuple

from ..clients import EmilyAPI, HiroAPI, MempoolAPI
from ..models import DepositInfo, DepositUpdate, EnrichedDepositInfo, RequestStatus
from ..services.deposit_enricher import enrich_deposits
from .. import settings

logger = logging.getLogger(__name__)


class DepositProcessor:
    """Service for processing deposits."""

    def __init__(self, emily_client: EmilyAPI):
        """Initialize the deposit processor.

        Args:
            emily_client: EmilyAPI client
        """
        self.emily_client = emily_client

    def process_rbf_transactions(
        self,
        enriched_deposits: List[EnrichedDepositInfo],
        stacks_height: int,
        stacks_hash: str,
    ) -> List[DepositUpdate]:
        """Process RBF transactions.

        Args:
            enriched_deposits: List of enriched deposit information
            stacks_height: Current Stacks block height
            stacks_hash: Current Stacks block hash

        Returns:
            List[DepositUpdate]: List of deposit updates
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
                        logger.info(f"Marking RBF'd transaction {tx.bitcoin_txid} as FAILED (replaced by confirmed tx)")
                        updates.append(DepositUpdate(
                            bitcoin_txid=tx.bitcoin_txid,
                            bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                            last_update_height=stacks_height,
                            last_update_block_hash=stacks_hash,
                            status=RequestStatus.FAILED.value,
                            status_message=f"Replaced by confirmed tx {confirmed_txs[0].bitcoin_txid}",
                        ))
        return updates

    def process_expired_locktime(
        self,
        enriched_deposits: List[EnrichedDepositInfo],
        bitcoin_height: int,
        stacks_height: int,
        stacks_hash: str,
    ) -> List[DepositUpdate]:
        """Process transactions with expired locktime.

        Args:
            enriched_deposits: List of enriched deposit information
            bitcoin_height: Current Bitcoin block height
            stacks_height: Current Stacks block height
            stacks_hash: Current Stacks block hash

        Returns:
            List[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Find transactions with expired locktime
        locktime_expired_txs = [
            tx for tx in enriched_deposits
            if tx.confirmed_height > 0 and  # Only process confirmed transactions
            bitcoin_height >= tx.confirmed_height + tx.lock_time + settings.MIN_BLOCK_CONFIRMATIONS  # Check if locktime has expired
        ]

        if not locktime_expired_txs:
            return updates

        logger.info(f"Found {len(locktime_expired_txs)} transactions with expired locktime to mark as FAILED")

        for tx in locktime_expired_txs:
            logger.info(f"Marking transaction {tx.bitcoin_txid} with expired locktime as FAILED")
            updates.append(DepositUpdate(
                bitcoin_txid=tx.bitcoin_txid,
                bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                last_update_height=stacks_height,
                last_update_block_hash=stacks_hash,
                status=RequestStatus.FAILED.value,
                status_message=f"Locktime expired at height {bitcoin_height}",
            ))

        return updates

    def process_long_pending(
        self,
        enriched_deposits: List[EnrichedDepositInfo],
        stacks_height: int,
        stacks_hash: str,
    ) -> List[DepositUpdate]:
        """Process long-pending transactions.

        Args:
            enriched_deposits: List of enriched deposit information
            stacks_height: Current Stacks block height
            stacks_hash: Current Stacks block hash

        Returns:
            List[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Get the current time plus the max unconfirmed time
        expiration_time = int(datetime.now().timestamp()) + settings.MAX_UNCONFIRMED_TIME

        long_pending_txs = [
            tx
            for tx in enriched_deposits
            if tx.status == RequestStatus.PENDING.value  # Only check pending transactions
            and not tx.in_mempool  # that we can't find via the mempool API (it might have been dropped)
            and tx.deposit_time >= expiration_time  # and has been pending for too long
        ]

        if not long_pending_txs:
            return updates

        logger.info(f"Found {len(long_pending_txs)} long-pending transactions to mark as FAILED")

        for tx in long_pending_txs:
            logger.info(f"Marking long-pending transaction {tx.bitcoin_txid} as FAILED")
            updates.append(DepositUpdate(
                bitcoin_txid=tx.bitcoin_txid,
                bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                last_update_height=stacks_height,
                last_update_block_hash=stacks_hash,
                status=RequestStatus.FAILED.value,
                status_message=f"Pending for too long ({settings.MAX_UNCONFIRMED_TIME} seconds)",
            ))

        return updates

    def update_deposits(self) -> None:
        """Update deposit statuses.

        This is the main entry point for the deposit processor.
        It fetches deposits, enriches them, processes them, and updates their status.
        """
        logger.info("Running deposit status update job")

        # Get current blockchain state
        bitcoin_chaintip = MempoolAPI.get_bitcoin_block_at()
        stacks_block = HiroAPI.get_stacks_block()

        # Fetch pending and accepted deposits
        pending_deposits = self.emily_client.fetch_deposits(RequestStatus.PENDING)
        accepted_deposits = self.emily_client.fetch_deposits(RequestStatus.ACCEPTED)

        # Enrich deposits with additional transaction data
        enriched_deposits = enrich_deposits(chain(pending_deposits, accepted_deposits))

        # Process deposits and collect updates
        updates = []

        # Process RBF transactions
        rbf_updates = self.process_rbf_transactions(
            enriched_deposits,
            stacks_block.height,
            stacks_block.hash
        )
        updates.extend(rbf_updates)

        # Process transactions with expired locktime
        locktime_updates = self.process_expired_locktime(
            enriched_deposits,
            bitcoin_chaintip.height,
            stacks_block.height,
            stacks_block.hash
        )
        updates.extend(locktime_updates)

        # Process long-pending transactions
        pending_updates = self.process_long_pending(
            enriched_deposits,
            stacks_block.height,
            stacks_block.hash
        )
        updates.extend(pending_updates)

        # Apply updates
        if updates:
            logger.info(f"Updating {len(updates)} deposit statuses")
            self.emily_client.update_deposits(updates)
        else:
            logger.info("No deposit updates needed")

        logger.info("Deposit status update job completed")


    def _group_rbf_transactions(self, rbf_txs: List[EnrichedDepositInfo]) -> Dict[str, Set[str]]:
        """Group RBF transactions by their replacement chains.

        Args:
            rbf_txs: List of transactions with RBF replacements

        Returns:
            Dict[str, Set[str]]: Dictionary mapping group IDs to sets of transaction IDs
        """
        rbf_groups = {}

        # First, build groups of related transactions (original + replacements)
        for tx in rbf_txs:
            # Create a set of all txids in this RBF chain
            chain_txids = tx.rbf_txids.copy()
            chain_txids.add(tx.bitcoin_txid)

            # Check if this chain overlaps with any existing group
            found_group = False
            for group_id, group_txids in list(rbf_groups.items()):
                if chain_txids.intersection(group_txids):
                    # Merge with existing group
                    rbf_groups[group_id] = group_txids.union(chain_txids)
                    found_group = True
                    break

            if not found_group:
                # Create a new group
                rbf_groups[tx.bitcoin_txid] = chain_txids

        return rbf_groups