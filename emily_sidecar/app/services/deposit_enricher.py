import logging
from dataclasses import asdict
from typing import Iterable, List

from ..clients import MempoolAPI
from ..models import DepositInfo, EnrichedDepositInfo

logger = logging.getLogger(__name__)


def enrich_deposits(deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
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
            "deposit_time": deposit.deposit_time,
        }

        # Only check for RBF if not confirmed
        if additional_info["confirmed_height"] == -1:
            additional_info["rbf_txids"] = MempoolAPI.check_for_rbf(deposit.bitcoin_txid)

        transaction_details.append(
            EnrichedDepositInfo.from_deposit_info(deposit, additional_info)
        )

    return transaction_details