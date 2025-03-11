from itertools import chain
from .clients import EmilyAPI, MempoolAPI, enrich_deposits, RequestStatus
from . import settings


def update_deposits():
    bitcoin_chaintip = MempoolAPI.get_bitcoin_block_at()
    pending_deposits = EmilyAPI.fetch_deposits(RequestStatus.PENDING)
    accepted_deposits = EmilyAPI.fetch_deposits(RequestStatus.ACCEPTED)

    enriched_deposits = enrich_deposits(
        chain(pending_deposits, accepted_deposits)
    )

    confirmed_txs = [
        deposit
        for deposit in enriched_deposits
        if deposit.last_update_height <= bitcoin_chaintip["height"]
    ]
