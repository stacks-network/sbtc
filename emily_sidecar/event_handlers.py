import logging

import emily_client

from clarity import try_into_address


def le_bytes_to_hex(le_bytes: list[str]) -> str:
    return bytes(reversed(le_bytes)).hex()


def handle_completed_deposit(
    event: dict, stacks_txid: str, stacks_block_hash: str, stacks_block_height: int
) -> emily_client.DepositUpdate:
    # amount = event.pop("amount")
    fulfillment = emily_client.Fulfillment(
        bitcoin_block_hash=le_bytes_to_hex(event["burn-hash"]),
        bitcoin_block_height=event["burn-height"],
        bitcoin_tx_index=0,  # in the signer, we are using output-index
        bitcoin_txid=le_bytes_to_hex(
            event["sweep-txid"]
        ),  # in the signer, we are using bitcoin-txid
        btc_fee=0,  # in the signer, we can compute the fee from the amount and the tx amount in the DB
        stacks_txid=stacks_txid,
    )
    return emily_client.DepositUpdate(
        bitcoin_tx_output_index=event["output-index"],
        bitcoin_txid=le_bytes_to_hex(event["bitcoin-txid"]),
        status="confirmed",
        fulfillment=fulfillment,
        status_message=f"Included in block {fulfillment.bitcoin_block_hash}",
        last_update_block_hash=stacks_block_hash,
        last_update_height=stacks_block_height,
    )


def handle_withdrawal_create(
    event: dict, _stacks_txid: str, stacks_block_hash: str, stacks_block_height: int
) -> emily_client.CreateWithdrawalRequestBody:
    # block_height: int = event["block-height"],  # Not used
    # sender: str = event["sender"]  # Not used
    recipient = try_into_address(
        bytes(event["recipient"]["version"]), bytes(event["recipient"]["hashbytes"])
    )
    return emily_client.CreateWithdrawalRequestBody(
        amount=event["amount"],
        parameters=emily_client.WithdrawalParameters(max_fee=event["max-fee"]),
        recipient=recipient,
        request_id=event["request-id"],
        stacks_block_hash=stacks_block_hash,
        stacks_block_height=stacks_block_height,
    )


def handle_withdrawal_accept(
    event: dict, stacks_txid: str, stacks_block_hash: str, stacks_block_height: int
) -> emily_client.WithdrawalUpdate:
    # bitmap: int = event["signer-bitmap"]  # Not used
    # bitcoin_txid = event["bitcoin-txid"]  # Not used
    bitcoin_tx_index = event["output-index"]
    fulfillment = emily_client.Fulfillment(
        bitcoin_block_hash=le_bytes_to_hex(event["burn-hash"]),
        bitcoin_block_height=event["burn-height"],
        bitcoin_tx_index=bitcoin_tx_index,
        bitcoin_txid=le_bytes_to_hex(
            event["sweep-txid"]
        ),  # in the signer, we are using bitcoin-txid
        btc_fee=event["fee"],
        stacks_txid=stacks_txid,
    )
    return emily_client.WithdrawalUpdate(
        request_id=event["request-id"],
        status="confirmed",
        fulfillment=fulfillment,
        status_message=f"Included in block {fulfillment.bitcoin_block_hash}",
        last_update_block_hash=stacks_block_hash,
        last_update_height=stacks_block_height,
    )


def handle_withdrawal_reject(
    event: dict, _stacks_txid: str, stacks_block_hash: str, stacks_block_height: int
) -> emily_client.WithdrawalUpdate:
    # bitmap: int = event["signer-bitmap"]  # Not used
    return emily_client.WithdrawalUpdate(
        fulfillment=None,
        request_id=event["request-id"],
        status="failed",
        status_message="Rejected",
        last_update_block_hash=stacks_block_hash,
        last_update_height=stacks_block_height,
    )


EVENT_HANDLERS = {
    "completed-deposit": handle_completed_deposit,
    "withdrawal-accept": handle_withdrawal_accept,
    "withdrawal-reject": handle_withdrawal_reject,
    "withdrawal-create": handle_withdrawal_create,
}
