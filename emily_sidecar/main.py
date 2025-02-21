from typing import Any

from fastapi import FastAPI, HTTPException
import emily_client

import settings
from settings import LOGGER
from event_handlers import EVENT_HANDLERS
from clarity import parse_clarity_value_safe
from models import NewBlockEventModel, TransactionEventModel

# Initialize the FastAPI app
app = FastAPI()

LOGGER.info("Using Emily endpoint: %s", settings.EMILY_ENDPOINT)
LOGGER.info("Using deployer address: %s", settings.DEPLOYER_ADDRESS)

conf = emily_client.Configuration(host=settings.EMILY_ENDPOINT)
conf.api_key["ApiGatewayKey"] = settings.API_KEY

api_client = emily_client.ApiClient(configuration=conf)

CHAINSTATE_API = emily_client.ChainstateApi(api_client)
DEPOSIT_API = emily_client.DepositApi(api_client)
WITHDRAWAL_API = emily_client.WithdrawalApi(api_client)


@app.get("/")
def read_root() -> dict:
    return {"message": "Hello, World!"}


@app.post("/new_block")
async def handle_new_block(new_block_event: NewBlockEventModel) -> dict:
    chainstate = emily_client.Chainstate(
        stacksBlockHeight=new_block_event.block_height,
        stacksBlockHash=new_block_event.index_block_hash,
    )

    try:
        CHAINSTATE_API.set_chainstate(chainstate)
    except Exception as e:
        LOGGER.error(
            "Failed to send chainstate %s to %s: %s",
            chainstate,
            settings.EMILY_ENDPOINT,
            e,
        )
        raise HTTPException(status_code=500, detail="Failed to send chainstate")

    LOGGER.info("Successfully processed new block for chainstate: %s", chainstate)

    contract_events = extract_sbtc_contract_events(new_block_event.events)

    completed_deposits, updated_withdrawals, created_withdrawals = [], [], []

    for txid, event_data in contract_events:
        result = EVENT_HANDLERS[event_data["topic"]](
            event_data,
            txid,
            new_block_event.index_block_hash,
            new_block_event.block_height,
        )
        match event_data["topic"]:
            case "completed-deposit":
                completed_deposits.append(result)
            case "withdrawal-create":
                created_withdrawals.append(result)
            case _:  # withdrawal-accept, withdrawal-reject
                updated_withdrawals.append(result)

    if completed_deposits:
        DEPOSIT_API.update_deposits(
            emily_client.UpdateDepositsRequestBody(deposits=completed_deposits)
        )

    for withdrawal in created_withdrawals:
        WITHDRAWAL_API.create_withdrawal(create_withdrawal_request_body=withdrawal)

    if updated_withdrawals:
        WITHDRAWAL_API.update_withdrawals(
            emily_client.UpdateWithdrawalsRequestBody(withdrawals=updated_withdrawals)
        )
    return {}


@app.post("/attachments/new")
async def handle_attachments() -> dict:
    return {}


def extract_sbtc_contract_events(
    events: list[TransactionEventModel],
) -> list[tuple[str, dict[str, Any]]]:
    """
    Extracts and transforms the events to only include the sBTC print events that we are interested in.

    Args:
        events (list[TransactionEventModel]): The list of transaction events to be processed.

    Returns:
        list[dict[str, Any]]: A list of tuples containing the transaction ID and the transformed contract value.
    """

    # Get the committed print events
    events = [
        e
        for e in events
        if e.committed
        and e.contract_event
        and e.contract_event.contract_identifier == settings.REGISTRY_ADDRESS
        and e.contract_event.topic == "print"
        and e.contract_event.value.get("Tuple") is not None
    ]

    # Get the contract events that we are interested in
    return [
        (event.txid, contract_value)
        for event in events
        if (contract_value := parse_clarity_value_safe(event.contract_event.value))
        and contract_value.get("topic") in EVENT_HANDLERS
    ]
