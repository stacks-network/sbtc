import os
import logging

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, ValidationError, Field

import emily_client


# Initialize the FastAPI app
app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Define the models
class NewBlockEventModel(BaseModel, extra="allow"):
    block_height: int
    index_block_hash: str


# Environment variables and configuration
api_key = os.getenv("EMILY_API_KEY", "testApiKey")
# The client fails if the endpoint has a trailing slash
emily_endpoint = os.getenv(
    "EMILY_ENDPOINT", "http://@host.docker.internal:3031"
).removesuffix("/")

deployer_address = os.getenv(
    "DEPLOYER_ADDRESS", "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS"
)

logger.info("Using Emily endpoint: %s", emily_endpoint)
logger.info("Using deployer address: %s", deployer_address)

conf = emily_client.Configuration(
    host=emily_endpoint,
)
conf.api_key["ApiGatewayKey"] = api_key

api_client = emily_client.ApiClient(configuration=conf)

CHAINSTATE_API = emily_client.ChainstateApi(api_client)
DEPOSIT_API = emily_client.DepositApi(api_client)
WITHDRAWAL_API = emily_client.WithdrawalApi(api_client)


@app.get("/")
def read_root() -> dict:
    return {"message": "Hello, World!"}


@app.post("/new_block")
async def handle_new_block(event: NewBlockEventModel) -> dict:
    logger.info("Received new block event: %s, %s", event, dir(event))
    chainstate = emily_client.Chainstate(
        stacksBlockHeight=event.block_height,
        stacksBlockHash=event.index_block_hash.removeprefix("0x"),
    )

    try:
        CHAINSTATE_API.set_chainstate(chainstate)
    except Exception as e:
        logger.error(
            "Failed to send chainstate %s to %s: %s", chainstate, emily_endpoint, e
        )
        raise HTTPException(status_code=500, detail="Failed to send chainstate")
    logger.info("Successfully processed new block for chainstate: %s", chainstate)
    return {}


@app.post("/attachments/new")
async def handle_attachments() -> dict:
    return {}
