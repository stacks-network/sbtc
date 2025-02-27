import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
import requests

import settings
import logging_config

# Initialize the FastAPI app
app = FastAPI()

# Set up logging when the app starts
logging_config.setup_logging()

# Get a logger instance
logger = logging.getLogger(__name__)

logger.info("Using Emily endpoint: %s", settings.EMILY_ENDPOINT)

headers = {"x-api-key": settings.API_KEY}


# The events received from the stacks-node contain many additional fields,
# but we only validate these specific ones for logging purposes.
# The `extra="allow"` argument permits extra fields in the request body
# that are not explicitly defined in the model.
class NewBlockEventModel(BaseModel, extra="allow"):
    block_height: int
    index_block_hash: str


@app.post("/new_block")
async def handle_new_block(new_block_event: NewBlockEventModel) -> Response:
    try:
        resp = requests.post(
            settings.NEW_BLOCK_URL,
            headers=headers,
            json=new_block_event.model_dump_json(),
        )
        resp.raise_for_status()  # This will raise an HTTPError if the response was an error
    except requests.RequestException as e:
        logger.error(
            "Failed to send new block event: block_height=%s, index_block_hash=%s, error=%s",
            new_block_event.block_height,
            new_block_event.index_block_hash,
            e,
        )
        # lets return an error so that the node will retry
        raise HTTPException(status_code=500, detail="Failed to send new_block event")
    logger.info(
        "Successfully processed new block event: block_height=%s, index_block_hash=%s",
        new_block_event.block_height,
        new_block_event.index_block_hash,
    )
    return Response(status_code=200)


@app.post("/attachments/new")
async def handle_attachments() -> Response:
    return Response(status_code=200)


@app.get("/")
def read_root() -> Response:
    return Response(status_code=200)
