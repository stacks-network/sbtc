import logging

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import asynccontextmanager
from fastapi.responses import Response
from pydantic import BaseModel
import requests
from apscheduler.schedulers.background import BackgroundScheduler

from app import settings, logging_config
from app.clients import EmilyAPI
from app.services import DepositProcessor

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Set up and tear down application resources."""
    # Initialize the scheduler
    scheduler = BackgroundScheduler()

    # Create the Emily API client
    emily_api = EmilyAPI(settings.API_KEY)

    # Create the deposit processor
    deposit_processor = DepositProcessor(emily_api)

    # Add the deposit update job to run every 5 minutes
    scheduler.add_job(
        deposit_processor.update_deposits,
        "interval",
        minutes=5,
        id="update_deposits",
        name="Update deposit statuses",
    )

    # Start the scheduler
    scheduler.start()
    logger.info("Started background scheduler for deposit status updates")

    yield

    # Shutdown the scheduler when the app is shutting down
    scheduler.shutdown()
    logger.info("Stopped background scheduler")


# Initialize the FastAPI app
app = FastAPI(lifespan=lifespan)


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
