from flask import Flask, request, jsonify
import os
import requests
import logging
from marshmallow import Schema, fields, ValidationError, INCLUDE

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the schema for the expected JSON data
class NewBlockEventSchema(Schema):
    block_height = fields.Int(required=True)
    block_hash = fields.Str(required=True)

    class Meta:
        unknown = INCLUDE


# Get the API key from environment variables
api_key = os.getenv("EMILY_API_KEY", "default_api_key")
url = os.getenv("EMILY_CHAINSTATE_URL",  "http://host.docker.internal:3031/chainstate")
deployer_address = os.getenv("DEPLOYER_ADDRESS", "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS")

logger.info("Using chainstate URL: %s", url)
logger.info("Using deployer address: %s", deployer_address)

headers = {
    "Content-Type": "application/json",
    "x-api-key": api_key
}

@app.route("/")
def hello():
    return "Hello, World!"

def validate_json(schema, data):
    try:
        return schema.load(data)
    except ValidationError as err:
        logger.warning("Validation error: %s", err.messages)
        raise ValueError({"error": "Invalid data", "messages": err.messages})

@app.route("/new_block", methods=["POST"])
def handle_new_block():
    logger.debug(f"Received new_block event")
    if not request.is_json:
        logger.error("Request was not JSON")
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    schema = NewBlockEventSchema()

    try:
        validated_data = validate_json(schema, data)
    except ValueError as e:
        logger.error("Failed to validate new block event: %s", e)
        return jsonify(str(e)), 400

    chainstate = {
        "stacksBlockHeight": validated_data["block_height"],
        "stacksBlockHash": validated_data["index_block_hash"].removeprefix("0x"),
    }

    try:
        resp = requests.post(url, headers=headers, json=chainstate)
        resp.raise_for_status()  # This will raise an HTTPError if the response was an error
    except requests.RequestException as e:
        logger.error("Failed to send chainstate %s to %s: %s", chainstate, url, e)
        # lets return an error so that the node will retry
        return jsonify({"error": "Failed to send chainstate"}), 500

    logger.info("Successfully processed new block for chainstate: %s", chainstate)
    return jsonify({}), 200


# stacks-node will seldomly send a POST request to /attachments/new
# if the request is not handled, the node will loop and keep retrying
# https://github.com/stacks-network/stacks-core/issues/5558
@app.route("/attachments/new", methods=["POST"])
def handle_attachments():
    return jsonify({}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=20540)
