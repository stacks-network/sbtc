import os

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "testApiKey")
EMILY_ENDPOINT = os.getenv(
    "EMILY_ENDPOINT", "http://host.docker.internal:3031"
).removesuffix("/")
NEW_BLOCK_URL = f"{EMILY_ENDPOINT}/new_block"
