import os

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "testApiKey")

DEPLOYER_ADDRESS = os.getenv("DEPLOYER_ADDRESS", "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS")

EMILY_ENDPOINT = os.getenv("EMILY_ENDPOINT", "http://host.docker.internal:3031").removesuffix("/")

NEW_BLOCK_URL = f"{EMILY_ENDPOINT}/new_block"

# The number of confirmations required for a deposit update to be considered final
MIN_BLOCK_CONFIRMATIONS = int(os.getenv("MIN_BLOCK_CONFIRMATIONS", 6))

# Maximum time (in seconds) a transaction can remain unconfirmed before being marked as FAILED
MAX_UNCONFIRMED_TIME = int(os.getenv("MAX_UNCONFIRMED_TIME", 60 * 60 * 24))  # 24 hours in seconds
