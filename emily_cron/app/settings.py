import os

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "testApiKey")
EMILY_ENDPOINT = os.getenv("EMILY_ENDPOINT", "https://sbtc-emily.com").removesuffix("/")
PRIVATE_EMILY_ENDPOINT = os.getenv(
    "PRIVATE_EMILY_ENDPOINT", f"https://private.sbtc-emily.com"
).removesuffix("/")
MEMPOOL_API_URL = os.getenv("MEMPOOL_API_URL", "https://mempool.space/api").removesuffix("/")
HIRO_API_URL = os.getenv("HIRO_API_URL", "https://api.hiro.so/extended").removesuffix("/")

# The number of confirmations required for a deposit update to be considered final
MIN_BLOCK_CONFIRMATIONS = int(os.getenv("MIN_BLOCK_CONFIRMATIONS", 6))

# Maximum time (in seconds) a transaction can remain unconfirmed before being marked as FAILED
MAX_UNCONFIRMED_TIME = int(os.getenv("MAX_UNCONFIRMED_TIME", 60 * 60 * 24))  # 24 hours in seconds
