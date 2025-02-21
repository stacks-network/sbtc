import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "testApiKey")
# The client fails if the endpoint has a trailing slash
EMILY_ENDPOINT = os.getenv(
    "EMILY_ENDPOINT", "http://@host.docker.internal:3031"
).removesuffix("/")

DEPLOYER_ADDRESS = os.getenv(
    "DEPLOYER_ADDRESS", "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS"
)

SBTC_REGISTRY_CONTRACT_NAME = "sbtc-registry"

REGISTRY_ADDRESS = f"{DEPLOYER_ADDRESS}.{SBTC_REGISTRY_CONTRACT_NAME}"

IS_MAINNET = os.getenv("IS_MAINNET", "false").lower() == "true"

NETWORK = "bitcoin" if IS_MAINNET else "regtest"
