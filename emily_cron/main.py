#!/usr/local/bin/python
"""
Standalone script to run the deposit update job.
This script is meant to be run as a cron job.
"""

import logging
import sys
from datetime import datetime

from app import settings
from app.services import DepositProcessor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("emily_cron")

# Log startup information
logger.info("=" * 80)
logger.info(f"Starting emily_cron job at {datetime.now().isoformat()}")
logger.info(f"EMILY_ENDPOINT: {settings.EMILY_ENDPOINT}")
logger.info(f"PRIVATE_EMILY_ENDPOINT: {settings.PRIVATE_EMILY_ENDPOINT}")
logger.info(f"MEMPOOL_API_URL: {settings.MEMPOOL_API_URL}")
logger.info(f"HIRO_API_URL: {settings.HIRO_API_URL}")
logger.info(f"MIN_BLOCK_CONFIRMATIONS: {settings.MIN_BLOCK_CONFIRMATIONS}")
logger.info("=" * 80)


def main():
    """Main entry point for the cron job."""

    # Create the deposit processor
    deposit_processor = DepositProcessor()
    try:
        deposit_processor.update_deposits()
    except Exception as e:
        logger.exception(f"Unhandled exception in cron job: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
