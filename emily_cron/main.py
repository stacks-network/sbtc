#!/usr/bin/env python3
"""
Standalone script to run the deposit update job.
This script is meant to be run as a cron job.
"""

import logging
import sys

from app import settings
from app.services import DepositProcessor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("emily_cron")


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
