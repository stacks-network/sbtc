import logging
import sys


def setup_logging(
    level: int = logging.INFO, log_to_file: bool = False, log_file: str = "app.log"
) -> None:
    """Set up application-wide logging."""
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_to_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


def silence_logging():
    """Disable logging for tests."""
    logging.disable(logging.CRITICAL)
