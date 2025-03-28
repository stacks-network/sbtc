from dataclasses import asdict
from typing import Any


def to_camel_case(s: str) -> str:
    """Convert snake_case to camelCase."""
    parts = s.split("_")
    return parts[0].lower() + "".join(word.capitalize() for word in parts[1:])


def asdict_camel(d: Any) -> dict:
    """Convert the dataclass to a dict with camelCase keys."""
    return {to_camel_case(key): value for key, value in asdict(d).items()}
