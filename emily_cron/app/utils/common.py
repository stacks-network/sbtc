from dataclasses import asdict
from typing import Any


def to_camel_case(s: str) -> str:
    """Convert snake_case to camelCase."""
    parts = s.split("_")
    return parts[0].lower() + "".join(word.capitalize() for word in parts[1:])


def asdict_camel(d: Any) -> dict:
    """Convert the dataclass to a dict with camelCase keys."""
    return {to_camel_case(key): value for key, value in asdict(d).items()}


def decode_cscript_int(vch: bytes) -> int:
    """Decodes a cscript integer.

    Reference implementation:
    https://github.com/bitcoin/bitcoin/blob/43a66c55ec8770cf7c21112aac9b997f3f2fb704/test/functional/test_framework/script.py#L407-L421

    Note: The original implementation expects the encoded integer to be
    prefixed with a byte indicating its length, which the decoder skips.
    In our case (e.g., when we decode reclaim script locktime), this length
    prefix is not present, so we don't skip the first byte.
    """
    result = 0
    # We assume valid push_size and minimal encoding
    if len(vch) == 0:
        return result
    for i, byte in enumerate(vch):
        result |= int(byte) << 8 * i
    if vch[-1] >= 0x80:
        # Mask for all but the highest result bit
        num_mask = (2 ** (len(vch) * 8) - 1) >> 1
        result &= num_mask
        result *= -1
    return result
