from bitcoinlib.keys import Address
from settings import LOGGER, NETWORK


# Types
# {"Tuple": {"key1": {}, key2: {}, ..}}
# {"Sequence": {"Buffer": {"data": []}}}
# {"Sequence": {"String": {"ASCII": {"data": []}}}}
# {"UInt": 0}
# {"Int": 0}
# {"Principal": {"Standard": [0, [0x0, 0x0, ..., 0x0]]}} TODO: Implement this
def parse_clarity_value(v: dict) -> dict:
    """
    Parses a Clarity value and transforms it into a Python dictionary with appropriate value types.

    This function handles a subset of Clarity types: Tuples, Sequences (Buffers and Strings), UInts and Ints.
    Only the subset used by the sBTC print events is supported. The other types are not handled.

    Note: The function expects the input to be properly formatted Clarity values. If the input is not properly
    formatted, the function will raise an exception.

    Args:
        v (dict[str, Any]): Clarity value to be parsed.

    Returns:
        dict[str, Any] corresponding Python type.

    """
    if "Tuple" in v:
        return {
            k: parse_clarity_value(val) for k, val in v["Tuple"]["data_map"].items()
        }
    if "Sequence" in v:
        sequence = v["Sequence"]
        if "Buffer" in sequence:
            return sequence["Buffer"]["data"]
        if "String" in sequence:
            return "".join(map(chr, sequence["String"]["ASCII"]["data"]))
    elif "UInt" in v:
        return v["UInt"]
    elif "Int" in v:
        return v["Int"]
    return v


def parse_clarity_value_safe(value: dict) -> dict | None:
    try:
        return parse_clarity_value(value)
    except Exception as e:
        # We are only interested in events that we can parse
        LOGGER.debug("Failed to parse Clarity value: %s", e)
        return None


def try_into_address(version: bytes, hash_bytes: bytes) -> str:
    """
    Tries to convert the version and hash_bytes into a Script object.

    Args:
        version (bytes): the version of the recipient
        hash_bytes (bytes): the hash of the recipient

    Raises:
        Exception: If the version is not handled

    Returns:
        str: The address
    """
    script_map = {
        b"\x00": ("p2pkh", 20),
        b"\x01": ("p2sh", 20),
        b"\x02": ("p2sh", 20),
        b"\x03": ("p2sh", 20),
        b"\x04": ("p2wpkh", 20),
        b"\x05": ("p2wsh", 32),
        b"\x06": ("p2tr", 32),
    }

    script_type, expected_length = script_map.get(version, (None, None))
    if script_type and len(hash_bytes) == expected_length:
        return Address(
            hash_bytes,
            encoding="base58" if expected_length == 20 else "bech32",
            script_type=script_type,
            network=NETWORK,
        ).address

    raise Exception(f"Unhandled recipient version: {version}, hash_bytes: {hash_bytes}")
