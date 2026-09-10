"""Helpers for deriving sBTC deposit scriptPubKeys via embit."""

from __future__ import annotations

from embit import compact
from embit.ec import PublicKey
from embit.hashes import tagged_hash

# BIP-341 NUMS x-only pubkey used as the internal key for sBTC deposits.
# Matches sbtc::NUMS_X_COORDINATE / UNSPENDABLE_TAPROOT_KEY.
_NUMS_INTERNAL_KEY = PublicKey.from_xonly(
    bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
)
_TAPSCRIPT_LEAF_VERSION = 0xC0


def _tap_leaf_hash(script: bytes) -> bytes:
    return tagged_hash(
        "TapLeaf",
        bytes([_TAPSCRIPT_LEAF_VERSION]) + compact.to_bytes(len(script)) + script,
    )


def _tap_branch_hash(left: bytes, right: bytes) -> bytes:
    if left > right:
        left, right = right, left
    return tagged_hash("TapBranch", left + right)


def deposit_script_pubkey(deposit_script_hex: str, reclaim_script_hex: str) -> bytes:
    """Derive the P2TR scriptPubKey for an sBTC deposit + reclaim script pair.

    Matches `sbtc::deposits::to_script_pubkey`: a two-leaf tapscript tree with
    the BIP-341 NUMS internal key.
    """
    merkle_root = _tap_branch_hash(
        _tap_leaf_hash(bytes.fromhex(deposit_script_hex)),
        _tap_leaf_hash(bytes.fromhex(reclaim_script_hex)),
    )
    output_key = _NUMS_INTERNAL_KEY.taproot_tweak(merkle_root)
    return bytes([0x51, 0x20]) + output_key.xonly()


def deposit_script_pubkey_hex(deposit_script_hex: str, reclaim_script_hex: str) -> str:
    """Hex-encoded form of :func:`deposit_script_pubkey`."""
    return deposit_script_pubkey(deposit_script_hex, reclaim_script_hex).hex()
