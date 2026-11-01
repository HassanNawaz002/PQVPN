
"""PQVPN v1 data-plane constants and packet format."""

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
CLIENT_TO_SERVER = 1
SERVER_TO_CLIENT = 2

KEY_SIZE = 32
NONCE_PREFIX_SIZE = 4
NONCE_SIZE = 12
TAG_SIZE = 16

MAX_SEQUENCE = (1 << 64) - 1
MAX_PLAINTEXT = 65535

HEADER = struct.Struct("!BBQ")
HEADER_SIZE = HEADER.size


class PacketError(Exception):
    """Invalid or unauthenticated PQVPN packet."""


class ReplayError(PacketError):
    """Duplicate or excessively old packet."""


class SequenceExhausted(PacketError):
    """Sender cannot safely allocate another nonce."""


def validate_key_material(key, nonce_prefix):
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be 32 bytes")

    if (
        not isinstance(nonce_prefix, bytes)
        or len(nonce_prefix) != NONCE_PREFIX_SIZE
    ):
        raise ValueError("Nonce prefix must be 4 bytes")


def validate_direction(direction):
    if direction not in (CLIENT_TO_SERVER, SERVER_TO_CLIENT):
        raise ValueError("Invalid packet direction")


def make_nonce(prefix, sequence):
    if (
        not isinstance(prefix, bytes)
        or len(prefix) != NONCE_PREFIX_SIZE
    ):
        raise ValueError("Invalid nonce prefix")

    if not isinstance(sequence, int) or not (
        0 <= sequence <= MAX_SEQUENCE
    ):
        raise ValueError("Invalid sequence number")

    return prefix + sequence.to_bytes(8, "big")
