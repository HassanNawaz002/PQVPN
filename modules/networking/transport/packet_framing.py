
"""PQVPN v1 UDP transport framing.

This frame is NOT authenticated. It is only an envelope
for the local transport prototype.
"""

import struct

MAGIC = b"PQVN"
VERSION = 1

TYPE_PING = 1
TYPE_PONG = 2
TYPE_DATA = 3

MAX_PAYLOAD = 60000

HEADER = struct.Struct("!4sBBH")
HEADER_SIZE = HEADER.size


class FrameError(Exception):
    """Invalid UDP transport frame."""


def encode_frame(message_type, payload=b""):
    if message_type not in (TYPE_PING, TYPE_PONG, TYPE_DATA):
        raise FrameError("Unsupported message type")

    if not isinstance(payload, bytes):
        raise FrameError("Payload must be bytes")

    if len(payload) > MAX_PAYLOAD:
        raise FrameError("Payload exceeds maximum size")

    header = HEADER.pack(
        MAGIC,
        VERSION,
        message_type,
        len(payload),
    )

    return header + payload


def decode_frame(datagram):
    if not isinstance(datagram, bytes):
        raise FrameError("Datagram must be bytes")

    if len(datagram) < HEADER_SIZE:
        raise FrameError("Datagram too short")

    magic, version, message_type, length = HEADER.unpack(
        datagram[:HEADER_SIZE]
    )

    if magic != MAGIC:
        raise FrameError("Invalid frame magic")

    if version != VERSION:
        raise FrameError("Unsupported frame version")

    if message_type not in (TYPE_PING, TYPE_PONG, TYPE_DATA):
        raise FrameError("Unsupported message type")

    if length > MAX_PAYLOAD:
        raise FrameError("Payload exceeds maximum size")

    payload = datagram[HEADER_SIZE:]

    if len(payload) != length:
        raise FrameError("Payload length mismatch")

    return message_type, payload
