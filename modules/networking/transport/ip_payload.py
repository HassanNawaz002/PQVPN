"""PQVPN authenticated IPv4 payload framing.

The output is plaintext framing intended to be encrypted
by SecureSessionTransport before UDP transmission.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from modules.networking.host.packet_reader import inspect_ipv4


MAGIC = b"PQIP"
VERSION = 1
TYPE_IPV4 = 1

HEADER = struct.Struct("!4sBBH")
HEADER_SIZE = HEADER.size

MAX_IPV4_PACKET = 1200


class IPPayloadError(ValueError):
    """Invalid IPv4 tunnel payload."""


@dataclass(frozen=True)
class DecodedIPPayload:
    packet: bytes
    source: str
    destination: str
    protocol: int


def _validate_packet(packet: bytes):
    if not isinstance(packet, bytes):
        raise IPPayloadError("IPv4 packet must be bytes")

    if not 20 <= len(packet) <= MAX_IPV4_PACKET:
        raise IPPayloadError("IPv4 packet size outside allowed range")

    try:
        return inspect_ipv4(packet)
    except (ValueError, TypeError) as exc:
        raise IPPayloadError("Invalid IPv4 packet") from exc


def encode_ipv4_payload(packet: bytes) -> bytes:
    _validate_packet(packet)

    return HEADER.pack(
        MAGIC,
        VERSION,
        TYPE_IPV4,
        len(packet),
    ) + packet


def decode_ipv4_payload(payload: bytes) -> DecodedIPPayload:
    if not isinstance(payload, bytes):
        raise IPPayloadError("Payload must be bytes")

    if len(payload) < HEADER_SIZE:
        raise IPPayloadError("Truncated IP payload header")

    magic, version, kind, packet_length = HEADER.unpack_from(
        payload
    )

    if magic != MAGIC:
        raise IPPayloadError("Invalid IP payload magic")

    if version != VERSION:
        raise IPPayloadError("Unsupported IP payload version")

    if kind != TYPE_IPV4:
        raise IPPayloadError("Unsupported IP payload type")

    packet = payload[HEADER_SIZE:]

    if len(packet) != packet_length:
        raise IPPayloadError("IP payload length mismatch")

    info = _validate_packet(packet)

    return DecodedIPPayload(
        packet=packet,
        source=info.source,
        destination=info.destination,
        protocol=info.protocol,
    )


def validate_tunnel_source(
    payload: DecodedIPPayload,
    assigned_ip: str,
) -> None:
    try:
        expected = ipaddress.IPv4Address(assigned_ip)
        actual = ipaddress.IPv4Address(payload.source)
    except ipaddress.AddressValueError as exc:
        raise IPPayloadError("Invalid tunnel source address") from exc

    if actual != expected:
        raise IPPayloadError("Tunnel source IP mismatch")
