
"""PQVPN IPv4 packet validation and inspection."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class IPv4Packet:
    source: str
    destination: str
    protocol: int
    header_length: int
    total_length: int


def inspect_ipv4(packet: bytes) -> IPv4Packet:
    if not isinstance(packet, bytes):
        raise TypeError("Packet must be bytes")

    if len(packet) < 20:
        raise ValueError("IPv4 packet too short")

    version = packet[0] >> 4
    header_length = (packet[0] & 0x0F) * 4

    if version != 4:
        raise ValueError("Unsupported IP version")

    if header_length < 20 or header_length > 60:
        raise ValueError("Invalid IPv4 header length")

    if len(packet) < header_length:
        raise ValueError("Truncated IPv4 header")

    total_length = struct.unpack_from("!H", packet, 2)[0]

    if total_length < header_length:
        raise ValueError("Invalid IPv4 total length")

    if total_length != len(packet):
        raise ValueError("IPv4 packet length mismatch")

    source = str(ipaddress.IPv4Address(packet[12:16]))
    destination = str(ipaddress.IPv4Address(packet[16:20]))

    return IPv4Packet(
        source=source,
        destination=destination,
        protocol=packet[9],
        header_length=header_length,
        total_length=total_length,
    )
