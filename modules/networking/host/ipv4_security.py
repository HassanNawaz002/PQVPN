
"""Strict IPv4 security validation for PQVPN TUN forwarding.

Rejects malformed headers, invalid checksums, fragmentation,
IPv4 options, and unsupported special addresses.

Does not validate TCP/UDP/ICMP transport checksums.
"""

import ipaddress
import struct

from modules.networking.host.packet_reader import inspect_ipv4


class IPv4SecurityError(ValueError):
    """IPv4 packet rejected by tunnel security policy."""


def _checksum_valid(header: bytes) -> bool:
    if len(header) % 2:
        return False

    words = struct.unpack(
        f"!{len(header) // 2}H",
        header,
    )

    total = sum(words)

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return total == 0xFFFF


def validate_secure_ipv4(packet: bytes):
    """Return IPv4 metadata only for accepted packets.

    Strict experimental profile:
      - IPv4 with exactly 20-byte header
      - valid IPv4 header checksum
      - no fragmentation or reserved flag
      - no broadcast/multicast/unspecified addresses
      - max 1200 bytes
    """
    try:
        info = inspect_ipv4(packet)
    except (ValueError, TypeError) as exc:
        raise IPv4SecurityError(
            "Malformed IPv4 packet"
        ) from exc

    if len(packet) > 1200:
        raise IPv4SecurityError(
            "Packet exceeds experimental tunnel MTU"
        )

    if info.header_length != 20:
        raise IPv4SecurityError(
            "IPv4 options are not supported"
        )

    if not _checksum_valid(packet[:info.header_length]):
        raise IPv4SecurityError(
            "Invalid IPv4 header checksum"
        )

    flags_offset = struct.unpack_from(
        "!H", packet, 6
    )[0]

    reserved_flag = bool(flags_offset & 0x8000)
    more_fragments = bool(flags_offset & 0x2000)
    fragment_offset = flags_offset & 0x1FFF

    if reserved_flag or more_fragments or fragment_offset:
        raise IPv4SecurityError(
            "IPv4 fragmentation or reserved flag rejected"
        )

    source = ipaddress.IPv4Address(info.source)
    destination = ipaddress.IPv4Address(info.destination)

    if (
        source.is_multicast
        or source.is_unspecified
        or source == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise IPv4SecurityError(
            "Invalid IPv4 source address"
        )

    if (
        destination.is_multicast
        or destination.is_unspecified
        or destination == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise IPv4SecurityError(
            "Invalid IPv4 destination address"
        )

    return info
