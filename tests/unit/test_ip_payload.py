
"""Unit tests for PQVPN IPv4 payload framing."""

import ipaddress
import struct
import unittest

from modules.networking.transport.ip_payload import (
    IPPayloadError,
    encode_ipv4_payload,
    decode_ipv4_payload,
    validate_tunnel_source,
)


def make_ipv4_packet(
    source="10.77.0.2",
    destination="10.77.0.1",
):
    """Construct a structurally valid IPv4 header for framing tests."""

    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20,
        1,
        0,
        64,
        1,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )


class TestIPPayload(unittest.TestCase):

    def test_ipv4_roundtrip(self):
        packet = make_ipv4_packet()

        encoded = encode_ipv4_payload(packet)
        decoded = decode_ipv4_payload(encoded)

        self.assertEqual(decoded.packet, packet)
        self.assertEqual(decoded.source, "10.77.0.2")
        self.assertEqual(decoded.destination, "10.77.0.1")
        self.assertEqual(decoded.protocol, 1)

    def test_invalid_magic(self):
        encoded = bytearray(
            encode_ipv4_payload(make_ipv4_packet())
        )
        encoded[0] = 0

        with self.assertRaises(IPPayloadError):
            decode_ipv4_payload(bytes(encoded))

    def test_invalid_version(self):
        encoded = bytearray(
            encode_ipv4_payload(make_ipv4_packet())
        )
        encoded[4] = 99

        with self.assertRaises(IPPayloadError):
            decode_ipv4_payload(bytes(encoded))

    def test_truncated_payload(self):
        encoded = encode_ipv4_payload(make_ipv4_packet())

        with self.assertRaises(IPPayloadError):
            decode_ipv4_payload(encoded[:-1])

    def test_reject_ipv6(self):
        with self.assertRaises(IPPayloadError):
            encode_ipv4_payload(b"\x60" + bytes(39))

    def test_reject_oversized_packet(self):
        with self.assertRaises(IPPayloadError):
            encode_ipv4_payload(b"\x45" + bytes(1300))

    def test_authorized_source(self):
        decoded = decode_ipv4_payload(
            encode_ipv4_payload(make_ipv4_packet())
        )

        validate_tunnel_source(decoded, "10.77.0.2")

    def test_spoofed_source_rejected(self):
        decoded = decode_ipv4_payload(
            encode_ipv4_payload(
                make_ipv4_packet(source="10.77.0.99")
            )
        )

        with self.assertRaises(IPPayloadError):
            validate_tunnel_source(decoded, "10.77.0.2")

    def test_legacy_ping_not_accepted_as_ip(self):
        with self.assertRaises(IPPayloadError):
            decode_ipv4_payload(b"PING")


if __name__ == "__main__":
    unittest.main()
