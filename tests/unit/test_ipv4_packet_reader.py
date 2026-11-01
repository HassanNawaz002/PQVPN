
"""Unit tests for PQVPN IPv4 packet inspection."""

import ipaddress
import struct
import unittest

from modules.networking.host.packet_reader import inspect_ipv4


def make_ipv4_packet(
    source="10.77.0.2",
    destination="10.77.0.1",
    payload=b"hello",
):
    header = bytearray(20)

    header[0] = 0x45
    header[2:4] = struct.pack("!H", 20 + len(payload))
    header[8] = 64
    header[9] = 1

    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed

    return bytes(header) + payload


class TestIPv4PacketReader(unittest.TestCase):

    def test_valid_ipv4_packet(self):
        packet = make_ipv4_packet()
        info = inspect_ipv4(packet)

        self.assertEqual(info.source, "10.77.0.2")
        self.assertEqual(info.destination, "10.77.0.1")
        self.assertEqual(info.protocol, 1)
        self.assertEqual(info.total_length, len(packet))

    def test_reject_short_packet(self):
        with self.assertRaises(ValueError):
            inspect_ipv4(b"\x45\x00")

    def test_reject_ipv6_packet(self):
        packet = bytearray(make_ipv4_packet())
        packet[0] = 0x65

        with self.assertRaises(ValueError):
            inspect_ipv4(bytes(packet))

    def test_reject_invalid_header_length(self):
        packet = bytearray(make_ipv4_packet())
        packet[0] = 0x44

        with self.assertRaises(ValueError):
            inspect_ipv4(bytes(packet))

    def test_reject_length_mismatch(self):
        packet = bytearray(make_ipv4_packet())
        packet[2:4] = struct.pack("!H", 999)

        with self.assertRaises(ValueError):
            inspect_ipv4(bytes(packet))

    def test_reject_non_bytes(self):
        with self.assertRaises(TypeError):
            inspect_ipv4("not-a-packet")


if __name__ == "__main__":
    unittest.main()
